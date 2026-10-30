/*
 * Phase 5 tests: the tc plan, captive-portal sessions and vouchers, and the
 * RADIUS client.
 *
 * The RADIUS exchange is driven against a mock server written here from the
 * RFC rather than from the client's own code, so the two implementations
 * have to agree on the wire format independently.
 *   make test-phase5
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>

#include "inspect.h"
#include "enterprise.h"
#include "shaper.h"
#include "portal.h"
#include "reload.h"
#include "netutil.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-58s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-58s %s\n", what, detail ? detail : ""); fail++; }
}

static uint32_t ip(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    return a.s_addr;
}

/* Does the plan contain a command with all of these substrings? */
static bool plan_has(const shaper_plan_t *p, const char *a, const char *b) {
    for (int i = 0; i < p->count; i++)
        if (strstr(p->cmd[i], a) && (!b || strstr(p->cmd[i], b))) return true;
    return false;
}

static int plan_count_with(const shaper_plan_t *p, const char *needle) {
    int n = 0;
    for (int i = 0; i < p->count; i++) if (strstr(p->cmd[i], needle)) n++;
    return n;
}

/* ═══════════════════ shaping ═══════════════════ */

static void build_net(vlan_ctx_t *v, netconf_ctx_t *n) {
    vlan_init(v);
    netconf_init(n);

    wan_config_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.ifname, IFNAME_LEN, "eth0");
    w.mode = WAN_DHCP; w.mtu = 1500;
    n->wan[n->wan_count++] = w;

    port_config_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.ifname, IFNAME_LEN, "eth1");
    p.mode = PORT_MODE_TRUNK; p.zone = ZONE_LAN; p.enabled = true;
    p.allowed_vlans[0] = 10; p.allowed_vlans[1] = 30; p.allowed_count = 2;
    port_configure(v, &p);

    vlan_config_t c;
    memset(&c, 0, sizeof(c));
    c.vlan_id = 10; snprintf(c.name, sizeof(c.name), "CORP");
    c.zone = ZONE_LAN; c.lease_time = 86400; c.priority = 5;
    c.subnet = ip("10.10.10.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.10.1");
    c.bandwidth_up_mbps = 30; c.bandwidth_down_mbps = 80;
    vlan_add(v, &c);

    memset(&c, 0, sizeof(c));
    c.vlan_id = 30; snprintf(c.name, sizeof(c.name), "GUEST");
    c.zone = ZONE_GUEST; c.lease_time = 3600; c.priority = 1;
    c.subnet = ip("10.10.30.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.30.1");
    c.bandwidth_down_mbps = 20;   /* no explicit upload limit */
    vlan_add(v, &c);
}

static void test_shaping(void) {
    puts("\n-- traffic shaping --");

    vlan_ctx_t v; netconf_ctx_t n;
    build_net(&v, &n);

    shaper_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    shaper_plan_t *p = calloc(1, sizeof(*p));

    ok("a disabled shaper plans nothing",
       shaper_plan(&cfg, &v, &n, p) == 0 && p->count == 0, NULL);

    cfg.enabled = true;
    cfg.wan_up_mbps = 100;
    cfg.qdisc = QDISC_FQ_CODEL;
    cfg.codel_target_ms = 5;
    cfg.codel_interval_ms = 100;
    cfg.ecn = true;

    int cmds = shaper_plan(&cfg, &v, &n, p);
    ok("an enabled shaper produces a plan", cmds > 0, NULL);
    ok("nothing overflowed", p->overflow == 0, NULL);

    ok("the old root qdisc is cleared first",
       plan_has(p, "qdisc del dev eth0 root", NULL), NULL);
    ok("HTB is the root on the WAN",
       plan_has(p, "qdisc add dev eth0 root handle 1: htb", NULL), NULL);
    ok("the ceiling class is created",
       plan_has(p, "classid 1:1 htb", "rate 100mbit ceil 100mbit"), NULL);

    /* The bug this catches: attaching the leaf to the root qdisc handle
     * rather than to its class leaves every class on the default qdisc. */
    ok("each leaf attaches to its class, not to the root handle",
       plan_has(p, "parent 1:100 handle 100: fq_codel", NULL) &&
       !plan_has(p, "parent 1: handle 100:", NULL), NULL);
    ok("the default class gets a leaf too",
       plan_has(p, "parent 1:999 handle 999: fq_codel", NULL), NULL);

    ok("FQ-CoDel carries its target and interval",
       plan_has(p, "fq_codel target 5ms interval 100ms", NULL), NULL);
    ok("ECN is requested when asked for",
       plan_has(p, "fq_codel", "ecn") && !plan_has(p, "fq_codel", "noecn"), NULL);

    ok("traffic is classified by source subnet",
       plan_has(p, "u32 match ip src 10.10.10.0/24", "flowid 1:") &&
       plan_has(p, "u32 match ip src 10.10.30.0/24", "flowid 1:"), NULL);

    ok("an explicit upload limit is honoured",
       plan_has(p, "classid 1:100", "rate 30mbit"), NULL);

    /*
     * HTB guarantees must not exceed the parent's. A VLAN with no explicit
     * upload limit therefore gets a share of what is left, not the ceiling.
     */
    ok("a VLAN with no upload limit does not claim the whole link",
       !plan_has(p, "classid 1:101", "rate 100mbit"), NULL);

    int guarantees = 0;
    for (int i = 0; i < p->count; i++) {
        if (!strstr(p->cmd[i], "dev eth0")) continue;
        if (!strstr(p->cmd[i], "classid 1:") || strstr(p->cmd[i], "classid 1:1 ")) continue;
        const char *r = strstr(p->cmd[i], "rate ");
        if (r) guarantees += atoi(r + 5);
    }
    char sum[64];
    snprintf(sum, sizeof(sum), "children guarantee %d of 100 Mbit", guarantees);
    ok("the children's guarantees fit inside the ceiling",
       guarantees > 0 && guarantees <= cfg.wan_up_mbps, sum);

    /* 802.1p 0 is lowest, tc prio 0 is highest, so the mapping inverts. */
    ok("802.1p priority is inverted for tc",
       plan_has(p, "classid 1:100", "prio 2") &&
       plan_has(p, "classid 1:101", "prio 6"), NULL);

    /* Per-VLAN download, on the VLAN's own interface. */
    ok("a VLAN with a download limit gets HTB on its own interface",
       plan_has(p, "qdisc add dev eth1.10 root handle 1: htb", NULL) &&
       plan_has(p, "dev eth1.10", "rate 80mbit ceil 80mbit"), NULL);
    ok("and a leaf under that class",
       plan_has(p, "dev eth1.10 parent 1:100 handle 100: fq_codel", NULL), NULL);
    ok("the guest VLAN gets its own ceiling",
       plan_has(p, "dev eth1.30", "rate 20mbit ceil 20mbit"), NULL);

    /* A VLAN with no limit still gets the leaf qdisc: that is the part that
     * fixes latency, and it costs nothing. */
    vlan_config_t extra;
    memset(&extra, 0, sizeof(extra));
    extra.vlan_id = 50; snprintf(extra.name, sizeof(extra.name), "VOIP");
    extra.zone = ZONE_VOIP; extra.lease_time = 86400;
    extra.subnet = ip("10.10.50.0"); extra.netmask = ip("255.255.255.0");
    extra.gateway = ip("10.10.50.1");
    vlan_add(&v, &extra);
    v.ports[0].allowed_vlans[v.ports[0].allowed_count++] = 50;

    shaper_plan(&cfg, &v, &n, p);
    ok("an unlimited VLAN still gets the leaf qdisc",
       plan_has(p, "qdisc replace dev eth1.50 root handle 1: fq_codel", NULL),
       NULL);
    ok("and no HTB it does not need",
       !plan_has(p, "qdisc add dev eth1.50 root handle 1: htb", NULL), NULL);
    ok("'parent root' is never emitted; tc rejects it",
       !plan_has(p, "parent root", NULL), NULL);

    /* qdisc selection */
    cfg.qdisc = QDISC_CAKE;
    shaper_plan(&cfg, &v, &n, p);
    ok("cake is selectable", plan_has(p, "cake besteffort", NULL), NULL);

    cfg.qdisc = QDISC_SFQ;
    shaper_plan(&cfg, &v, &n, p);
    ok("sfq is selectable", plan_has(p, "sfq perturb", NULL), NULL);

    cfg.qdisc = QDISC_FQ_CODEL;
    cfg.ecn = false;
    shaper_plan(&cfg, &v, &n, p);
    ok("ECN can be turned off",
       plan_has(p, "fq_codel", "noecn"), NULL);

    /* ingress via IFB */
    cfg.ingress_shaping = true;
    cfg.wan_down_mbps = 500;
    shaper_plan(&cfg, &v, &n, p);
    ok("ingress shaping creates the IFB device",
       plan_has(p, "ip link add " SHAPER_IFB_DEV, NULL), NULL);
    ok("WAN ingress is redirected to it",
       plan_has(p, "action mirred egress redirect dev " SHAPER_IFB_DEV, NULL),
       NULL);
    ok("the IFB carries the download ceiling",
       plan_has(p, "dev " SHAPER_IFB_DEV, "rate 500mbit"), NULL);

    cfg.ingress_shaping = true;
    cfg.wan_down_mbps = 0;
    shaper_plan(&cfg, &v, &n, p);
    ok("ingress shaping without a ceiling does nothing",
       !plan_has(p, SHAPER_IFB_DEV, NULL), NULL);

    /* An unusable interface name must never reach a shell. */
    cfg.ingress_shaping = false;
    snprintf(n.wan[0].ifname, IFNAME_LEN, "eth0; rm -rf /");
    shaper_plan(&cfg, &v, &n, p);
    ok("an unsafe interface name is skipped entirely",
       !plan_has(p, "rm -rf", NULL), NULL);
    snprintf(n.wan[0].ifname, IFNAME_LEN, "eth0");

    /* teardown */
    shaper_plan_teardown(&cfg, &v, &n, p);
    ok("teardown clears the WAN root",
       plan_has(p, "qdisc del dev eth0 root", NULL), NULL);
    ok("teardown clears WAN ingress",
       plan_has(p, "qdisc del dev eth0 ingress", NULL), NULL);
    ok("teardown clears every VLAN interface",
       plan_count_with(p, "qdisc del dev eth1.") == 3, NULL);

    ok("a classid is reported for a shaped VLAN",
       shaper_classid_for(&v, 10) == SHAPER_BASE_CLASS, NULL);
    ok("an unshaped VLAN falls into the default class",
       shaper_classid_for(&v, 50) == SHAPER_DEF_CLASS, NULL);

    ok("qdisc names round-trip",
       qdisc_from("cake") == QDISC_CAKE &&
       qdisc_from("fq_codel") == QDISC_FQ_CODEL &&
       !strcmp(qdisc_name(QDISC_CAKE), "cake"), NULL);
    ok("an unknown qdisc name falls back to fq_codel",
       qdisc_from("nonsense") == QDISC_FQ_CODEL, NULL);

    free(p);
    vlan_shutdown(&v);
    netconf_shutdown(&n);
}

/* ═══════════════════ portal sessions ═══════════════════ */

static void test_sessions(void) {
    puts("\n-- portal sessions --");

    portal_ctx_t p;
    portal_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = true;
    cfg.auth = PORTAL_AUTH_CLICK;
    cfg.session_minutes = 60;
    cfg.idle_minutes = 10;

    portal_init(&p, &cfg, false);   /* false: never touch iptables */

    char why[192];
    portal_session_t s;

    ok("a client with no session is not authorised",
       !portal_session(&p, ip("10.10.30.5"), &s), NULL);

    ok("click-through authorises",
       portal_login(&p, ip("10.10.30.5"), 30, NULL, NULL, NULL,
                    why, sizeof(why)) == 0, why);
    ok("the session is now found",
       portal_session(&p, ip("10.10.30.5"), &s), NULL);
    ok("it records the VLAN", s.vlan_id == 30, NULL);
    ok("it expires in the configured window",
       s.expires > s.started && s.expires - s.started == 60 * 60, NULL);
    ok("another address is still unauthorised",
       !portal_session(&p, ip("10.10.30.6"), &s), NULL);

    portal_logout(&p, ip("10.10.30.5"));
    ok("logout removes the session",
       !portal_session(&p, ip("10.10.30.5"), &s), NULL);

    /* expiry */
    portal_login(&p, ip("10.10.30.7"), 30, NULL, NULL, NULL, why, sizeof(why));
    ok("reaping before expiry keeps the session",
       portal_reap(&p, time(NULL)) == 0 &&
       portal_session(&p, ip("10.10.30.7"), &s), NULL);
    ok("reaping past the hard expiry drops it",
       portal_reap(&p, time(NULL) + 61 * 60) == 1 &&
       !portal_session(&p, ip("10.10.30.7"), &s), NULL);

    portal_login(&p, ip("10.10.30.8"), 30, NULL, NULL, NULL, why, sizeof(why));
    ok("an idle session is dropped even inside its window",
       portal_reap(&p, time(NULL) + 11 * 60) == 1, NULL);

    /* A disabled portal must not authorise anyone. */
    portal_ctx_t off;
    portal_cfg_t offcfg;
    memset(&offcfg, 0, sizeof(offcfg));
    portal_init(&off, &offcfg, false);
    ok("a disabled portal refuses to log anyone in",
       portal_login(&off, ip("10.0.0.1"), 1, NULL, NULL, NULL,
                    why, sizeof(why)) != 0, why);
    portal_shutdown(&off);

    ok("successful logins are counted", p.logins_ok >= 3, NULL);
    portal_shutdown(&p);
}

/* ═══════════════════ vouchers ═══════════════════ */

static void test_vouchers(void) {
    puts("\n-- vouchers --");

    portal_ctx_t p;
    portal_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = true;
    cfg.auth = PORTAL_AUTH_VOUCHER;
    cfg.session_minutes = 240;
    cfg.idle_minutes = 30;
    portal_init(&p, &cfg, false);

    ok("vouchers are generated",
       portal_generate_vouchers(&p, 8, 60, "front desk") == 8, NULL);

    portal_voucher_t v[16];
    int n = portal_voucher_snapshot(&p, v, 16);
    ok("they can be listed", n == 8, NULL);

    /* The code is read off a printed slip, so no vowels (no accidental
     * words) and no glyphs that look alike. */
    bool shape_ok = true, no_vowels = true;
    for (int i = 0; i < n; i++) {
        if (strlen(v[i].code) != 11 || v[i].code[5] != '-') shape_ok = false;
        for (const char *c = v[i].code; *c; c++)
            if (strchr("AEIOUaeiou01lI", *c)) no_vowels = false;
    }
    ok("codes are XXXXX-XXXXX", shape_ok, n ? v[0].code : "");
    ok("codes avoid vowels and look-alike glyphs", no_vowels, NULL);

    bool unique = true;
    for (int i = 0; i < n && unique; i++)
        for (int j = i + 1; j < n; j++)
            if (!strcmp(v[i].code, v[j].code)) { unique = false; break; }
    ok("codes are unique", unique, NULL);

    ok("a fresh voucher is unused", !v[0].used && v[0].first_used == 0, NULL);

    char why[192];
    ok("a valid code authorises",
       portal_login(&p, ip("10.10.30.20"), 30, NULL, NULL, v[0].code,
                    why, sizeof(why)) == 0, why);

    portal_voucher_snapshot(&p, v, 16);
    ok("redeeming marks it used and starts its clock",
       v[0].used && v[0].first_used > 0, NULL);

    portal_session_t s;
    portal_session(&p, ip("10.10.30.20"), &s);
    ok("the session records which voucher opened it",
       !strcmp(s.voucher, v[0].code), s.voucher);
    ok("the session is capped by the voucher, not the portal default",
       s.expires - s.started <= 60 * 60, NULL);

    /* The same code from a second device, still inside its window. */
    ok("a code still inside its window works again",
       portal_login(&p, ip("10.10.30.21"), 30, NULL, NULL, v[0].code,
                    why, sizeof(why)) == 0, why);

    ok("an unknown code is refused",
       portal_login(&p, ip("10.10.30.22"), 30, NULL, NULL, "ZZZZZ-ZZZZZ",
                    why, sizeof(why)) != 0, why);
    ok("an empty code is refused",
       portal_login(&p, ip("10.10.30.23"), 30, NULL, NULL, "",
                    why, sizeof(why)) != 0, why);
    ok("a missing code is refused",
       portal_login(&p, ip("10.10.30.24"), 30, NULL, NULL, NULL,
                    why, sizeof(why)) != 0, why);

    ok("a voucher can be revoked",
       portal_revoke_voucher(&p, v[1].code) == 0, NULL);
    ok("a revoked code no longer works",
       portal_login(&p, ip("10.10.30.25"), 30, NULL, NULL, v[1].code,
                    why, sizeof(why)) != 0, why);
    ok("revoking an unknown code fails",
       portal_revoke_voucher(&p, "NOPE-NOPE") != 0, NULL);

    ok("nonsense generation parameters are refused",
       portal_generate_vouchers(&p, 0, 60, NULL) < 0 &&
       portal_generate_vouchers(&p, 5, 0, NULL) < 0, NULL);

    ok("failed logins are counted", p.logins_failed >= 4, NULL);
    portal_shutdown(&p);
}

/* ═══════════════════ RADIUS ═══════════════════ */

static void md5_2(const uint8_t *a, size_t al, const uint8_t *b, size_t bl,
                  uint8_t out[16]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int l = 16;
    EVP_DigestInit_ex(c, EVP_md5(), NULL);
    if (a && al) EVP_DigestUpdate(c, a, al);
    if (b && bl) EVP_DigestUpdate(c, b, bl);
    EVP_DigestFinal_ex(c, out, &l);
    EVP_MD_CTX_free(c);
}

/* Pulls an attribute out of a RADIUS packet. */
static int get_attr(const uint8_t *pkt, size_t len, uint8_t type,
                    uint8_t *out, size_t outlen) {
    size_t off = RADIUS_HDR_LEN;
    while (off + 2 <= len) {
        uint8_t t = pkt[off], l = pkt[off + 1];
        if (l < 2 || off + l > len) break;
        if (t == type) {
            size_t vlen = (size_t)l - 2;
            if (vlen > outlen) vlen = outlen;
            memcpy(out, pkt + off + 2, vlen);
            return (int)vlen;
        }
        off += l;
    }
    return -1;
}

struct mock {
    int      fd;
    uint16_t port;
    char     secret[64];
    char     good_user[64];
    char     good_pass[64];
    bool     corrupt_signature;   /* reply with a bad authenticator */
    int      served;
    bool     running;
    pthread_t th;
};

/*
 * A RADIUS server implemented straight from RFC 2865, independently of the
 * client under test: it decrypts User-Password with its own MD5 chain and
 * signs the reply itself. If the two agree, both read the RFC the same way.
 */
static void *mock_server(void *arg) {
    struct mock *m = arg;
    uint8_t req[RADIUS_MAX_PACKET];

    while (m->running) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(m->fd, req, sizeof(req), 0,
                             (struct sockaddr *)&from, &flen);
        if (n < RADIUS_HDR_LEN) continue;

        uint8_t user[256] = {0}, cipher[256] = {0};
        int ulen = get_attr(req, (size_t)n, 1, user, sizeof(user));
        int clen = get_attr(req, (size_t)n, 2, cipher, sizeof(cipher));
        if (ulen < 0 || clen <= 0 || (clen % 16) != 0) continue;

        /* Decrypt: p_i = c_i XOR MD5(secret | previous ciphertext block). */
        uint8_t plain[256] = {0};
        const uint8_t *prev = req + 4;          /* request authenticator */
        size_t slen = strlen(m->secret);
        for (int blk = 0; blk < clen; blk += 16) {
            uint8_t d[16];
            md5_2((const uint8_t *)m->secret, slen, prev, 16, d);
            for (int i = 0; i < 16; i++) plain[blk + i] = cipher[blk + i] ^ d[i];
            prev = cipher + blk;
        }

        bool good = (ulen == (int)strlen(m->good_user)) &&
                    !memcmp(user, m->good_user, (size_t)ulen) &&
                    !strcmp((char *)plain, m->good_pass);

        uint8_t resp[RADIUS_HDR_LEN];
        resp[0] = good ? RADIUS_ACCESS_ACCEPT : RADIUS_ACCESS_REJECT;
        resp[1] = req[1];
        resp[2] = 0;
        resp[3] = RADIUS_HDR_LEN;

        /* ResponseAuth = MD5(Code|ID|Length|RequestAuth|Attributes|Secret) */
        uint8_t basis[RADIUS_HDR_LEN + 64];
        memcpy(basis, resp, 4);
        memcpy(basis + 4, req + 4, 16);
        memcpy(basis + RADIUS_HDR_LEN, m->secret, slen);

        uint8_t sig[16];
        md5_2(basis, RADIUS_HDR_LEN + slen, NULL, 0, sig);
        if (m->corrupt_signature) sig[0] ^= 0xff;
        memcpy(resp + 4, sig, 16);

        sendto(m->fd, resp, RADIUS_HDR_LEN, 0,
               (struct sockaddr *)&from, flen);
        m->served++;
    }
    return NULL;
}

static bool mock_start(struct mock *m, uint16_t port) {
    memset(m, 0, sizeof(*m));
    m->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m->fd < 0) return false;

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(m->fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(m->fd);
        return false;
    }
    struct timeval tv = { 0, 200000 };
    setsockopt(m->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    m->port = port;
    m->running = true;
    return pthread_create(&m->th, NULL, mock_server, m) == 0;
}

static void mock_stop(struct mock *m) {
    m->running = false;
    pthread_join(m->th, NULL);
    close(m->fd);
}

static void test_radius(void) {
    puts("\n-- RADIUS wire format --");

    const char *secret = "a-shared-secret";
    uint8_t auth[RADIUS_AUTH_LEN];
    for (int i = 0; i < RADIUS_AUTH_LEN; i++) auth[i] = (uint8_t)(i * 7 + 3);

    uint8_t req[RADIUS_MAX_PACKET];
    int n = radius_build_request(req, sizeof(req), 42, auth, "alice",
                                 "correct horse", secret, ip("10.10.30.1"),
                                 "firex-test");
    ok("a request is built", n > 0, NULL);
    ok("the code is Access-Request", req[0] == RADIUS_ACCESS_REQUEST, NULL);
    ok("the identifier is carried", req[1] == 42, NULL);
    ok("the declared length matches",
       (((int)req[2] << 8) | req[3]) == n, NULL);
    ok("the authenticator is carried",
       memcmp(req + 4, auth, RADIUS_AUTH_LEN) == 0, NULL);

    uint8_t val[256];
    int l = get_attr(req, (size_t)n, 1, val, sizeof(val));
    ok("User-Name is present and correct",
       l == 5 && !memcmp(val, "alice", 5), NULL);

    l = get_attr(req, (size_t)n, 2, val, sizeof(val));
    ok("User-Password is present", l > 0, NULL);
    ok("it is padded to a multiple of 16", l > 0 && (l % 16) == 0, NULL);
    /* The whole point: the password must not travel in the clear. */
    ok("the password is not sent in plain text",
       l > 0 && memmem(req, (size_t)n, "correct horse", 13) == NULL, NULL);

    l = get_attr(req, (size_t)n, 4, val, sizeof(val));
    uint32_t nas;
    memcpy(&nas, val, 4);
    ok("NAS-IP-Address is present and correct",
       l == 4 && nas == ip("10.10.30.1"), NULL);

    l = get_attr(req, (size_t)n, 32, val, sizeof(val));
    ok("NAS-Identifier is present",
       l == (int)strlen("firex-test") && !memcmp(val, "firex-test", (size_t)l),
       NULL);

    ok("a request with no user is refused",
       radius_build_request(req, sizeof(req), 1, auth, "", "p", secret, 0, NULL) < 0,
       NULL);
    ok("a request with no secret is refused",
       radius_build_request(req, sizeof(req), 1, auth, "u", "p", "", 0, NULL) < 0,
       NULL);
    ok("a buffer too small is refused",
       radius_build_request(req, 32, 1, auth, "u", "p", secret, 0, NULL) < 0,
       NULL);

    /* ── response verification ── */
    puts("\n-- RADIUS response verification --");

    uint8_t resp[RADIUS_HDR_LEN];
    resp[0] = RADIUS_ACCESS_ACCEPT;
    resp[1] = 42;
    resp[2] = 0;
    resp[3] = RADIUS_HDR_LEN;

    uint8_t basis[RADIUS_HDR_LEN + 64];
    memcpy(basis, resp, 4);
    memcpy(basis + 4, auth, 16);
    memcpy(basis + RADIUS_HDR_LEN, secret, strlen(secret));
    uint8_t sig[16];
    md5_2(basis, RADIUS_HDR_LEN + strlen(secret), NULL, 0, sig);
    memcpy(resp + 4, sig, 16);

    ok("a correctly signed Accept verifies",
       radius_verify_response(resp, sizeof(resp), auth, secret)
         == RADIUS_ACCESS_ACCEPT, NULL);

    /*
     * This is the check that matters: without it, anyone able to spoof a UDP
     * source address could grant themselves network access.
     */
    uint8_t forged[RADIUS_HDR_LEN];
    memcpy(forged, resp, sizeof(forged));
    forged[4] ^= 0xff;
    ok("a forged authenticator is rejected",
       radius_verify_response(forged, sizeof(forged), auth, secret) < 0, NULL);

    ok("the wrong shared secret is rejected",
       radius_verify_response(resp, sizeof(resp), auth, "wrong-secret") < 0,
       NULL);

    uint8_t other[RADIUS_AUTH_LEN];
    memset(other, 0xAA, sizeof(other));
    ok("a reply to a different request is rejected",
       radius_verify_response(resp, sizeof(resp), other, secret) < 0, NULL);

    ok("a truncated packet is rejected",
       radius_verify_response(resp, 8, auth, secret) < 0, NULL);

    uint8_t liar[RADIUS_HDR_LEN];
    memcpy(liar, resp, sizeof(liar));
    liar[3] = 99;      /* declares a length it does not have */
    ok("a packet whose declared length is wrong is rejected",
       radius_verify_response(liar, sizeof(liar), auth, secret) < 0, NULL);

    /* ── full exchange against the mock server ── */
    puts("\n-- RADIUS against a mock server --");

    struct mock m;
    if (!mock_start(&m, 18120)) {
        ok("the mock RADIUS server starts", 0, "could not bind 127.0.0.1:18120");
        return;
    }
    snprintf(m.secret, sizeof(m.secret), "%s", secret);
    snprintf(m.good_user, sizeof(m.good_user), "alice");
    snprintf(m.good_pass, sizeof(m.good_pass), "correct horse");
    ok("the mock RADIUS server starts", 1, "127.0.0.1:18120");

    portal_cfg_t rc;
    memset(&rc, 0, sizeof(rc));
    rc.enabled = true;
    rc.auth = PORTAL_AUTH_RADIUS;
    rc.session_minutes = 60;
    snprintf(rc.radius_host, PORTAL_HOST_LEN, "127.0.0.1");
    rc.radius_port = 18120;
    snprintf(rc.radius_secret, PORTAL_SECRET_LEN, "%s", secret);
    snprintf(rc.nas_id, PORTAL_USER_LEN, "firex-test");
    rc.radius_timeout_ms = 1500;
    rc.radius_retries = 2;

    char why[192] = "";
    ok("correct credentials are accepted end to end",
       radius_authenticate(&rc, "alice", "correct horse", ip("10.10.30.1"),
                           why, sizeof(why)) == RADIUS_ACCESS_ACCEPT, why);
    ok("a wrong password is rejected",
       radius_authenticate(&rc, "alice", "wrong", ip("10.10.30.1"),
                           why, sizeof(why)) == RADIUS_ACCESS_REJECT, NULL);
    ok("an unknown user is rejected",
       radius_authenticate(&rc, "mallory", "whatever", ip("10.10.30.1"),
                           why, sizeof(why)) == RADIUS_ACCESS_REJECT, NULL);

    /* The server decrypted the password we encrypted, so both sides agree on
     * RFC 2865 section 5.2 independently. */
    ok("the server could decrypt what the client encrypted",
       m.served >= 3, NULL);

    /* The portal end to end. */
    portal_ctx_t rp;
    portal_init(&rp, &rc, false);
    ok("the portal logs a client in via RADIUS",
       portal_login(&rp, ip("10.10.30.40"), 30, "alice", "correct horse",
                    NULL, why, sizeof(why)) == 0, why);
    portal_session_t s;
    ok("the session records the username",
       portal_session(&rp, ip("10.10.30.40"), &s) && !strcmp(s.user, "alice"),
       s.user);
    ok("bad credentials do not open a session",
       portal_login(&rp, ip("10.10.30.41"), 30, "alice", "nope", NULL,
                    why, sizeof(why)) != 0 &&
       !portal_session(&rp, ip("10.10.30.41"), &s), why);
    ok("missing credentials are refused before any packet is sent",
       portal_login(&rp, ip("10.10.30.42"), 30, "", "", NULL,
                    why, sizeof(why)) != 0, why);
    portal_shutdown(&rp);

    /* A server whose signature does not verify must not grant access, even
     * though it replies with an Accept code. */
    m.corrupt_signature = true;
    why[0] = '\0';
    ok("an Accept with a bad signature is not trusted",
       radius_authenticate(&rc, "alice", "correct horse", ip("10.10.30.1"),
                           why, sizeof(why)) != RADIUS_ACCESS_ACCEPT, why);

    mock_stop(&m);

    /* No server configured at all. */
    portal_cfg_t none;
    memset(&none, 0, sizeof(none));
    ok("no configured server is refused, not hung on",
       radius_authenticate(&none, "u", "p", 0, why, sizeof(why)) < 0, why);
}

/* ═══════════════════ pages ═══════════════════ */

static void test_pages(void) {
    puts("\n-- portal pages --");

    portal_ctx_t p;
    portal_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = true;
    cfg.auth = PORTAL_AUTH_VOUCHER;
    cfg.session_minutes = 60;
    snprintf(cfg.terms, PORTAL_TERMS_LEN, "Be reasonable.");
    portal_init(&p, &cfg, false);

    char *page = malloc(32768);
    int n = portal_render_login(&p, page, 32768, "", "/");
    ok("the login page renders", n > 0, NULL);
    ok("it posts to the login endpoint",
       strstr(page, "action=\"/portal/login\"") != NULL, NULL);
    ok("voucher mode asks for a code",
       strstr(page, "name=\"voucher\"") != NULL, NULL);
    ok("and not for a password",
       strstr(page, "name=\"password\"") == NULL, NULL);
    ok("the terms are shown", strstr(page, "Be reasonable.") != NULL, NULL);

    /* The message comes from a failed login and the redirect from the
     * client's own request, so both must be escaped. */
    n = portal_render_login(&p, page, 32768,
                            "<script>alert(1)</script>",
                            "\"><script>alert(2)</script>");
    ok("a hostile message is escaped",
       n > 0 && strstr(page, "<script>alert(1)") == NULL &&
       strstr(page, "&lt;script&gt;") != NULL, NULL);
    ok("a hostile redirect cannot break out of its attribute",
       strstr(page, "\"><script>alert(2)") == NULL, NULL);

    cfg.auth = PORTAL_AUTH_RADIUS;
    portal_init(&p, &cfg, false);
    portal_render_login(&p, page, 32768, "", "/");
    ok("RADIUS mode asks for a username and password",
       strstr(page, "name=\"username\"") && strstr(page, "name=\"password\""),
       NULL);

    cfg.auth = PORTAL_AUTH_CLICK;
    portal_init(&p, &cfg, false);
    portal_render_login(&p, page, 32768, "", "/");
    ok("click-through asks for no credentials",
       !strstr(page, "name=\"username\"") && !strstr(page, "name=\"voucher\""),
       NULL);

    portal_session_t s;
    memset(&s, 0, sizeof(s));
    s.ip = ip("10.10.30.5");
    snprintf(s.user, PORTAL_USER_LEN, "guest");
    s.started = time(NULL);
    s.expires = s.started + 3600;
    s.used = true;

    n = portal_render_success(&p, &s, page, 32768);
    ok("the success page renders", n > 0, NULL);
    ok("it shows the client's address",
       strstr(page, "10.10.30.5") != NULL, NULL);
    ok("it shows who signed in", strstr(page, "guest") != NULL, NULL);

    char tiny[128];
    ok("a buffer too small is refused, not overflowed",
       portal_render_login(&p, tiny, sizeof(tiny), "", "") < 0, NULL);

    free(page);
    portal_shutdown(&p);
}

/* ═══════════════════ validation ═══════════════════ */

static void test_validation(void) {
    puts("\n-- validation --");

    cfg_validate_t res;
    ok("the shipped config, now with shaping and the portal, validates",
       firex_validate_file("config/firex.conf", &res) == 0, res.error);
    ok("the lab config still validates",
       firex_validate_file("config/firex-qemu.conf", &res) == 0, res.error);
}

int main(void) {
    test_shaping();
    test_sessions();
    test_vouchers();
    test_radius();
    test_pages();
    test_validation();

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
