/*
 * Phase 6 tests: VRRP and conntrackd config generation, and the signed
 * configuration replication between nodes.
 *
 * The signature is checked against an HMAC computed separately in this file,
 * and the push is driven against a mock peer that verifies it independently,
 * so the two sides have to agree without sharing code.
 *   make test-phase6
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <openssl/hmac.h>

#include "inspect.h"
#include "enterprise.h"
#include "reload.h"
#include "ha.h"
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

static char tmpdir[256];

/* Rotating buffers: one static would alias between two paths held at once. */
static const char *tpath(const char *name) {
    static char pool[8][512];
    static int idx;
    char *b = pool[idx++ % 8];
    snprintf(b, 512, "%s/%s", tmpdir, name);
    return b;
}

static bool file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static int file_mode(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return st.st_mode & 07777;
}

/* An HMAC computed here, not by the code under test. */
static void ref_sign(const char *secret, time_t ts, const void *body,
                     size_t len, char *out) {
    char prefix[32];
    int pl = snprintf(prefix, sizeof(prefix), "%lld\n", (long long)ts);

    unsigned char mac[64];
    unsigned int maclen = 0;
    HMAC_CTX *c = HMAC_CTX_new();
    HMAC_Init_ex(c, secret, (int)strlen(secret), EVP_sha256(), NULL);
    HMAC_Update(c, (const unsigned char *)prefix, (size_t)pl);
    if (len) HMAC_Update(c, body, len);
    HMAC_Final(c, mac, &maclen);
    HMAC_CTX_free(c);

    static const char HEX[] = "0123456789abcdef";
    for (unsigned i = 0; i < maclen; i++) {
        out[i*2]     = HEX[mac[i] >> 4];
        out[i*2 + 1] = HEX[mac[i] & 0x0f];
    }
    out[maclen * 2] = '\0';
}

/* ═══════════════════ signing ═══════════════════ */

static void test_signing(void) {
    puts("\n-- replication signatures --");

    const char *secret = "a-sufficiently-long-sync-secret";
    const char *body = "[system]\ndomain = example.com\n";
    size_t blen = strlen(body);
    time_t ts = 1767322445;

    char sig[HA_SIG_LEN];
    ok("a signature is produced",
       ha_sign(secret, ts, body, blen, sig, sizeof(sig)) == 64, NULL);
    ok("it is 64 hex characters", strlen(sig) == 64, sig);

    char ref[80];
    ref_sign(secret, ts, body, blen, ref);
    ok("it matches an independently computed HMAC-SHA256",
       !strcmp(sig, ref), NULL);

    char other[HA_SIG_LEN];
    ha_sign(secret, ts, body, blen, other, sizeof(other));
    ok("signing is deterministic", !strcmp(sig, other), NULL);

    ha_sign(secret, ts, "different body", 14, other, sizeof(other));
    ok("a different body signs differently", strcmp(sig, other) != 0, NULL);

    ha_sign(secret, ts + 1, body, blen, other, sizeof(other));
    ok("a different timestamp signs differently", strcmp(sig, other) != 0, NULL);

    ha_sign("another-secret-entirely", ts, body, blen, other, sizeof(other));
    ok("a different secret signs differently", strcmp(sig, other) != 0, NULL);

    ok("an empty body still signs",
       ha_sign(secret, ts, NULL, 0, other, sizeof(other)) == 64, NULL);
    ok("no secret is refused",
       ha_sign("", ts, body, blen, other, sizeof(other)) < 0, NULL);
    ok("a buffer too small is refused",
       ha_sign(secret, ts, body, blen, other, 8) < 0, NULL);

    /* ── verification ── */
    puts("\n-- replication verification --");

    char tsb[32];
    snprintf(tsb, sizeof(tsb), "%lld", (long long)ts);
    char why[256];

    ok("a correctly signed push verifies",
       ha_verify(secret, tsb, sig, body, blen, ts, why, sizeof(why)), why);
    ok("it verifies anywhere inside the window",
       ha_verify(secret, tsb, sig, body, blen, ts + HA_REPLAY_WINDOW - 1,
                 why, sizeof(why)), why);

    ok("a wrong signature is rejected",
       !ha_verify(secret, tsb, "00000000000000000000000000000000"
                  "00000000000000000000000000000000",
                  body, blen, ts, why, sizeof(why)), why);
    ok("the wrong secret is rejected",
       !ha_verify("wrong-secret-entirely-here", tsb, sig, body, blen, ts,
                  why, sizeof(why)), why);
    ok("an altered body is rejected",
       !ha_verify(secret, tsb, sig, "tampered", 8, ts, why, sizeof(why)), why);

    /*
     * The timestamp is inside the signed material, so a captured push cannot
     * be replayed later by presenting a fresh timestamp header: the old
     * signature will not match the new one.
     */
    char fresh[32];
    snprintf(fresh, sizeof(fresh), "%lld", (long long)(ts + 10000));
    ok("a replay with a fresh timestamp header is rejected",
       !ha_verify(secret, fresh, sig, body, blen, ts + 10000,
                  why, sizeof(why)), why);

    ok("a stale push is rejected",
       !ha_verify(secret, tsb, sig, body, blen, ts + HA_REPLAY_WINDOW + 60,
                  why, sizeof(why)), why);
    ok("a push from the future is rejected too",
       !ha_verify(secret, tsb, sig, body, blen, ts - HA_REPLAY_WINDOW - 60,
                  why, sizeof(why)), why);
    ok("the clock-skew message says what to check",
       strstr(why, "clock") != NULL, why);

    ok("a missing timestamp is rejected",
       !ha_verify(secret, NULL, sig, body, blen, ts, why, sizeof(why)), why);
    ok("a missing signature is rejected",
       !ha_verify(secret, tsb, NULL, body, blen, ts, why, sizeof(why)), why);
    ok("a non-numeric timestamp is rejected",
       !ha_verify(secret, "tomorrow", sig, body, blen, ts, why, sizeof(why)), why);
    ok("no configured secret refuses everything",
       !ha_verify("", tsb, sig, body, blen, ts, why, sizeof(why)), why);
}

/* ═══════════════════ generated configuration ═══════════════════ */

static void build_net(vlan_ctx_t *v) {
    vlan_init(v);

    port_config_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.ifname, IFNAME_LEN, "eth1");
    p.mode = PORT_MODE_TRUNK; p.zone = ZONE_LAN; p.enabled = true;
    p.allowed_vlans[0] = 10; p.allowed_vlans[1] = 99; p.allowed_count = 2;
    port_configure(v, &p);

    memset(&p, 0, sizeof(p));
    snprintf(p.ifname, IFNAME_LEN, "eth2");
    p.mode = PORT_MODE_ACCESS; p.zone = ZONE_DMZ; p.pvid = 20; p.enabled = true;
    port_configure(v, &p);

    vlan_config_t c;
    memset(&c, 0, sizeof(c));
    c.vlan_id = 10; snprintf(c.name, sizeof(c.name), "CORP");
    c.zone = ZONE_LAN; c.lease_time = 86400;
    c.subnet = ip("10.10.10.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.10.1");
    vlan_add(v, &c);

    memset(&c, 0, sizeof(c));
    c.vlan_id = 20; snprintf(c.name, sizeof(c.name), "SERVERS");
    c.zone = ZONE_DMZ; c.lease_time = 86400;
    c.subnet = ip("10.10.20.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.20.1");
    vlan_add(v, &c);

    memset(&c, 0, sizeof(c));
    c.vlan_id = 99; snprintf(c.name, sizeof(c.name), "MGMT");
    c.zone = ZONE_MGMT; c.lease_time = 86400;
    c.subnet = ip("10.10.99.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.99.1");
    vlan_add(v, &c);
}

static void base_cfg(ha_cfg_t *c, ha_role_t role) {
    memset(c, 0, sizeof(*c));
    c->enabled = true;
    c->role = role;
    snprintf(c->peer_address, HA_ADDR_LEN, "10.10.99.3");
    snprintf(c->sync_address, HA_ADDR_LEN, "10.10.99.2");
    snprintf(c->sync_interface, IFNAME_LEN, "eth1.99");
    c->vrrp_id = 51;
    snprintf(c->vrrp_password, HA_VRRP_PASS_LEN, "fxvrrp01");
    c->priority = role == HA_ROLE_PRIMARY ? 150 : 100;
    c->advert_interval = 1;
    c->preempt = true;
    c->conntrack_sync = true;
    c->conntrack_port = 3780;
    c->config_sync = true;
    c->config_sync_port = 8080;
    snprintf(c->sync_secret, HA_SECRET_LEN, "a-sufficiently-long-sync-secret");
}

static void test_generation(void) {
    puts("\n-- generated VRRP configuration --");

    vlan_ctx_t v;
    build_net(&v);

    ha_ctx_t h;
    ha_cfg_t cfg;
    base_cfg(&cfg, HA_ROLE_PRIMARY);
    ha_init(&h, &cfg);

    const char *ka = tpath("keepalived.conf");
    const char *notify = tpath("ha-notify.sh");

    int vips = ha_generate_keepalived(&h, &v, ka, notify);
    ok("every VLAN with a gateway becomes a virtual address", vips == 3, NULL);
    ok("the file is owner-only", file_mode(ka) == 0600, NULL);

    /*
     * Both nodes start as BACKUP and let priority decide. Declaring the
     * primary MASTER makes it claim the addresses before hearing from the
     * peer, which is how a restart produces two masters.
     */
    ok("both nodes start as BACKUP, not MASTER",
       file_has(ka, "state BACKUP") && !file_has(ka, "state MASTER"), NULL);
    ok("the priority is carried", file_has(ka, "priority 150"), NULL);
    ok("the router id is carried", file_has(ka, "virtual_router_id 51"), NULL);
    ok("the advert interval is carried", file_has(ka, "advert_int 1"), NULL);
    ok("preempt is requested", file_has(ka, "preempt"), NULL);
    ok("the sync interface is used for VRRP",
       file_has(ka, "interface eth1.99"), NULL);
    ok("unicast is used rather than multicast",
       file_has(ka, "unicast_src_ip 10.10.99.2") &&
       file_has(ka, "unicast_peer"), NULL);
    ok("the peer address is listed", file_has(ka, "10.10.99.3"), NULL);

    ok("a trunked VLAN's address lands on its sub-interface",
       file_has(ka, "10.10.10.1/24 dev eth1.10"), NULL);
    ok("an access port's VLAN lands on the port itself",
       file_has(ka, "10.10.20.1/24 dev eth2"), NULL);
    ok("the management VLAN is carried too",
       file_has(ka, "10.10.99.1/24 dev eth1.99"), NULL);

    ok("the notify script is wired for every transition",
       file_has(ka, "notify_master") && file_has(ka, "notify_backup") &&
       file_has(ka, "notify_fault"), NULL);
    ok("authentication is configured", file_has(ka, "auth_type PASS"), NULL);
    ok("the VRRP password is carried", file_has(ka, "auth_pass fxvrrp01"), NULL);

    /* VRRPv2 only uses the first 8 characters. */
    snprintf(h.cfg.vrrp_password, HA_VRRP_PASS_LEN, "averylongvrrppassword");
    ha_generate_keepalived(&h, &v, ka, notify);
    ok("a long VRRP password is truncated to the 8 bytes VRRP uses",
       file_has(ka, "auth_pass averylon") &&
       !file_has(ka, "auth_pass averylongvrrppassword"), NULL);

    /* nopreempt */
    h.cfg.preempt = false;
    ha_generate_keepalived(&h, &v, ka, notify);
    ok("nopreempt is emitted when preemption is off",
       file_has(ka, "nopreempt"), NULL);

    /* secondary */
    ha_cfg_t sec;
    base_cfg(&sec, HA_ROLE_SECONDARY);
    ha_ctx_t h2;
    ha_init(&h2, &sec);
    const char *ka2 = tpath("keepalived-secondary.conf");
    ha_generate_keepalived(&h2, &v, ka2, notify);
    ok("the secondary gets the lower priority",
       file_has(ka2, "priority 100"), NULL);
    ok("it is identified as the secondary",
       file_has(ka2, "router_id FireX-secondary"), NULL);
    ok("it also starts as BACKUP", file_has(ka2, "state BACKUP"), NULL);

    /* ── notify script ── */
    puts("\n-- notify script --");

    ok("the notify script is written", ha_generate_notify(&h, notify) == 0, NULL);
    ok("it is executable", (file_mode(notify) & 0100) != 0, NULL);
    ok("it records the state keepalived passes",
       file_has(notify, HA_STATE_FILE) && file_has(notify, "\"$3\""), NULL);

    /* ── conntrackd ── */
    puts("\n-- generated connection sync --");

    const char *ct = tpath("conntrackd.conf");
    ok("conntrackd config is written",
       ha_generate_conntrackd(&h, ct) == 0, NULL);
    ok("it is owner-only", file_mode(ct) == 0600, NULL);
    ok("FTFW is the mode, so missed updates are resent",
       file_has(ct, "Mode FTFW"), NULL);
    ok("this node's address is set",
       file_has(ct, "IPv4_address 10.10.99.2"), NULL);
    ok("the peer's address is set",
       file_has(ct, "IPv4_Destination_Address 10.10.99.3"), NULL);
    ok("the port is set", file_has(ct, "Port 3780"), NULL);
    ok("the sync interface is set", file_has(ct, "Interface eth1.99"), NULL);
    ok("TCP and UDP are replicated",
       file_has(ct, "TCP") && file_has(ct, "UDP"), NULL);

    /* Replicating the sync link's own traffic would feed on itself. */
    ok("loopback and both sync addresses are ignored",
       file_has(ct, "IPv4_address 127.0.0.1") &&
       file_has(ct, "Address Ignore"), NULL);

    h.cfg.conntrack_sync = false;
    const char *ct2 = tpath("conntrackd-off.conf");
    ok("nothing is written when connection sync is off",
       ha_generate_conntrackd(&h, ct2) == 0 && access(ct2, F_OK) != 0, NULL);

    /* ── disabled ── */
    ha_cfg_t off;
    memset(&off, 0, sizeof(off));
    ha_ctx_t h3;
    ha_init(&h3, &off);
    const char *ka3 = tpath("keepalived-off.conf");
    ok("a disabled HA writes no VRRP config",
       ha_generate_keepalived(&h3, &v, ka3, notify) == 0 &&
       access(ka3, F_OK) != 0, NULL);

    ha_shutdown(&h);
    ha_shutdown(&h2);
    ha_shutdown(&h3);
    vlan_shutdown(&v);
}

/* ═══════════════════ state ═══════════════════ */

static void test_state(void) {
    puts("\n-- state tracking --");

    ok("state names parse",
       ha_state_from("MASTER") == HA_STATE_MASTER &&
       ha_state_from("BACKUP") == HA_STATE_BACKUP &&
       ha_state_from("FAULT")  == HA_STATE_FAULT, NULL);
    ok("an unknown state parses as unknown",
       ha_state_from("WHATEVER") == HA_STATE_UNKNOWN &&
       ha_state_from(NULL) == HA_STATE_UNKNOWN, NULL);
    ok("state names format back",
       !strcmp(ha_state_name(HA_STATE_MASTER), "MASTER"), NULL);
    ok("roles parse and format",
       ha_role_from("secondary") == HA_ROLE_SECONDARY &&
       ha_role_from("primary") == HA_ROLE_PRIMARY &&
       ha_role_from("anything else") == HA_ROLE_PRIMARY &&
       !strcmp(ha_role_name(HA_ROLE_SECONDARY), "secondary"), NULL);

    ha_ctx_t h;
    ha_cfg_t cfg;
    base_cfg(&cfg, HA_ROLE_PRIMARY);
    ha_init(&h, &cfg);

    ok("a fresh node's state is unknown", h.state == HA_STATE_UNKNOWN, NULL);

    ha_set_state(&h, HA_STATE_BACKUP);
    ok("a transition is recorded",
       h.state == HA_STATE_BACKUP && h.transitions == 1 && h.state_since > 0,
       NULL);

    ha_set_state(&h, HA_STATE_BACKUP);
    ok("setting the same state again is not a transition",
       h.transitions == 1, NULL);

    ha_set_state(&h, HA_STATE_MASTER);
    ok("taking over is a transition",
       h.state == HA_STATE_MASTER && h.transitions == 2, NULL);

    ha_shutdown(&h);
}

/* ═══════════════════ the push, against a mock peer ═══════════════════ */

struct peer {
    int      fd;
    char     secret[128];
    bool     running;
    bool     verified;
    bool     reject;          /* answer 401 regardless */
    char     got_body[4096];
    size_t   got_len;
    int      served;
    pthread_t th;
};

/* A peer that checks the signature with its own HMAC, not the client's. */
static void *peer_server(void *arg) {
    struct peer *p = arg;

    while (p->running) {
        int c = accept(p->fd, NULL, NULL);
        if (c < 0) continue;

        char buf[8192];
        size_t total = 0;
        char *hdr_end = NULL;
        while (total < sizeof(buf) - 1) {
            ssize_t n = read(c, buf + total, sizeof(buf) - 1 - total);
            if (n <= 0) break;
            total += (size_t)n;
            buf[total] = '\0';
            if ((hdr_end = strstr(buf, "\r\n\r\n")) != NULL) {
                size_t head = (size_t)(hdr_end - buf) + 4;
                const char *cl = strcasestr(buf, "\nContent-Length:");
                long want = cl ? strtol(cl + 16, NULL, 10) : 0;
                if ((long)(total - head) >= want) break;
            }
        }
        if (!hdr_end) { close(c); continue; }

        size_t head = (size_t)(hdr_end - buf) + 4;
        const char *body = buf + head;
        size_t blen = total - head;

        char ts[32] = "", sig[80] = "";
        const char *t = strcasestr(buf, "X-FireX-HA-Timestamp:");
        if (t) sscanf(t + 21, " %31s", ts);
        const char *g = strcasestr(buf, "X-FireX-HA-Signature:");
        if (g) sscanf(g + 21, " %79s", sig);

        char want[80] = "";
        if (ts[0]) ref_sign(p->secret, (time_t)strtoll(ts, NULL, 10),
                            body, blen, want);

        p->verified = ts[0] && sig[0] && !strcmp(want, sig);
        p->got_len = blen < sizeof(p->got_body) ? blen : sizeof(p->got_body) - 1;
        memcpy(p->got_body, body, p->got_len);
        p->got_body[p->got_len] = '\0';
        p->served++;

        const char *resp = (p->verified && !p->reject)
            ? "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
            : "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n"
              "Connection: close\r\n\r\n{}";
        if (write(c, resp, strlen(resp)) < 0) { /* the client may have gone */ }
        close(c);
    }
    return NULL;
}

static bool peer_start(struct peer *p, uint16_t port, const char *secret) {
    memset(p, 0, sizeof(*p));
    snprintf(p->secret, sizeof(p->secret), "%s", secret);

    p->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (p->fd < 0) return false;
    int one = 1;
    setsockopt(p->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(p->fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(p->fd, 4) != 0) {
        close(p->fd);
        return false;
    }
    struct timeval tv = { 0, 200000 };
    setsockopt(p->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    p->running = true;
    return pthread_create(&p->th, NULL, peer_server, p) == 0;
}

static void peer_stop(struct peer *p) {
    p->running = false;
    shutdown(p->fd, SHUT_RDWR);
    close(p->fd);
    pthread_join(p->th, NULL);
}

static void test_push(void) {
    puts("\n-- configuration push --");

    const char *secret = "a-sufficiently-long-sync-secret";

    struct peer peer;
    if (!peer_start(&peer, 18443, secret)) {
        ok("the mock peer starts", 0, "could not bind 127.0.0.1:18443");
        return;
    }
    ok("the mock peer starts", 1, "127.0.0.1:18443");

    /* A small config file to push. */
    const char *cfgpath = tpath("push.conf");
    FILE *f = fopen(cfgpath, "w");
    fprintf(f, "[system]\ndomain = replicated.example\n");
    fclose(f);

    ha_ctx_t h;
    ha_cfg_t cfg;
    base_cfg(&cfg, HA_ROLE_PRIMARY);
    snprintf(cfg.peer_address, HA_ADDR_LEN, "127.0.0.1");
    cfg.config_sync_port = 18443;
    ha_init(&h, &cfg);

    char why[256] = "";
    ok("the primary pushes successfully",
       ha_push_config(&h, cfgpath, why, sizeof(why)) == 0, why);
    ok("the peer verified the signature itself", peer.verified, NULL);
    ok("the peer received the configuration body",
       strstr(peer.got_body, "replicated.example") != NULL, NULL);
    ok("the push is counted", h.pushes_sent == 1, NULL);

    /* A secret mismatch must be caught by the peer, not waved through. */
    snprintf(h.cfg.sync_secret, HA_SECRET_LEN, "a-different-secret-entirely");
    why[0] = '\0';
    ok("a push signed with the wrong secret is refused",
       ha_push_config(&h, cfgpath, why, sizeof(why)) != 0, why);
    ok("the peer did not verify it", !peer.verified, NULL);
    ok("the rejection is counted", h.pushes_rejected == 1, NULL);

    snprintf(h.cfg.sync_secret, HA_SECRET_LEN, "%s", secret);

    /* A secondary must not push: replication is one-way by design. */
    h.cfg.role = HA_ROLE_SECONDARY;
    why[0] = '\0';
    ok("a secondary refuses to push",
       ha_push_config(&h, cfgpath, why, sizeof(why)) != 0 &&
       strstr(why, "primary") != NULL, why);
    h.cfg.role = HA_ROLE_PRIMARY;

    h.cfg.config_sync = false;
    ok("pushing is a no-op when config sync is off",
       ha_push_config(&h, cfgpath, why, sizeof(why)) == 0, NULL);
    h.cfg.config_sync = true;

    why[0] = '\0';
    ok("a missing config file is reported, not pushed",
       ha_push_config(&h, tpath("nope.conf"), why, sizeof(why)) != 0, why);

    char saved[HA_ADDR_LEN];
    snprintf(saved, sizeof(saved), "%s", h.cfg.peer_address);
    h.cfg.peer_address[0] = '\0';
    why[0] = '\0';
    ok("no peer address is reported, not guessed",
       ha_push_config(&h, cfgpath, why, sizeof(why)) != 0, why);
    snprintf(h.cfg.peer_address, HA_ADDR_LEN, "%s", saved);

    /* A peer that refuses must be reported as a failure, not a success. */
    peer.reject = true;
    why[0] = '\0';
    ok("a peer that refuses the push is reported",
       ha_push_config(&h, cfgpath, why, sizeof(why)) != 0, why);
    peer.reject = false;

    peer_stop(&peer);

    why[0] = '\0';
    ok("an unreachable peer is reported, not hung on",
       ha_push_config(&h, cfgpath, why, sizeof(why)) != 0, why);

    ha_shutdown(&h);
}

/* ═══════════════════ validation ═══════════════════ */

static void build_base(vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *b) {
    build_net(v);
    netconf_init(n);
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->lock, NULL);
    b->enabled = true;
    b->port = 8080;

    wan_config_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.ifname, IFNAME_LEN, "eth0");
    w.mode = WAN_DHCP; w.mtu = 1500;
    n->wan[n->wan_count++] = w;

    base_cfg(&n->ha, HA_ROLE_PRIMARY);
}

static void expect_bad(const char *what, vlan_ctx_t *v, netconf_ctx_t *n,
                       blockpage_ctx_t *b) {
    cfg_validate_t res;
    int rc = firex_validate(v, n, b, NULL, &res);
    ok(what, rc != 0, rc != 0 ? res.error : "ACCEPTED, should not have been");
}

static void test_validation(void) {
    puts("\n-- validation --");

    vlan_ctx_t v; netconf_ctx_t n; blockpage_ctx_t b;
    cfg_validate_t res;

    build_base(&v, &n, &b);
    ok("the baseline HA configuration is valid",
       firex_validate(&v, &n, &b, NULL, &res) == 0, res.error);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.peer_address[0] = '\0';
    expect_bad("HA with no peer address", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.sync_interface[0] = '\0';
    expect_bad("HA with no sync interface", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    snprintf(n.ha.sync_interface, IFNAME_LEN, "eth1; rm -rf /");
    expect_bad("a sync interface that is not shell-safe", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    snprintf(n.ha.peer_address, HA_ADDR_LEN, "not-an-address");
    expect_bad("a peer address that is not an IPv4 address", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    snprintf(n.ha.sync_address, HA_ADDR_LEN, "10.10.99.3");
    expect_bad("a node sharing an address with its peer", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    /* A node whose sync address is a VLAN gateway would lose the address
     * VRRP moves, and with it the link to its peer. */
    build_base(&v, &n, &b);
    snprintf(n.ha.sync_address, HA_ADDR_LEN, "10.10.99.1");
    expect_bad("a sync address that VRRP will move", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.vrrp_id = 300;
    expect_bad("a VRRP id outside 1-255", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.priority = 300;
    expect_bad("a priority outside 1-254", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.sync_secret[0] = '\0';
    expect_bad("config sync with no shared secret", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    snprintf(n.ha.sync_secret, HA_SECRET_LEN, "short");
    expect_bad("a sync secret under 16 characters", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.conntrack_port = b.port;
    expect_bad("a conntrack port that collides with the portal", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    puts("\n-- validation: warnings --");

    build_base(&v, &n, &b);
    n.ha.vrrp_password[0] = '\0';
    ok("no VRRP password is allowed but warned about",
       firex_validate(&v, &n, &b, NULL, &res) == 0 && res.warnings > 0,
       res.warning);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    snprintf(n.ha.vrrp_password, HA_VRRP_PASS_LEN, "muchlongerthaneight");
    ok("an over-long VRRP password warns that most of it is ignored",
       firex_validate(&v, &n, &b, NULL, &res) == 0 && res.warnings > 0,
       res.warning);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.priority = 90;
    ok("a primary that cannot outrank the secondary warns",
       firex_validate(&v, &n, &b, NULL, &res) == 0 && res.warnings > 0,
       res.warning);
    vlan_shutdown(&v); netconf_shutdown(&n);

    build_base(&v, &n, &b);
    n.ha.enabled = false;
    n.ha.vrrp_id = 999;
    expect_bad("range checks apply even while HA is off", &v, &n, &b);
    vlan_shutdown(&v); netconf_shutdown(&n);

    ok("the shipped config, now with an HA section, validates",
       firex_validate_file("config/firex.conf", &res) == 0, res.error);
    ok("the lab config still validates",
       firex_validate_file("config/firex-qemu.conf", &res) == 0, res.error);
}

int main(void) {
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/firex-p6-XXXXXX");
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }

    test_signing();
    test_generation();
    test_state();
    test_push();
    test_validation();

    printf("\n%d passed, %d failed\n", pass, fail);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
    if (system(cmd) != 0) fprintf(stderr, "note: could not clean %s\n", tmpdir);

    return fail ? 1 : 0;
}
