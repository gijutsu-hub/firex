/*
 * Phase 3 tests: WireGuard key management, the peer table, per-peer zone
 * assignment, generated configuration files and IPsec.
 *
 * Nothing here touches the network or needs root; the generated files go to
 * a temporary directory.
 *   make test-phase3
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "inspect.h"
#include "enterprise.h"
#include "config_write.h"
#include "reload.h"
#include "vpn.h"
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

/*
 * One static buffer would alias between calls, so two paths held at once
 * would silently become the same path -- the same trap fx_ip_str() exists to
 * avoid. Rotate through a small pool instead.
 */
static const char *tpath(const char *name) {
    static char pool[8][512];
    static int idx;
    char *buf = pool[idx++ % 8];
    snprintf(buf, 512, "%s/%s", tmpdir, name);
    return buf;
}

/* Does this file contain the given text? */
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

/* ═══════════════════ keys ═══════════════════ */

static void test_keys(void) {
    puts("\n-- WireGuard key management --");

    char priv[WG_KEY_B64_LEN], pub[WG_KEY_B64_LEN];
    ok("a keypair is generated", wg_generate_keypair(priv, pub) == 0, NULL);
    ok("the private key is 44 base64 characters", strlen(priv) == 44, priv);
    ok("the public key is 44 base64 characters", strlen(pub) == 44, pub);
    ok("the two halves differ", strcmp(priv, pub) != 0, NULL);
    ok("both validate", wg_key_valid(priv) && wg_key_valid(pub), NULL);

    char priv2[WG_KEY_B64_LEN], pub2[WG_KEY_B64_LEN];
    wg_generate_keypair(priv2, pub2);
    ok("a second keypair is different",
       strcmp(priv, priv2) != 0 && strcmp(pub, pub2) != 0, NULL);

    char derived[WG_KEY_B64_LEN];
    ok("the public key re-derives from the private key",
       wg_public_from_private(priv, derived) == 0 && !strcmp(derived, pub), NULL);
    ok("a different private key derives a different public key",
       wg_public_from_private(priv2, derived) == 0 && strcmp(derived, pub) != 0,
       NULL);

    /* malformed keys */
    ok("a short key is refused",  !wg_key_valid("abc"), NULL);
    ok("an empty key is refused", !wg_key_valid(""), NULL);
    ok("NULL is refused",         !wg_key_valid(NULL), NULL);
    ok("43 characters is refused",
       !wg_key_valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), NULL);
    ok("45 characters is refused",
       !wg_key_valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), NULL);
    ok("44 characters without the trailing '=' is refused",
       !wg_key_valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), NULL);
    ok("a non-base64 character is refused",
       !wg_key_valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!AA="), NULL);
    ok("deriving from a malformed private key fails",
       wg_public_from_private("nonsense", derived) != 0, NULL);

    /* fingerprints */
    char fp1[32], fp2[32];
    wg_key_fingerprint(priv, fp1, sizeof(fp1));
    wg_key_fingerprint(priv, fp2, sizeof(fp2));
    ok("a fingerprint is stable", !strcmp(fp1, fp2), fp1);
    ok("it is short", strlen(fp1) == 8, fp1);
    ok("it does not contain the key",
       strstr(priv, fp1) == NULL && strstr(fp1, priv) == NULL, NULL);

    wg_key_fingerprint(priv2, fp2, sizeof(fp2));
    ok("different keys fingerprint differently", strcmp(fp1, fp2) != 0, NULL);
    ok("an absent key reads as none",
       !strcmp(wg_key_fingerprint("", fp1, sizeof(fp1)), "(none)"), fp1);
    ok("a malformed key reads as invalid",
       !strcmp(wg_key_fingerprint("garbage", fp1, sizeof(fp1)), "(invalid)"), fp1);

    explicit_bzero(priv, sizeof(priv));
    explicit_bzero(priv2, sizeof(priv2));
}

/* ═══════════════════ tables ═══════════════════ */

static void make_iface(wg_iface_t *w, const char *name, uint16_t port,
                       const char *addr, zone_t z) {
    memset(w, 0, sizeof(*w));
    snprintf(w->ifname, IFNAME_LEN, "%s", name);
    w->listen_port = port;
    w->address = ip(addr);
    w->netmask = ip("255.255.255.0");
    w->mtu     = 1420;
    w->zone    = z;
    w->enabled = true;
    char pub[WG_KEY_B64_LEN];
    wg_generate_keypair(w->private_key, pub);
}

static void make_peer(wg_peer_t *p, const char *name, const char *ifn,
                      const char *cidr, zone_t z) {
    memset(p, 0, sizeof(*p));
    snprintf(p->name, VPN_NAME_LEN, "%s", name);
    snprintf(p->ifname, IFNAME_LEN, "%s", ifn);
    p->zone = z;
    p->enabled = true;
    char priv[WG_KEY_B64_LEN];
    wg_generate_keypair(priv, p->public_key);
    explicit_bzero(priv, sizeof(priv));
    fx_parse_cidr(cidr, &p->allowed[0].ip, &p->allowed[0].mask);
    p->allowed_count = 1;
}

static void test_tables(void) {
    puts("\n-- interface and peer tables --");

    vpn_ctx_t v;
    vpn_init(&v);

    wg_iface_t w;
    make_iface(&w, "wg0", 51820, "10.99.0.1", ZONE_VPN);
    ok("an interface is accepted", vpn_add_wg(&v, &w) == 0, NULL);
    ok("the same interface twice is refused", vpn_add_wg(&v, &w) != 0, NULL);
    ok("it can be found", vpn_find_wg(&v, "wg0") != NULL, NULL);
    ok("an unknown interface is not found", vpn_find_wg(&v, "wg9") == NULL, NULL);

    wg_iface_t *stored = vpn_find_wg(&v, "wg0");
    char expect[WG_KEY_B64_LEN];
    wg_public_from_private(w.private_key, expect);
    ok("the public key is derived on insert",
       stored && !strcmp(stored->public_key, expect), NULL);

    wg_iface_t noname;
    make_iface(&noname, "", 51821, "10.98.0.1", ZONE_VPN);
    ok("an interface with no name is refused", vpn_add_wg(&v, &noname) != 0, NULL);

    wg_peer_t p;
    make_peer(&p, "branch", "wg0", "10.99.0.2/32", ZONE_LAN);
    ok("a peer is accepted", vpn_add_peer(&v, &p) == 0, NULL);
    ok("the same peer twice is refused", vpn_add_peer(&v, &p) != 0, NULL);
    ok("it can be found", vpn_find_peer(&v, "branch") != NULL, NULL);

    wg_peer_t keyless;
    make_peer(&keyless, "nokey", "wg0", "10.99.0.9/32", ZONE_VPN);
    keyless.public_key[0] = '\0';
    ok("a peer with no public key is refused",
       vpn_add_peer(&v, &keyless) != 0, NULL);

    make_peer(&p, "laptop", "wg0", "10.99.0.50/32", ZONE_GUEST);
    vpn_add_peer(&v, &p);
    ok("two peers are held", v.peer_count == 2, NULL);

    ok("a peer can be removed",
       vpn_remove_peer(&v, "branch") == 0 && v.peer_count == 1, NULL);
    ok("removing it again fails", vpn_remove_peer(&v, "branch") != 0, NULL);
    ok("the other peer survived", vpn_find_peer(&v, "laptop") != NULL, NULL);

    ok("a WireGuard interface is recognised", vpn_is_wg_iface(&v, "wg0"), NULL);
    ok("an ordinary interface is not", !vpn_is_wg_iface(&v, "eth0"), NULL);

    vpn_shutdown(&v);
}

/* ═══════════════════ per-peer zone assignment ═══════════════════ */

static void test_zone_mapping(void) {
    puts("\n-- per-peer zone assignment --");

    vpn_ctx_t v;
    vpn_init(&v);

    wg_iface_t w;
    make_iface(&w, "wg0", 51820, "10.99.0.1", ZONE_VPN);
    vpn_add_wg(&v, &w);

    /* A branch office carrying a whole site, and one host inside that site
     * pulled out into a stricter zone. */
    wg_peer_t site;
    make_peer(&site, "branch", "wg0", "192.168.50.0/24", ZONE_LAN);
    vpn_add_peer(&v, &site);

    wg_peer_t host;
    make_peer(&host, "branch-kiosk", "wg0", "192.168.50.77/32", ZONE_GUEST);
    vpn_add_peer(&v, &host);

    wg_peer_t roam;
    make_peer(&roam, "laptop", "wg0", "10.99.0.50/32", ZONE_GUEST);
    vpn_add_peer(&v, &roam);

    ok("an address inside a peer's range takes that peer's zone",
       vpn_zone_for(&v, ip("192.168.50.10")) == ZONE_LAN, NULL);
    ok("a more specific peer wins over a broader one",
       vpn_zone_for(&v, ip("192.168.50.77")) == ZONE_GUEST, NULL);
    ok("a roaming peer's single address maps",
       vpn_zone_for(&v, ip("10.99.0.50")) == ZONE_GUEST, NULL);
    ok("an address no peer claims maps to nothing",
       vpn_zone_for(&v, ip("8.8.8.8")) == ZONE_MAX, NULL);
    ok("a NULL table claims nothing",
       vpn_zone_for(NULL, ip("192.168.50.10")) == ZONE_MAX, NULL);

    /* A disabled peer must stop claiming its addresses. */
    wg_peer_t *stored = vpn_find_peer(&v, "branch-kiosk");
    stored->enabled = false;
    ok("a disabled peer stops claiming its addresses",
       vpn_zone_for(&v, ip("192.168.50.77")) == ZONE_LAN, NULL);

    /* IPsec tunnels claim their remote subnet too. */
    ipsec_tunnel_t t;
    memset(&t, 0, sizeof(t));
    snprintf(t.name, VPN_NAME_LEN, "dc");
    snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
    snprintf(t.psk, VPN_SECRET_LEN, "a-sufficiently-long-secret");
    fx_parse_cidr("10.10.0.0/16",  &t.local_subnet,  &t.local_mask);
    fx_parse_cidr("172.30.0.0/16", &t.remote_subnet, &t.remote_mask);
    t.zone = ZONE_DMZ;
    t.enabled = true;
    ok("a tunnel is accepted", vpn_add_tunnel(&v, &t) == 0, NULL);
    ok("its remote subnet maps to its zone",
       vpn_zone_for(&v, ip("172.30.4.5")) == ZONE_DMZ, NULL);
    ok("the same tunnel twice is refused", vpn_add_tunnel(&v, &t) != 0, NULL);
    ok("proposal defaults are filled in",
       vpn_find_peer(&v, "laptop") != NULL &&
       v.tunnels[0].ike_proposal[0] && v.tunnels[0].esp_proposal[0], NULL);

    vpn_shutdown(&v);
}

/* The zone matrix has to govern VPN traffic the same way it governs VLANs. */
static void test_zone_policy(void) {
    puts("\n-- zone policy over tunnels --");

    vlan_ctx_t v;
    vlan_init(&v);
    vlan_set_zone_policy(&v, ZONE_VPN, ZONE_LAN, IVR_ALLOW);
    vlan_set_zone_policy(&v, ZONE_VPN, ZONE_MGMT, IVR_DENY);
    vlan_set_zone_policy(&v, ZONE_GUEST, ZONE_LAN, IVR_DENY);

    char why[256];
    ok("a permitted zone pair is allowed",
       vlan_check_zones(&v, ZONE_VPN, ZONE_LAN, why, sizeof(why)) == IVR_ALLOW, why);
    ok("a denied zone pair is denied",
       vlan_check_zones(&v, ZONE_VPN, ZONE_MGMT, why, sizeof(why)) == IVR_DENY, why);
    ok("a peer placed in GUEST is held to GUEST policy",
       vlan_check_zones(&v, ZONE_GUEST, ZONE_LAN, why, sizeof(why)) == IVR_DENY, why);
    ok("a zone always reaches itself",
       vlan_check_zones(&v, ZONE_VPN, ZONE_VPN, why, sizeof(why)) == IVR_ALLOW, why);
    ok("an out-of-range zone is denied, not accepted",
       vlan_check_zones(&v, ZONE_MAX, ZONE_LAN, why, sizeof(why)) == IVR_DENY, why);
    ok("the decision is counted",
       v.inter_vlan_allowed > 0 && v.inter_vlan_denied > 0, NULL);

    vlan_shutdown(&v);
}

/* ═══════════════════ generated files ═══════════════════ */

static void test_generation(void) {
    puts("\n-- generated configuration --");

    vpn_ctx_t v;
    vpn_init(&v);

    wg_iface_t w;
    make_iface(&w, "wg0", 51820, "10.99.0.1", ZONE_VPN);
    snprintf(w.description, VLAN_DESC_LEN, "Main tunnel");
    vpn_add_wg(&v, &w);

    wg_iface_t w2;
    make_iface(&w2, "wg1", 51821, "10.98.0.1", ZONE_DMZ);
    vpn_add_wg(&v, &w2);

    wg_peer_t site;
    make_peer(&site, "branch", "wg0", "192.168.50.0/24", ZONE_LAN);
    snprintf(site.endpoint_host, VPN_HOST_LEN, "203.0.113.77");
    site.endpoint_port = 51820;
    site.keepalive = 25;
    char psk_priv[WG_KEY_B64_LEN];
    wg_generate_keypair(psk_priv, site.preshared_key);
    vpn_add_peer(&v, &site);

    wg_peer_t other;
    make_peer(&other, "on-wg1", "wg1", "10.98.0.2/32", ZONE_DMZ);
    vpn_add_peer(&v, &other);

    int n = vpn_generate_wg_config(&v, tmpdir);
    ok("both interfaces are written", n == 2, NULL);

    const char *c0 = tpath("wg0.conf");
    ok("wg0.conf exists", access(c0, R_OK) == 0, c0);
    ok("it is readable only by its owner", file_mode(c0) == 0600, NULL);
    ok("it carries the private key", file_has(c0, w.private_key), NULL);
    ok("it sets the listen port", file_has(c0, "ListenPort = 51820"), NULL);
    ok("it sets the tunnel address", file_has(c0, "Address = 10.99.0.1/24"), NULL);
    ok("it sets the MTU", file_has(c0, "MTU = 1420"), NULL);
    ok("it has a peer section", file_has(c0, "[Peer]"), NULL);
    ok("the peer's public key is there", file_has(c0, site.public_key), NULL);
    ok("the pre-shared key is there", file_has(c0, site.preshared_key), NULL);
    ok("allowed IPs are written", file_has(c0, "192.168.50.0/24"), NULL);
    ok("the endpoint is written",
       file_has(c0, "Endpoint = 203.0.113.77:51820"), NULL);
    ok("keepalive is written", file_has(c0, "PersistentKeepalive = 25"), NULL);
    ok("the peer's zone is recorded as a comment",
       file_has(c0, "zone: LAN"), NULL);

    /* Peers must land in their own interface's file, and no other. */
    ok("a peer on another interface is not in this file",
       !file_has(c0, other.public_key), NULL);
    ok("and it is in that interface's file",
       file_has(tpath("wg1.conf"), other.public_key), NULL);
    ok("the other interface's private key is not in this file",
       !file_has(c0, w2.private_key), NULL);

    /* ── IPsec ── */
    ipsec_tunnel_t t;
    memset(&t, 0, sizeof(t));
    snprintf(t.name, VPN_NAME_LEN, "dc-east");
    snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
    snprintf(t.local_id, VPN_HOST_LEN, "fw.example.com");
    snprintf(t.remote_id, VPN_HOST_LEN, "dc.example.com");
    snprintf(t.psk, VPN_SECRET_LEN, "a-very-long-preshared-secret");
    fx_parse_cidr("10.10.0.0/16",  &t.local_subnet,  &t.local_mask);
    fx_parse_cidr("172.30.0.0/16", &t.remote_subnet, &t.remote_mask);
    t.zone = ZONE_VPN;
    t.dpd = true;
    t.enabled = true;
    vpn_add_tunnel(&v, &t);

    const char *ic = tpath("swanctl.conf");
    const char *is = tpath("swanctl-secrets.conf");
    ok("the IPsec files are written",
       vpn_generate_ipsec_config(&v, ic, is) == 1, NULL);
    ok("the connection file is owner-only", file_mode(ic) == 0600, NULL);
    ok("the secrets file is owner-only",    file_mode(is) == 0600, NULL);
    ok("the tunnel is named in the connection file",
       file_has(ic, "dc-east"), NULL);
    ok("the remote address is there", file_has(ic, "198.51.100.10"), NULL);
    ok("the traffic selectors are there",
       file_has(ic, "local_ts  = 10.10.0.0/16") &&
       file_has(ic, "remote_ts = 172.30.0.0/16"), NULL);
    ok("IKEv2 is selected", file_has(ic, "version = 2"), NULL);
    ok("dead peer detection is configured", file_has(ic, "dpd_delay"), NULL);

    ok("the pre-shared key is in the secrets file", file_has(is, t.psk), NULL);
    ok("and NOT in the connection file", !file_has(ic, t.psk), NULL);

    vpn_shutdown(&v);
}

/* ═══════════════════ validation ═══════════════════ */

static void build_base(vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *b,
                       vpn_ctx_t *x) {
    vlan_init(v);
    netconf_init(n);
    vpn_init(x);
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->lock, NULL);
    b->enabled = true;
    b->port = 8080;

    vlan_config_t c;
    memset(&c, 0, sizeof(c));
    c.vlan_id = 10;
    snprintf(c.name, sizeof(c.name), "CORP");
    c.zone = ZONE_LAN;
    c.subnet = ip("10.10.10.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.10.1");
    c.lease_time = 86400;
    vlan_add(v, &c);

    wan_config_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.ifname, IFNAME_LEN, "eth0");
    w.mode = WAN_DHCP; w.mtu = 1500;
    n->wan[n->wan_count++] = w;

    wg_iface_t g;
    make_iface(&g, "wg0", 51820, "10.99.0.1", ZONE_VPN);
    vpn_add_wg(x, &g);

    wg_peer_t p;
    make_peer(&p, "branch", "wg0", "10.99.0.2/32", ZONE_LAN);
    vpn_add_peer(x, &p);
}

static void drop(vlan_ctx_t *v, netconf_ctx_t *n, vpn_ctx_t *x) {
    vlan_shutdown(v); netconf_shutdown(n); vpn_shutdown(x);
}

static void expect_bad(const char *what, vlan_ctx_t *v, netconf_ctx_t *n,
                       blockpage_ctx_t *b, vpn_ctx_t *x) {
    cfg_validate_t res;
    int rc = firex_validate(v, n, b, x, &res);
    ok(what, rc != 0, rc != 0 ? res.error : "ACCEPTED, should not have been");
}

static void test_validation(void) {
    puts("\n-- validation: rejects --");

    vlan_ctx_t v; netconf_ctx_t n; blockpage_ctx_t b; vpn_ctx_t x;
    cfg_validate_t res;

    build_base(&v, &n, &b, &x);
    ok("the baseline VPN configuration is valid",
       firex_validate(&v, &n, &b, &x, &res) == 0, res.error);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    x.wg[0].private_key[0] = '\0';
    expect_bad("a WireGuard interface with no private key", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    snprintf(x.wg[0].private_key, WG_KEY_B64_LEN, "not-a-real-key");
    expect_bad("a malformed private key", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    x.wg[0].listen_port = 0;
    expect_bad("listen port 0", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    x.wg[0].mtu = 100;
    expect_bad("an MTU below the floor", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    snprintf(x.wg[0].ifname, IFNAME_LEN, "wg0; rm -rf /");
    expect_bad("an interface name that is not shell-safe", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    /* A tunnel address inside a VLAN subnet makes routing ambiguous. */
    x.wg[0].address = ip("10.10.10.200");
    expect_bad("a tunnel address inside a VLAN subnet", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    snprintf(x.wg[0].ifname, IFNAME_LEN, "eth0");
    expect_bad("a WireGuard name that is already a WAN link", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    {
        wg_iface_t second;
        make_iface(&second, "wg1", 51820, "10.98.0.1", ZONE_VPN);
        vpn_add_wg(&x, &second);
    }
    expect_bad("two interfaces on the same UDP port", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    {
        port_forward_t f;
        memset(&f, 0, sizeof(f));
        snprintf(f.name, VLAN_NAME_LEN, "clash");
        f.protocol = 17;
        f.wan_port_start = f.wan_port_end = 51820;
        f.internal_ip = ip("10.10.10.5"); f.internal_port = 51820;
        netconf_add_forward(&n, &f);
    }
    expect_bad("a port forward that would swallow the handshake", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    snprintf(x.peers[0].public_key, WG_KEY_B64_LEN, "short");
    expect_bad("a peer with a malformed public key", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    snprintf(x.peers[0].preshared_key, WG_KEY_B64_LEN, "nope");
    expect_bad("a peer with a malformed pre-shared key", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    snprintf(x.peers[0].ifname, IFNAME_LEN, "wg7");
    expect_bad("a peer on an interface that does not exist", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    x.peers[0].allowed_count = 0;
    expect_bad("a peer with no allowed IPs", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    {
        wg_peer_t clash;
        make_peer(&clash, "other", "wg0", "10.99.0.2/32", ZONE_DMZ);
        vpn_add_peer(&x, &clash);
    }
    expect_bad("two peers claiming the same address", &v, &n, &b, &x);
    drop(&v, &n, &x);

    /* ── IPsec ── */
    build_base(&v, &n, &b, &x);
    {
        ipsec_tunnel_t t;
        memset(&t, 0, sizeof(t));
        snprintf(t.name, VPN_NAME_LEN, "weak");
        snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
        snprintf(t.psk, VPN_SECRET_LEN, "short");
        fx_parse_cidr("172.30.0.0/16", &t.remote_subnet, &t.remote_mask);
        t.enabled = true;
        vpn_add_tunnel(&x, &t);
    }
    expect_bad("an IPsec pre-shared key under 16 characters", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    {
        ipsec_tunnel_t t;
        memset(&t, 0, sizeof(t));
        snprintf(t.name, VPN_NAME_LEN, "nopsk");
        snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
        fx_parse_cidr("172.30.0.0/16", &t.remote_subnet, &t.remote_mask);
        t.enabled = true;
        vpn_add_tunnel(&x, &t);
    }
    expect_bad("an IPsec tunnel with no pre-shared key", &v, &n, &b, &x);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    {
        ipsec_tunnel_t t;
        memset(&t, 0, sizeof(t));
        snprintf(t.name, VPN_NAME_LEN, "overlap");
        snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
        snprintf(t.psk, VPN_SECRET_LEN, "a-sufficiently-long-secret");
        fx_parse_cidr("10.10.0.0/16", &t.local_subnet,  &t.local_mask);
        fx_parse_cidr("10.10.0.0/16", &t.remote_subnet, &t.remote_mask);
        t.enabled = true;
        vpn_add_tunnel(&x, &t);
    }
    expect_bad("an IPsec tunnel whose subnets overlap", &v, &n, &b, &x);
    drop(&v, &n, &x);

    puts("\n-- validation: accepts, with warnings --");

    build_base(&v, &n, &b, &x);
    {
        ipsec_tunnel_t t;
        memset(&t, 0, sizeof(t));
        snprintf(t.name, VPN_NAME_LEN, "legacy");
        snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
        snprintf(t.psk, VPN_SECRET_LEN, "a-sufficiently-long-secret");
        fx_parse_cidr("10.10.0.0/16",  &t.local_subnet,  &t.local_mask);
        fx_parse_cidr("172.30.0.0/16", &t.remote_subnet, &t.remote_mask);
        t.version = IKE_V1;
        t.enabled = true;
        vpn_add_tunnel(&x, &t);
    }
    int rc = firex_validate(&v, &n, &b, &x, &res);
    ok("IKEv1 is allowed but warned about",
       rc == 0 && res.warnings > 0, res.warning);
    drop(&v, &n, &x);

    build_base(&v, &n, &b, &x);
    x.peers[0].enabled = false;
    x.peers[0].public_key[0] = '\0';
    ok("a disabled peer is not validated",
       firex_validate(&v, &n, &b, &x, &res) == 0, res.error);
    drop(&v, &n, &x);

    ok("the shipped config, now with VPN, validates",
       firex_validate_file("config/firex.conf", &res) == 0, res.error);
    ok("it reports the WireGuard interface",  res.wg_ifaces == 1, NULL);
    ok("it reports both peers",               res.wg_peers == 2, NULL);
    ok("it reports the IPsec tunnel",         res.ipsec_tunnels == 1, NULL);
}

/* ═══════════════════ round-trip ═══════════════════ */

static void test_roundtrip(void) {
    puts("\n-- VPN round-trip --");

    vlan_ctx_t v;  netconf_ctx_t n;  blockpage_ctx_t b;  vpn_ctx_t x;
    vlan_init(&v); netconf_init(&n); vpn_init(&x);
    memset(&b, 0, sizeof(b));
    pthread_mutex_init(&b.lock, NULL);
    b.enabled = true; b.port = 8080;

    wg_iface_t w;
    make_iface(&w, "wg0", 51820, "10.99.0.1", ZONE_VPN);
    w.dns = ip("10.10.10.1");
    snprintf(w.description, VLAN_DESC_LEN, "Main tunnel");
    vpn_add_wg(&x, &w);

    wg_peer_t p;
    make_peer(&p, "branch", "wg0", "192.168.50.0/24", ZONE_LAN);
    fx_parse_cidr("10.99.0.2/32", &p.allowed[1].ip, &p.allowed[1].mask);
    p.allowed_count = 2;
    snprintf(p.endpoint_host, VPN_HOST_LEN, "203.0.113.77");
    p.endpoint_port = 51820;
    p.keepalive = 25;
    char throwaway[WG_KEY_B64_LEN];
    wg_generate_keypair(throwaway, p.preshared_key);
    snprintf(p.description, VLAN_DESC_LEN, "London branch");
    vpn_add_peer(&x, &p);

    ipsec_tunnel_t t;
    memset(&t, 0, sizeof(t));
    snprintf(t.name, VPN_NAME_LEN, "dc-east");
    snprintf(t.remote_host, VPN_HOST_LEN, "198.51.100.10");
    snprintf(t.local_id, VPN_HOST_LEN, "fw.example.com");
    snprintf(t.remote_id, VPN_HOST_LEN, "dc.example.com");
    snprintf(t.psk, VPN_SECRET_LEN, "a-very-long-preshared-secret");
    snprintf(t.esp_proposal, VPN_PROPOSAL_LEN, "aes256gcm16-modp2048");
    fx_parse_cidr("10.10.0.0/16",  &t.local_subnet,  &t.local_mask);
    fx_parse_cidr("172.30.0.0/16", &t.remote_subnet, &t.remote_mask);
    t.zone = ZONE_DMZ;
    t.dpd = true; t.dpd_delay = 45;
    t.ike_lifetime = 7200; t.esp_lifetime = 1800;
    t.enabled = true;
    vpn_add_tunnel(&x, &t);

    const char *path = tpath("rt.conf");
    ok("save succeeds",
       firex_save_enterprise_config_ex(path, &v, &n, &b, NULL, &x, NULL) == 0,
       NULL);
    ok("the saved config is owner-only", file_mode(path) == 0600, NULL);

    vlan_ctx_t v2;  netconf_ctx_t n2;  blockpage_ctx_t b2;  vpn_ctx_t x2;
    vlan_init(&v2); netconf_init(&n2); vpn_init(&x2);
    memset(&b2, 0, sizeof(b2));
    pthread_mutex_init(&b2.lock, NULL);

    ok("it loads back",
       firex_load_enterprise_config_ex(path, &v2, &n2, &b2, NULL, &x2) == 0, NULL);

    ok("the interface count survives", x2.wg_count == 1, NULL);
    ok("the peer count survives",      x2.peer_count == 1, NULL);
    ok("the tunnel count survives",    x2.tunnel_count == 1, NULL);

    wg_iface_t *w2 = vpn_find_wg(&x2, "wg0");
    ok("the private key round-trips",
       w2 && !strcmp(w2->private_key, w.private_key), NULL);
    /* vpn_add_wg() derives into the stored copy, not the local one, so
     * compare against the key derived from the private half. */
    char expect_pub[WG_KEY_B64_LEN];
    wg_public_from_private(w.private_key, expect_pub);
    ok("the public key is re-derived on load",
       w2 && !strcmp(w2->public_key, expect_pub), NULL);
    ok("port, address and MTU round-trip",
       w2 && w2->listen_port == 51820 && w2->address == ip("10.99.0.1") &&
       w2->mtu == 1420, NULL);
    ok("the interface zone round-trips", w2 && w2->zone == ZONE_VPN, NULL);
    ok("the pushed DNS round-trips", w2 && w2->dns == ip("10.10.10.1"), NULL);

    wg_peer_t *p2 = vpn_find_peer(&x2, "branch");
    ok("the peer's public key round-trips",
       p2 && !strcmp(p2->public_key, p.public_key), NULL);
    ok("its pre-shared key round-trips",
       p2 && !strcmp(p2->preshared_key, p.preshared_key), NULL);
    ok("both allowed ranges round-trip",
       p2 && p2->allowed_count == 2 &&
       p2->allowed[0].ip == ip("192.168.50.0") &&
       p2->allowed[1].ip == ip("10.99.0.2"), NULL);
    ok("the endpoint and port round-trip",
       p2 && !strcmp(p2->endpoint_host, "203.0.113.77") &&
       p2->endpoint_port == 51820, NULL);
    ok("keepalive round-trips", p2 && p2->keepalive == 25, NULL);
    ok("the peer's zone round-trips, distinct from the interface's",
       p2 && p2->zone == ZONE_LAN, NULL);

    ok("the tunnel's subnets round-trip",
       x2.tunnel_count == 1 &&
       x2.tunnels[0].local_subnet  == ip("10.10.0.0") &&
       x2.tunnels[0].remote_subnet == ip("172.30.0.0"), NULL);
    ok("its pre-shared key round-trips",
       x2.tunnel_count == 1 && !strcmp(x2.tunnels[0].psk, t.psk), NULL);
    ok("its proposals round-trip",
       x2.tunnel_count == 1 &&
       !strcmp(x2.tunnels[0].esp_proposal, "aes256gcm16-modp2048"), NULL);
    ok("its lifetimes and DPD round-trip",
       x2.tunnel_count == 1 && x2.tunnels[0].ike_lifetime == 7200 &&
       x2.tunnels[0].esp_lifetime == 1800 && x2.tunnels[0].dpd_delay == 45, NULL);
    ok("its zone round-trips", x2.tunnel_count == 1 &&
       x2.tunnels[0].zone == ZONE_DMZ, NULL);

    /* Still a fixed point with the VPN sections present. */
    const char *path2 = tpath("rt2.conf");
    firex_save_enterprise_config_ex(path2, &v2, &n2, &b2, NULL, &x2, NULL);
    FILE *f1 = fopen(path, "r"), *f2 = fopen(path2, "r");
    int same = f1 && f2;
    if (same) {
        int c1, c2;
        do { c1 = fgetc(f1); c2 = fgetc(f2); if (c1 != c2) same = 0; }
        while (same && c1 != EOF && c2 != EOF);
    }
    if (f1) fclose(f1);
    if (f2) fclose(f2);
    ok("a second save is byte-identical", same, NULL);

    vlan_shutdown(&v);  netconf_shutdown(&n);  vpn_shutdown(&x);
    vlan_shutdown(&v2); netconf_shutdown(&n2); vpn_shutdown(&x2);
}

int main(void) {
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/firex-p3-XXXXXX");
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }

    test_keys();
    test_tables();
    test_zone_mapping();
    test_zone_policy();
    test_generation();
    test_validation();
    test_roundtrip();

    printf("\n%d passed, %d failed\n", pass, fail);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
    if (system(cmd) != 0) fprintf(stderr, "note: could not clean %s\n", tmpdir);

    return fail ? 1 : 0;
}
