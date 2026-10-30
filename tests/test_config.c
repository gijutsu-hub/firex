/*
 * Config spine tests: serialiser round-trip, semantic validation, the
 * versioned revision store, and console authentication.
 * No root, no network, no listening socket.
 *   make test-config
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
#include "configstore.h"
#include "reload.h"
#include <crypt.h>
#include "auth.h"
#include "netutil.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-56s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-56s %s\n", what, detail ? detail : ""); fail++; }
}

static uint32_t ip(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    return a.s_addr;
}

static char tmpdir[256];

static const char *tpath(const char *name) {
    static char buf[512];
    snprintf(buf, sizeof(buf), "%s/%s", tmpdir, name);
    return buf;
}

/* ─────────────────────────────────────────────────────────────────────
 * A small but complete configuration, built in memory.
 * ───────────────────────────────────────────────────────────────────── */
static void build_baseline(vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *b) {
    vlan_init(v);
    netconf_init(n);
    memset(b, 0, sizeof(*b));
    pthread_mutex_init(&b->lock, NULL);
    b->enabled = true;
    b->port    = 8080;
    snprintf(b->org_name, sizeof(b->org_name), "Test Org");
    snprintf(b->admin_contact, sizeof(b->admin_contact), "soc@example.com");
    snprintf(n->domain, sizeof(n->domain), "test.local");

    vlan_config_t c;
    memset(&c, 0, sizeof(c));
    c.vlan_id = 10;
    snprintf(c.name, sizeof(c.name), "CORP");
    snprintf(c.description, sizeof(c.description), "Corporate segment");
    c.zone = ZONE_LAN;
    c.subnet = ip("10.10.10.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.10.1");
    c.dhcp_enabled = true;
    c.dhcp_start = ip("10.10.10.100"); c.dhcp_end = ip("10.10.10.200");
    c.dns_primary = ip("1.1.1.1");
    c.lease_time = 86400;
    c.inter_vlan_routing = true; c.internet_access = true;
    c.dpi_enabled = true; c.show_block_page = true;
    c.priority = 3;
    vlan_add(v, &c);

    memset(&c, 0, sizeof(c));
    c.vlan_id = 30;
    snprintf(c.name, sizeof(c.name), "GUEST");
    c.zone = ZONE_GUEST;
    c.subnet = ip("10.10.30.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.30.1");
    c.internet_access = true; c.client_isolation = true;
    c.lease_time = 3600;
    c.priority = 1;
    vlan_add(v, &c);

    port_config_t p;
    memset(&p, 0, sizeof(p));
    snprintf(p.ifname, sizeof(p.ifname), "eth1");
    snprintf(p.label, sizeof(p.label), "TRUNK-CORE");
    p.mode = PORT_MODE_TRUNK; p.zone = ZONE_LAN; p.pvid = 1;
    p.allowed_vlans[0] = 10; p.allowed_vlans[1] = 30; p.allowed_count = 2;
    p.enabled = true;
    port_configure(v, &p);

    wan_config_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.ifname, sizeof(w.ifname), "eth0");
    w.mode = WAN_DHCP; w.mtu = 1500; w.nat_enabled = true;
    w.block_bogons = true;
    n->wan[n->wan_count++] = w;

    vlan_set_zone_policy(v, ZONE_GUEST, ZONE_LAN, IVR_DENY);
    vlan_set_zone_policy(v, ZONE_LAN, ZONE_WAN, IVR_ALLOW);
}

static void teardown(vlan_ctx_t *v, netconf_ctx_t *n) {
    vlan_shutdown(v);
    netconf_shutdown(n);
}

/* ─────────────────────────────────────────────────────────────────────
 * 1. Serialiser round-trip
 * ───────────────────────────────────────────────────────────────────── */
static void test_roundtrip(void) {
    puts("\n-- serialiser round-trip --");

    vlan_ctx_t v, v2; netconf_ctx_t n, n2; blockpage_ctx_t b, b2;
    build_baseline(&v, &n, &b);

    /* An ACL carrying host-level match, which only survives via the
     * src=/dst= extension in the rule line. */
    ivr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.src_vlan = 30; r.dst_vlan = 10;
    r.protocol = 6; r.dst_port_start = 443; r.dst_port_end = 443;
    r.action = IVR_ALLOW; r.priority = 50;
    r.src_ip = ip("10.10.30.0"); r.src_mask = ip("255.255.255.0");
    r.dst_ip = ip("10.10.10.5"); r.dst_mask = ip("255.255.255.255");
    snprintf(r.description, sizeof(r.description), "guest to intranet");
    ivr_add_rule(&v, &r);

    /* A port range, to exercise the N-M form. */
    memset(&r, 0, sizeof(r));
    r.src_vlan = 10; r.dst_vlan = 0;
    r.protocol = 17; r.dst_port_start = 5060; r.dst_port_end = 5070;
    r.action = IVR_LOG_DENY; r.priority = 60;
    snprintf(r.description, sizeof(r.description), "sip range");
    ivr_add_rule(&v, &r);

    port_forward_t f;
    memset(&f, 0, sizeof(f));
    snprintf(f.name, sizeof(f.name), "web");
    f.protocol = 6; f.wan_port_start = f.wan_port_end = 443;
    f.internal_ip = ip("10.10.10.50"); f.internal_port = 8443;
    f.dst_vlan = 10;
    f.source_restrict = ip("203.0.113.0"); f.source_mask = ip("255.255.255.0");
    f.log_hits = true;
    netconf_add_forward(&n, &f);

    const char *path = tpath("rt.conf");
    ok("save succeeds",
       firex_save_enterprise_config(path, &v, &n, &b, NULL) == 0, path);

    vlan_init(&v2); netconf_init(&n2);
    memset(&b2, 0, sizeof(b2));
    pthread_mutex_init(&b2.lock, NULL);
    ok("saved file loads back",
       firex_load_enterprise_config(path, &v2, &n2, &b2) == 0, NULL);

    ok("VLAN count preserved", v2.vlan_count == v.vlan_count, NULL);
    ok("port count preserved", v2.port_count == v.port_count, NULL);
    ok("ACL count preserved",  v2.ivr_count  == v.ivr_count,  NULL);
    ok("WAN count preserved",  n2.wan_count  == n.wan_count,  NULL);
    ok("forward count preserved",
       n2.forward_count == n.forward_count, NULL);

    vlan_config_t *a = vlan_get(&v, 10), *c = vlan_get(&v2, 10);
    int same = a && c &&
        !strcmp(a->name, c->name) &&
        a->zone == c->zone && a->subnet == c->subnet &&
        a->netmask == c->netmask && a->gateway == c->gateway &&
        a->dhcp_enabled == c->dhcp_enabled &&
        a->dhcp_start == c->dhcp_start && a->dhcp_end == c->dhcp_end &&
        a->dns_primary == c->dns_primary &&
        a->lease_time == c->lease_time &&
        a->inter_vlan_routing == c->inter_vlan_routing &&
        a->internet_access == c->internet_access &&
        a->client_isolation == c->client_isolation &&
        a->dpi_enabled == c->dpi_enabled &&
        a->priority == c->priority;
    ok("VLAN 10 survives field for field", same, NULL);

    vlan_config_t *g1 = vlan_get(&v, 30), *g2 = vlan_get(&v2, 30);
    ok("VLAN 30 isolation + lease preserved",
       g1 && g2 && g1->client_isolation == g2->client_isolation &&
       g1->lease_time == g2->lease_time, NULL);

    ok("VLAN description preserved",
       a && c && !strcmp(a->description, c->description), c ? c->description : "");

    port_config_t *p1 = port_get(&v, "eth1"), *p2 = port_get(&v2, "eth1");
    ok("trunk port and allowed VLANs preserved",
       p1 && p2 && p1->mode == p2->mode && p1->allowed_count == p2->allowed_count &&
       p2->allowed_count == 2 &&
       port_vlan_permitted(p2, 10) && port_vlan_permitted(p2, 30), NULL);

    /* Find the ACL that carries host match, wherever priority sorting put it. */
    ivr_rule_t *host_rule = NULL, *range_rule = NULL;
    for (int i = 0; i < v2.ivr_count; i++) {
        if (v2.ivr[i].dst_port_start == 443) host_rule  = &v2.ivr[i];
        if (v2.ivr[i].dst_port_start == 5060) range_rule = &v2.ivr[i];
    }
    ok("ACL src= host match round-trips",
       host_rule && host_rule->src_ip == ip("10.10.30.0") &&
       host_rule->src_mask == ip("255.255.255.0"), NULL);
    ok("ACL dst= host match round-trips",
       host_rule && host_rule->dst_ip == ip("10.10.10.5") &&
       host_rule->dst_mask == ip("255.255.255.255"), NULL);
    ok("ACL port range round-trips",
       range_rule && range_rule->dst_port_start == 5060 &&
       range_rule->dst_port_end == 5070, NULL);
    ok("ACL action and protocol round-trip",
       range_rule && range_rule->action == IVR_LOG_DENY &&
       range_rule->protocol == 17, NULL);

    ok("zone matrix preserved",
       v2.zone_matrix[ZONE_GUEST][ZONE_LAN] == IVR_DENY &&
       v2.zone_matrix[ZONE_LAN][ZONE_WAN] == IVR_ALLOW, NULL);

    ok("port forward round-trips",
       n2.forward_count == 1 &&
       n2.forwards[0].internal_ip == ip("10.10.10.50") &&
       n2.forwards[0].internal_port == 8443 &&
       n2.forwards[0].wan_port_start == 443 &&
       n2.forwards[0].dst_vlan == 10, NULL);
    ok("forward source restriction round-trips",
       n2.forward_count == 1 &&
       n2.forwards[0].source_restrict == ip("203.0.113.0") &&
       n2.forwards[0].source_mask == ip("255.255.255.0"), NULL);

    ok("WAN settings round-trip",
       n2.wan_count == 1 && n2.wan[0].mode == WAN_DHCP &&
       n2.wan[0].mtu == 1500 && n2.wan[0].nat_enabled &&
       n2.wan[0].block_bogons && !strcmp(n2.wan[0].ifname, "eth0"), NULL);

    ok("blockpage settings round-trip",
       b2.enabled && b2.port == 8080 &&
       !strcmp(b2.org_name, "Test Org"), b2.org_name);
    ok("system domain round-trips", !strcmp(n2.domain, "test.local"), n2.domain);

    /* Saving the reloaded config must produce a byte-identical file: the
     * serialiser has to be a fixed point, or history diffs become noise. */
    const char *path2 = tpath("rt2.conf");
    firex_save_enterprise_config(path2, &v2, &n2, &b2, NULL);
    FILE *f1 = fopen(path, "r"), *f2 = fopen(path2, "r");
    int identical = f1 && f2;
    if (identical) {
        int ch1, ch2;
        do { ch1 = fgetc(f1); ch2 = fgetc(f2); if (ch1 != ch2) identical = 0; }
        while (identical && ch1 != EOF && ch2 != EOF);
    }
    if (f1) fclose(f1);
    if (f2) fclose(f2);
    ok("second save is byte-identical (fixed point)", identical, NULL);

    teardown(&v, &n);
    teardown(&v2, &n2);
}

/* Descriptions carrying characters the INI format uses structurally must not
 * be able to break the file. */
static void test_description_sanitising(void) {
    puts("\n-- hostile descriptions --");

    vlan_ctx_t v, v2; netconf_ctx_t n, n2; blockpage_ctx_t b, b2;
    build_baseline(&v, &n, &b);

    ivr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.src_vlan = 10; r.dst_vlan = 30; r.action = IVR_DENY; r.priority = 10;
    snprintf(r.description, sizeof(r.description),
             "evil \" # ; \n rule = 1 -> 2 tcp 22 ALLOW 1 \"pwn\"");
    ivr_add_rule(&v, &r);

    const char *path = tpath("hostile.conf");
    firex_save_enterprise_config(path, &v, &n, &b, NULL);

    vlan_init(&v2); netconf_init(&n2);
    memset(&b2, 0, sizeof(b2));
    pthread_mutex_init(&b2.lock, NULL);
    firex_load_enterprise_config(path, &v2, &n2, &b2);

    ok("quote/comment injection does not add rules",
       v2.ivr_count == v.ivr_count, NULL);
    ok("no smuggled ALLOW rule appeared",
       !(v2.ivr_count > 0 && v2.ivr[0].dst_port_start == 22 &&
         v2.ivr[0].action == IVR_ALLOW), NULL);
    ok("VLANs still intact after hostile description",
       v2.vlan_count == 2 && vlan_get(&v2, 10) && vlan_get(&v2, 30), NULL);

    teardown(&v, &n);
    teardown(&v2, &n2);
}

/* ─────────────────────────────────────────────────────────────────────
 * 2. Validation
 * ───────────────────────────────────────────────────────────────────── */
static void expect_invalid(const char *what, vlan_ctx_t *v, netconf_ctx_t *n,
                           blockpage_ctx_t *b) {
    cfg_validate_t res;
    int rc = firex_validate(v, n, b, NULL, &res);
    ok(what, rc != 0, rc != 0 ? res.error : "ACCEPTED, should not have been");
}

static void test_validation(void) {
    puts("\n-- validation: rejects --");

    vlan_ctx_t v; netconf_ctx_t n; blockpage_ctx_t b;
    cfg_validate_t res;

    build_baseline(&v, &n, &b);
    ok("baseline configuration is valid",
       firex_validate(&v, &n, &b, NULL, &res) == 0, res.error);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->gateway = ip("192.168.1.1");
    expect_invalid("gateway outside its own subnet", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    /* Move the whole VLAN onto VLAN 10's network, gateway included, so the
     * gateway check passes and overlap detection is what has to catch it. */
    vlan_get(&v, 30)->subnet  = ip("10.10.10.0");
    vlan_get(&v, 30)->gateway = ip("10.10.10.2");
    expect_invalid("two VLANs with overlapping subnets", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    /* A /16 that swallows another VLAN's /24: overlap is not only exact
     * equality, so the wider prefix has to be detected too. */
    vlan_get(&v, 30)->subnet  = ip("10.10.0.0");
    vlan_get(&v, 30)->netmask = ip("255.255.0.0");
    vlan_get(&v, 30)->gateway = ip("10.10.0.1");
    vlan_get(&v, 30)->dhcp_enabled = false;
    expect_invalid("a wider subnet containing another VLAN", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->dhcp_end = ip("10.10.99.200");
    expect_invalid("DHCP pool outside the VLAN subnet", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->dhcp_start = ip("10.10.10.1");
    expect_invalid("gateway sitting inside its own DHCP pool", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->dhcp_start = ip("10.10.10.200");
    vlan_get(&v, 10)->dhcp_end   = ip("10.10.10.100");
    expect_invalid("DHCP range running backwards", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->netmask = ip("255.0.255.0");
    expect_invalid("non-contiguous netmask", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->subnet = ip("10.10.10.7");
    expect_invalid("subnet with host bits set", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->priority = 9;
    expect_invalid("802.1p priority above 7", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->lease_time = 5;
    expect_invalid("DHCP lease below 60 seconds", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    vlan_get(&v, 10)->name[0] = '\0';
    expect_invalid("VLAN with no name", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    v.vlans[1].vlan_id = 10;                /* duplicate, bypassing vlan_add */
    expect_invalid("duplicate VLAN id", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    port_get(&v, "eth1")->allowed_vlans[0] = 999;
    expect_invalid("trunk allowing an undefined VLAN", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    port_get(&v, "eth1")->mode = PORT_MODE_ACCESS;
    port_get(&v, "eth1")->pvid = 777;
    expect_invalid("access port with an undefined PVID", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    snprintf(v.ports[v.port_count].ifname, IFNAME_LEN, "eth1");
    v.ports[v.port_count].enabled = true;
    v.port_count++;
    expect_invalid("the same interface configured twice", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    snprintf(port_get(&v, "eth1")->ifname, IFNAME_LEN, "eth0; rm -rf /");
    expect_invalid("interface name that is not shell-safe", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    n.wan[0].mode = WAN_STATIC;             /* no ip/netmask supplied */
    expect_invalid("static WAN with no address", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    n.wan[0].mode = WAN_STATIC;
    n.wan[0].ip = ip("203.0.113.5");
    n.wan[0].netmask = ip("255.255.255.0");
    n.wan[0].gateway = ip("198.51.100.1");
    expect_invalid("static WAN gateway off-subnet", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    n.wan[0].mtu = 100;
    expect_invalid("MTU below the legal floor", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    n.wan[0].mode = WAN_PPPOE;
    expect_invalid("PPPoE with no username", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    {
        port_forward_t f;
        memset(&f, 0, sizeof(f));
        snprintf(f.name, sizeof(f.name), "a");
        f.protocol = 6; f.wan_port_start = 443;
        f.internal_ip = ip("10.10.10.5"); f.internal_port = 443;
        netconf_add_forward(&n, &f);
        snprintf(f.name, sizeof(f.name), "b");
        f.internal_ip = ip("10.10.10.6");
        netconf_add_forward(&n, &f);
    }
    expect_invalid("two forwards claiming the same WAN port", &v, &n, &b);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    {
        port_forward_t f;
        memset(&f, 0, sizeof(f));
        snprintf(f.name, sizeof(f.name), "ghost");
        f.protocol = 6; f.wan_port_start = 8443;
        f.internal_ip = ip("10.10.99.5"); f.internal_port = 443;
        f.dst_vlan = 999;
        netconf_add_forward(&n, &f);
    }
    expect_invalid("forward into a VLAN that does not exist", &v, &n, &b);
    teardown(&v, &n);

    puts("\n-- validation: accepts --");

    build_baseline(&v, &n, &b);
    {
        vlan_config_t c;
        memset(&c, 0, sizeof(c));
        c.vlan_id = 40;
        snprintf(c.name, sizeof(c.name), "L2ONLY");
        c.zone = ZONE_IOT;
        c.lease_time = 86400;
        vlan_add(&v, &c);
    }
    ok("VLAN with no L3 config (pure L2 segment)",
       firex_validate(&v, &n, &b, NULL, &res) == 0, res.error);
    teardown(&v, &n);

    build_baseline(&v, &n, &b);
    n.wan[0].mode = WAN_STATIC;
    n.wan[0].ip = ip("203.0.113.5");
    n.wan[0].netmask = ip("255.255.255.0");
    n.wan[0].gateway = ip("203.0.113.1");
    ok("static WAN with a gateway on-subnet",
       firex_validate(&v, &n, &b, NULL, &res) == 0, res.error);
    teardown(&v, &n);

    ok("shipped config/firex.conf validates",
       firex_validate_file("config/firex.conf", &res) == 0, res.error);
    ok("shipped config/firex-qemu.conf validates",
       firex_validate_file("config/firex-qemu.conf", &res) == 0, res.error);

    ok("a file that does not exist is rejected, not crashed on",
       firex_validate_file(tpath("nope.conf"), &res) != 0, NULL);

    /* Warnings must not read as failures. */
    build_baseline(&v, &n, &b);
    port_get(&v, "eth1")->allowed_count = 0;
    int rc = firex_validate(&v, &n, &b, NULL, &res);
    ok("empty trunk warns but stays valid",
       rc == 0 && res.warnings > 0, res.warning);
    teardown(&v, &n);
}

/* ─────────────────────────────────────────────────────────────────────
 * 3. Revision store
 * ───────────────────────────────────────────────────────────────────── */
static void test_store(void) {
    puts("\n-- revision store --");

    vlan_ctx_t v; netconf_ctx_t n; blockpage_ctx_t b;
    build_baseline(&v, &n, &b);

    cfgstore_t st;
    const char *active = tpath("firex.conf");
    ok("store initialises", cfgstore_init(&st, active) == 0, st.dir);
    ok("store starts empty", cfgstore_latest(&st) == 0, NULL);

    int r1 = cfgstore_commit(&st, &v, &n, &b, NULL, NULL, "alice", "first");
    ok("first commit is revision 1", r1 == 1, NULL);

    vlan_get(&v, 10)->internet_access = false;
    int r2 = cfgstore_commit(&st, &v, &n, &b, NULL, NULL, "bob", "cut corp internet");
    ok("second commit is revision 2", r2 == 2, NULL);
    ok("latest tracks the highest revision", cfgstore_latest(&st) == 2, NULL);

    ok("active config exists after commit", access(active, R_OK) == 0, NULL);

    cfg_revision_t revs[8];
    int count = cfgstore_list(&st, revs, 8);
    ok("list returns both revisions", count == 2, NULL);
    ok("list is newest first", count == 2 && revs[0].revision == 2, NULL);
    ok("author recorded", count == 2 && !strcmp(revs[0].author, "bob"),
       count ? revs[0].author : "");
    ok("note recorded",
       count == 2 && !strcmp(revs[0].note, "cut corp internet"),
       count ? revs[0].note : "");
    ok("timestamp recorded", count == 2 && revs[0].when > 0, NULL);

    char p[CFG_PATH_LEN];
    ok("path_for finds an existing revision",
       cfgstore_path_for(&st, 1, p, sizeof(p)) == 0, p);
    ok("path_for rejects a missing revision",
       cfgstore_path_for(&st, 99, p, sizeof(p)) != 0, NULL);

    /* Revision 1 still has internet enabled; rolling back must bring it back. */
    ok("rollback to revision 1 succeeds", cfgstore_rollback(&st, 1) == 0, NULL);

    vlan_ctx_t rv; netconf_ctx_t rn; blockpage_ctx_t rb;
    vlan_init(&rv); netconf_init(&rn);
    memset(&rb, 0, sizeof(rb));
    pthread_mutex_init(&rb.lock, NULL);
    firex_load_enterprise_config(active, &rv, &rn, &rb);
    ok("rolled-back config has the old value",
       vlan_get(&rv, 10) && vlan_get(&rv, 10)->internet_access, NULL);
    ok("rollback leaves history intact", cfgstore_latest(&st) == 2, NULL);
    teardown(&rv, &rn);

    cfg_meta_t meta;
    ok("revision header parses back",
       cfgstore_path_for(&st, 2, p, sizeof(p)) == 0 &&
       firex_read_config_meta(p, &meta) == 0 &&
       meta.revision == 2 && !strcmp(meta.author, "bob"), NULL);

    cfgstore_shutdown(&st);
    teardown(&v, &n);
}

/* ─────────────────────────────────────────────────────────────────────
 * 4. Authentication
 * ───────────────────────────────────────────────────────────────────── */
static void test_auth(void) {
    puts("\n-- console authentication --");

    auth_ctx_t a;
    const char *users = tpath("users");

    ok("bootstrap creates a user database",
       auth_init(&a, users) == 0 && a.user_count == 1, NULL);

    struct stat stt;
    ok("user file is not world-readable",
       stat(users, &stt) == 0 && (stt.st_mode & 0077) == 0, NULL);

    /* The generated password is never returned, so set a known one. */
    ok("password can be changed",
       auth_set_password(&a, "admin", "correct-horse-battery") == 0, NULL);

    fx_session_t s1, s2;
    ok("correct credentials sign in",
       auth_login(&a, "admin", "correct-horse-battery", 0x0100007f, &s1) == 0,
       s1.user);
    ok("session carries the admin role", s1.role == ROLE_ADMIN, NULL);
    ok("session token is full length", strlen(s1.token) == AUTH_TOKEN_LEN - 1, NULL);
    ok("CSRF token is full length", strlen(s1.csrf) == AUTH_CSRF_LEN - 1, NULL);

    fx_session_t look;
    ok("session resolves by token",
       auth_session(&a, s1.token, &look) && !strcmp(look.user, "admin"), NULL);
    ok("an unknown token does not resolve",
       !auth_session(&a, "deadbeef", &look), NULL);
    ok("an empty token does not resolve", !auth_session(&a, "", &look), NULL);

    ok("matching CSRF token accepted", auth_csrf_ok(&s1, s1.csrf), NULL);
    ok("wrong CSRF token rejected",
       !auth_csrf_ok(&s1, "00000000000000000000000000000000"), NULL);
    ok("empty CSRF token rejected", !auth_csrf_ok(&s1, ""), NULL);

    ok("a second login gets a different token",
       auth_login(&a, "admin", "correct-horse-battery", 0x0100007f, &s2) == 0 &&
       strcmp(s1.token, s2.token) != 0, NULL);

    auth_logout(&a, s1.token);
    ok("logout invalidates that session",
       !auth_session(&a, s1.token, &look), NULL);
    ok("the other session survives logout",
       auth_session(&a, s2.token, &look), NULL);

    ok("wrong password is refused",
       auth_login(&a, "admin", "wrong", 0x0200007f, &s1) == -1, NULL);
    ok("unknown user is refused",
       auth_login(&a, "nobody", "whatever", 0x0300007f, &s1) == -1, NULL);

    /* Throttle: distinct source so the earlier successes do not interfere. */
    uint32_t attacker = 0x0400007f;
    int refused = 0, throttled = 0;
    for (int i = 0; i < AUTH_FAIL_THRESHOLD + 2; i++) {
        int rc = auth_login(&a, "admin", "nope", attacker, &s1);
        if (rc == -1) refused++;
        if (rc == -2) throttled++;
    }
    ok("repeated failures eventually throttle the source",
       throttled > 0, NULL);
    ok("throttling did not lock out a different source",
       auth_login(&a, "admin", "correct-horse-battery", 0x0500007f, &s1) == 0,
       NULL);

    ok("viewer accounts can be created",
       auth_add_user(&a, "watcher", "observation-only-pw", ROLE_VIEWER) == 0, NULL);
    ok("duplicate username is refused",
       auth_add_user(&a, "watcher", "another-password", ROLE_VIEWER) != 0, NULL);

    /* Sign in first: the detail argument and the condition have no ordering
     * guarantee between them, so reading vs.role inline would print a stale
     * value even on a pass. */
    fx_session_t vs;
    int vrc = auth_login(&a, "watcher", "observation-only-pw", 0x0600007f, &vs);
    ok("viewer signs in with the viewer role",
       vrc == 0 && vs.role == ROLE_VIEWER, auth_role_name(vs.role));

    /* Changing a password must cut every session that user holds. */
    auth_set_password(&a, "watcher", "a-brand-new-password");
    ok("password change invalidates existing sessions",
       !auth_session(&a, vs.token, &look), NULL);
    ok("the old password no longer works",
       auth_login(&a, "watcher", "observation-only-pw", 0x0700007f, &vs) == -1,
       NULL);
    ok("the new password works",
       auth_login(&a, "watcher", "a-brand-new-password", 0x0800007f, &vs) == 0,
       NULL);

    auth_shutdown(&a);

    /* Reloading from disk must find both accounts with their roles. */
    auth_ctx_t a2;
    ok("users reload from disk",
       auth_init(&a2, users) == 0 && a2.user_count == 2, NULL);
    ok("roles survive a reload",
       auth_login(&a2, "watcher", "a-brand-new-password", 0x0900007f, &vs) == 0 &&
       vs.role == ROLE_VIEWER, NULL);
    ok("hashes are not stored in the clear",
       !strstr(a2.users[0].hash, "correct-horse-battery") &&
       !strncmp(a2.users[0].hash, "$6$", 3), NULL);
    auth_shutdown(&a2);
}

/* ─────────────────────────────────────────────────────────────────────
 * Shipped defaults: the appliance goes out with root/root and
 * admin/admin, and the console has to be able to say so. These tests
 * stand in for a reviewer asking "how do you know the banner is
 * honest?" -- the answer has to be a real crypt() comparison, not a
 * flag somebody remembered to clear.
 * ───────────────────────────────────────────────────────────────── */

static void test_default_credentials(void) {
    printf("\n== shipped default credentials ==\n");

    const char *users = tpath("users-default");
    unlink(users);

    auth_ctx_t a;
    memset(&a, 0, sizeof(a));
    ok("an empty database loads without bootstrapping anything",
       auth_load_quiet(&a, users) == 0 && a.user_count == 0, NULL);

    /* Exactly what tools/build-image.sh seeds. */
    ok("admin seeds with its own name",
       auth_add_user(&a, "admin", "admin", ROLE_ADMIN) == 0, NULL);
    ok("root seeds with its own name",
       auth_add_user(&a, "root", "root", ROLE_ADMIN) == 0, NULL);

    ok("admin/admin is recognised as the default",
       auth_password_is(&a, "admin", "admin"), NULL);
    ok("root/root is recognised as the default",
       auth_password_is(&a, "root", "root"), NULL);
    ok("a wrong password is not the default",
       !auth_password_is(&a, "admin", "Admin"), NULL);
    ok("an account that does not exist is not at its default",
       !auth_password_is(&a, "nobody", "nobody"), NULL);

    auth_entry_t list[AUTH_MAX_USERS];
    int n = auth_list(&a, list, AUTH_MAX_USERS);
    ok("auth_list reports every account", n == 2, NULL);

    int flagged = 0;
    bool saw_admin = false, saw_root = false;
    for (int i = 0; i < n; i++) {
        if (list[i].is_default) flagged++;
        if (!strcmp(list[i].name, "admin")) saw_admin = true;
        if (!strcmp(list[i].name, "root"))  saw_root  = true;
        ok("auth_list hands out no hash",
           !strstr(list[i].name, "$6$"), list[i].name);
    }
    ok("both shipped accounts are flagged", flagged == 2, NULL);
    ok("both accounts are named", saw_admin && saw_root, NULL);
    ok("roles come back with the names",
       list[0].role == ROLE_ADMIN && list[1].role == ROLE_ADMIN, NULL);

    /* The whole point: changing a password has to clear the flag, and
     * the flag has to come from the stored hash rather than from any
     * bookkeeping that a reload could lose. */
    ok("a real change is accepted",
       auth_set_password(&a, "admin", "something-of-my-own") == 0, NULL);
    ok("the changed account is no longer at its default",
       !auth_password_is(&a, "admin", "admin"), NULL);

    n = auth_list(&a, list, AUTH_MAX_USERS);
    flagged = 0;
    for (int i = 0; i < n; i++) if (list[i].is_default) flagged++;
    ok("the count drops to the one account left", flagged == 1, NULL);
    auth_shutdown(&a);

    auth_ctx_t b;
    memset(&b, 0, sizeof(b));
    ok("the database reloads from disk", auth_load_quiet(&b, users) == 0, NULL);
    n = auth_list(&b, list, AUTH_MAX_USERS);
    flagged = 0;
    for (int i = 0; i < n; i++) if (list[i].is_default) flagged++;
    ok("the verdict survives a reload -- it is read from the hash",
       n == 2 && flagged == 1, NULL);

    /* A short list must not be overrun. */
    auth_entry_t one[1];
    ok("auth_list respects the caller's capacity",
       auth_list(&b, one, 1) == 1, NULL);
    ok("auth_list tolerates a zero capacity",
       auth_list(&b, one, 0) == 0, NULL);
    auth_shutdown(&b);
}

/* ─────────────────────────────────────────────────────────────────────
 * The Linux half of the same pair. /etc/shadow is not writable here, so
 * these check the parsing and the refusals rather than a real change.
 * ───────────────────────────────────────────────────────────────── */

static void test_system_accounts(void) {
    printf("\n== the Linux account behind the console ==\n");

    /*
     * A fixture rather than the real /etc/shadow: the hashes below are
     * this machine's crypt() of the user's own name, which is exactly
     * what the build seeds, so a passing test here means the console's
     * "still default" verdict is reading the file correctly.
     */
    /*
     * Copied, not aliased: tpath() hands back one static buffer, so the
     * tpath("no-such-shadow") call further down would otherwise rewrite
     * the path this variable points at and every check after it would
     * silently be asking about a file that does not exist.
     */
    char shadow[512];
    snprintf(shadow, sizeof(shadow), "%s", tpath("shadow"));

    char missing[512];
    snprintf(missing, sizeof(missing), "%s", tpath("no-such-shadow"));

    struct crypt_data cd;
    char rootline[512], adminline[512];

    memset(&cd, 0, sizeof(cd));
    snprintf(rootline, sizeof(rootline), "%s",
             crypt_r("root", "$6$fixedsalt0123456$", &cd));
    memset(&cd, 0, sizeof(cd));
    snprintf(adminline, sizeof(adminline), "%s",
             crypt_r("not-the-default", "$6$fixedsalt0123456$", &cd));

    FILE *sf = fopen(shadow, "w");
    ok("a shadow fixture can be written", sf != NULL, NULL);
    if (sf) {
        fprintf(sf, "daemon:*:19000:0:99999:7:::\n");
        fprintf(sf, "root:%s:19000:0:99999:7:::\n", rootline);
        fprintf(sf, "admin:%s:19000:0:99999:7:::\n", adminline);
        fprintf(sf, "locked:!:19000:0:99999:7:::\n");
        fprintf(sf, "nopass::19000:0:99999:7:::\n");
        fclose(sf);
    }

    ok("root with its own name as the password reads as default",
       auth_system_state_in(shadow, "root") == 1, NULL);
    ok("an account with a password of its own reads as set",
       auth_system_state_in(shadow, "admin") == 0, NULL);
    ok("a '!' hash reads as locked",
       auth_system_state_in(shadow, "locked") == 2, NULL);
    ok("an empty hash reads as locked, not as a match",
       auth_system_state_in(shadow, "nopass") == 2, NULL);
    ok("'*' reads as locked",
       auth_system_state_in(shadow, "daemon") == 2, NULL);
    ok("an account that is not in the file is absent",
       auth_system_state_in(shadow, "nobody") == -1, NULL);
    ok("a file that cannot be read is reported as unknown, not absent",
       auth_system_state_in(missing, "root") == -2, NULL);

    /* A prefix must not match: "roo" and "rootkit" are not "root". */
    ok("a shorter name does not match a longer record",
       auth_system_state_in(shadow, "roo") == -1, NULL);
    ok("a longer name does not match a shorter record",
       auth_system_state_in(shadow, "rootkit") == -1, NULL);
    ok("an empty name matches nothing",
       auth_system_state_in(shadow, "") == -1, NULL);

    int st = auth_system_state("root");
    ok("the real /etc/shadow gives a state the console can render",
       st == 0 || st == 1 || st == 2 || st == -1 || st == -2,
       st == -2 ? "unreadable as this user, reported as such" : "read");

    /* chpasswd input is "user:password" on one line, so a name or a
     * password carrying a separator could forge a second record. */
    ok("a colon in the user name is refused",
       auth_system_set_password("ro:ot", "whatever-long-enough") == -1, NULL);
    ok("a newline in the user name is refused",
       auth_system_set_password("root\nx", "whatever-long-enough") == -1, NULL);
    ok("an upper-case name is refused",
       auth_system_set_password("Root", "whatever-long-enough") == -1, NULL);
    ok("a newline in the password is refused",
       auth_system_set_password("root", "pass\nroot:other") == -1, NULL);
    ok("a carriage return in the password is refused",
       auth_system_set_password("root", "pass\rroot:other") == -1, NULL);
    ok("an empty password is refused",
       auth_system_set_password("root", "") == -1, NULL);
    ok("an empty user is refused",
       auth_system_set_password("", "whatever-long-enough") == -1, NULL);
}

int main(void) {
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/firex-test-XXXXXX");
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }

    test_roundtrip();
    test_description_sanitising();
    test_validation();
    test_store();
    test_auth();
    test_default_credentials();
    test_system_accounts();

    printf("\n%d passed, %d failed\n", pass, fail);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
    if (system(cmd) != 0) fprintf(stderr, "note: could not clean %s\n", tmpdir);

    return fail ? 1 : 0;
}
