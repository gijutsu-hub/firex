/*
 * Phase 2 tests: aliases, schedules, static routes, gateway monitoring and
 * multi-WAN failover selection.
 *
 * The ICMP probe is exercised against loopback; everything else is pure
 * logic. No root, no network reconfiguration.
 *   make test-phase2
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "inspect.h"
#include "enterprise.h"
#include "config_write.h"
#include "reload.h"
#include "policy.h"
#include "gwmon.h"
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

/* A specific local wall-clock moment, so schedule tests are deterministic
 * regardless of when they run. mday is chosen to land on the named weekday. */
static time_t at(int year, int mon, int mday, int hour, int min) {
    struct tm t;
    memset(&t, 0, sizeof(t));
    t.tm_year = year - 1900;
    t.tm_mon  = mon - 1;
    t.tm_mday = mday;
    t.tm_hour = hour;
    t.tm_min  = min;
    t.tm_isdst = -1;
    return mktime(&t);
}

static int weekday_of(time_t t) {
    struct tm tmv;
    localtime_r(&t, &tmv);
    return tmv.tm_wday;
}

/* ═══════════════════ aliases ═══════════════════ */

static void test_aliases(void) {
    puts("\n-- aliases --");

    policy_ctx_t p;
    policy_init(&p);

    alias_t a;
    memset(&a, 0, sizeof(a));
    snprintf(a.name, sizeof(a.name), "SERVERS");
    a.kind = ALIAS_NETWORK;
    ok("network entries parse",
       policy_parse_entries(&a, "10.10.20.0/24, 192.168.5.7, 172.16.0.0/12") == 3,
       NULL);
    ok("a bare address becomes a /32 host",
       a.nets[1].ip == ip("192.168.5.7") && a.nets[1].mask == ip("255.255.255.255"),
       NULL);
    ok("alias is accepted", policy_add_alias(&p, &a) == 0, NULL);
    ok("the same name twice is refused", policy_add_alias(&p, &a) != 0, NULL);

    alias_t ports;
    memset(&ports, 0, sizeof(ports));
    snprintf(ports.name, sizeof(ports.name), "WEB");
    ports.kind = ALIAS_PORT;
    ok("port entries parse, ranges included",
       policy_parse_entries(&ports, "80, 443, 8000-8100") == 3, NULL);
    ok("a range keeps both ends",
       ports.ports[2].start == 8000 && ports.ports[2].end == 8100, NULL);
    policy_add_alias(&p, &ports);

    /* malformed input */
    alias_t bad;
    memset(&bad, 0, sizeof(bad));
    snprintf(bad.name, sizeof(bad.name), "BAD");
    bad.kind = ALIAS_NETWORK;
    ok("a non-address entry is refused",
       policy_parse_entries(&bad, "10.0.0.0/8, notanaddress") < 0, NULL);
    ok("\"any\" is refused rather than read as match-everything",
       policy_parse_entries(&bad, "any") < 0, NULL);
    ok("\"*\" is refused too", policy_parse_entries(&bad, "*") < 0, NULL);

    bad.kind = ALIAS_PORT;
    ok("port 0 is refused",            policy_parse_entries(&bad, "0") < 0, NULL);
    ok("a port above 65535 is refused", policy_parse_entries(&bad, "70000") < 0, NULL);
    ok("a backwards range is refused",  policy_parse_entries(&bad, "900-100") < 0, NULL);
    ok("a non-numeric port is refused", policy_parse_entries(&bad, "http") < 0, NULL);

    /* matching */
    ok("an address inside the alias matches",
       policy_match_ip(&p, "SERVERS", ip("10.10.20.55")), NULL);
    ok("a host entry matches exactly",
       policy_match_ip(&p, "SERVERS", ip("192.168.5.7")), NULL);
    ok("a neighbouring host does not match",
       !policy_match_ip(&p, "SERVERS", ip("192.168.5.8")), NULL);
    ok("an address outside every entry does not match",
       !policy_match_ip(&p, "SERVERS", ip("8.8.8.8")), NULL);
    ok("the $ sigil is accepted on lookup",
       policy_match_ip(&p, "$SERVERS", ip("10.10.20.55")), NULL);

    ok("a port inside a range matches", policy_match_port(&p, "WEB", 8050), NULL);
    ok("a listed port matches",         policy_match_port(&p, "WEB", 443), NULL);
    ok("a port outside every entry does not match",
       !policy_match_port(&p, "WEB", 9999), NULL);

    ok("an unknown alias matches nothing, rather than everything",
       !policy_match_ip(&p, "NOSUCH", ip("10.10.20.55")), NULL);
    ok("a network alias used as a port alias matches nothing",
       !policy_match_port(&p, "SERVERS", 443), NULL);
    ok("a port alias used as an address alias matches nothing",
       !policy_match_ip(&p, "WEB", ip("10.10.20.55")), NULL);
    ok("a NULL table matches nothing",
       !policy_match_ip(NULL, "SERVERS", ip("10.10.20.55")), NULL);

    ok("hits are counted", policy_find_alias(&p, "SERVERS")->hits > 0, NULL);

    /* formatting round-trip */
    char buf[512];
    policy_entries_str(policy_find_alias(&p, "WEB"), buf, sizeof(buf));
    ok("port entries format back", !strcmp(buf, "80, 443, 8000-8100"), buf);

    alias_t again;
    memset(&again, 0, sizeof(again));
    again.kind = ALIAS_PORT;
    ok("formatted entries parse back identically",
       policy_parse_entries(&again, buf) == 3 &&
       again.ports[2].start == 8000 && again.ports[2].end == 8100, NULL);

    /* mutation */
    alias_t upd = *policy_find_alias(&p, "WEB");
    policy_parse_entries(&upd, "80, 443");
    ok("an alias can be updated in place",
       policy_update_alias(&p, "WEB", &upd) == 0 &&
       policy_find_alias(&p, "WEB")->count == 2, NULL);
    ok("the removed port stops matching", !policy_match_port(&p, "WEB", 8050), NULL);

    upd.kind = ALIAS_NETWORK;
    ok("an update cannot change the alias kind",
       policy_update_alias(&p, "WEB", &upd) != 0, NULL);

    ok("an alias can be removed",
       policy_remove_alias(&p, "WEB") == 0 && !policy_find_alias(&p, "WEB"), NULL);
    ok("removing an unknown alias fails",
       policy_remove_alias(&p, "WEB") != 0, NULL);
    ok("removal did not disturb the other alias",
       policy_match_ip(&p, "SERVERS", ip("10.10.20.55")), NULL);

    policy_shutdown(&p);
}

/* ═══════════════════ schedules ═══════════════════ */

static void test_schedules(void) {
    puts("\n-- schedules --");

    uint8_t days = 0;
    ok("a day list parses",
       policy_parse_days("mon,tue,wed", &days) == 0 && days == 0x0e, NULL);
    ok("\"weekdays\" is Monday to Friday",
       policy_parse_days("weekdays", &days) == 0 && days == 0x3e, NULL);
    ok("\"weekends\" is Saturday and Sunday",
       policy_parse_days("weekends", &days) == 0 && days == 0x41, NULL);
    ok("\"daily\" is every day",
       policy_parse_days("daily", &days) == 0 && days == 0x7f, NULL);
    ok("full day names work",
       policy_parse_days("monday,friday", &days) == 0 && days == 0x22, NULL);
    ok("an unknown day is refused",
       policy_parse_days("funday", &days) != 0, NULL);
    ok("an empty day list is refused", policy_parse_days("", &days) != 0, NULL);

    char buf[64];
    ok("weekdays formats back as a word",
       !strcmp(policy_days_str(0x3e, buf, sizeof(buf)), "weekdays"), buf);
    ok("an irregular set formats as a list",
       !strcmp(policy_days_str(0x0e, buf, sizeof(buf)), "mon,tue,wed"), buf);

    int m = -1;
    ok("a time parses", policy_parse_hhmm("09:30", &m) == 0 && m == 570, NULL);
    ok("midnight parses", policy_parse_hhmm("00:00", &m) == 0 && m == 0, NULL);
    ok("24:00 folds to midnight", policy_parse_hhmm("24:00", &m) == 0 && m == 0, NULL);
    ok("an impossible hour is refused", policy_parse_hhmm("25:00", &m) != 0, NULL);
    ok("an impossible minute is refused", policy_parse_hhmm("09:70", &m) != 0, NULL);
    ok("a non-time is refused", policy_parse_hhmm("morning", &m) != 0, NULL);
    ok("trailing junk is refused", policy_parse_hhmm("09:30xyz", &m) != 0, NULL);

    char hb[8];
    ok("a time formats back",
       !strcmp(policy_hhmm_str(570, hb, sizeof(hb)), "09:30"), hb);

    /* 2026-10-26 is a Monday; 2026-10-31 a Saturday, 2026-11-01 a Sunday. */
    time_t mon_10 = at(2026, 10, 26, 10, 0);
    time_t mon_20 = at(2026, 10, 26, 20, 0);
    time_t sat_10 = at(2026, 10, 31, 10, 0);
    ok("the fixture dates land on the expected weekdays",
       weekday_of(mon_10) == 1 && weekday_of(sat_10) == 6, NULL);

    schedule_t biz;
    memset(&biz, 0, sizeof(biz));
    snprintf(biz.name, sizeof(biz.name), "BIZ");
    policy_parse_days("weekdays", &biz.days);
    biz.start_min = 9 * 60;
    biz.end_min   = 18 * 60;
    biz.enabled   = true;

    ok("inside the window on a selected day",   policy_window_active(&biz, mon_10), NULL);
    ok("outside the window on a selected day", !policy_window_active(&biz, mon_20), NULL);
    ok("inside the hours but on an excluded day",
       !policy_window_active(&biz, sat_10), NULL);
    ok("exactly at the start is inside",
       policy_window_active(&biz, at(2026, 10, 26, 9, 0)), NULL);
    ok("exactly at the end is outside",
       !policy_window_active(&biz, at(2026, 10, 26, 18, 0)), NULL);

    /* A window that crosses midnight belongs to the day it opened on. */
    schedule_t night;
    memset(&night, 0, sizeof(night));
    snprintf(night.name, sizeof(night.name), "NIGHT");
    policy_parse_days("fri", &night.days);
    night.start_min = 22 * 60;
    night.end_min   = 6 * 60;
    night.enabled   = true;

    time_t fri_23 = at(2026, 10, 30, 23, 0);   /* Friday */
    time_t sat_02 = at(2026, 10, 31,  2, 0);   /* Saturday, inside Friday's window */
    time_t sat_23 = at(2026, 10, 31, 23, 0);   /* Saturday evening, not selected */
    time_t fri_12 = at(2026, 10, 30, 12, 0);   /* Friday midday, between windows */

    ok("the fixture Friday is a Friday", weekday_of(fri_23) == 5, NULL);
    ok("a midnight-crossing window is active the evening it opens",
       policy_window_active(&night, fri_23), NULL);
    ok("it is still active after midnight, on the next calendar day",
       policy_window_active(&night, sat_02), NULL);
    ok("it is not active on an evening its day is not selected",
       !policy_window_active(&night, sat_23), NULL);
    ok("it is not active in the gap between windows",
       !policy_window_active(&night, fri_12), NULL);

    /* start == end means the whole of each selected day. */
    schedule_t allday;
    memset(&allday, 0, sizeof(allday));
    policy_parse_days("sat", &allday.days);
    allday.start_min = allday.end_min = 0;
    allday.enabled = true;
    ok("start equal to end covers the whole day",
       policy_window_active(&allday, sat_10) &&
       policy_window_active(&allday, sat_23), NULL);
    ok("and still excludes other days", !policy_window_active(&allday, mon_10), NULL);

    schedule_t off = biz;
    off.enabled = false;
    ok("a disabled schedule is never active",
       !policy_window_active(&off, mon_10), NULL);

    policy_ctx_t p;
    policy_init(&p);
    policy_add_schedule(&p, &biz);
    ok("lookup by name agrees with the window test",
       policy_schedule_active(&p, "BIZ", mon_10) &&
       !policy_schedule_active(&p, "BIZ", mon_20), NULL);
    ok("an unknown schedule reads as inactive, not as always-on",
       !policy_schedule_active(&p, "NOSUCH", mon_10), NULL);
    ok("a duplicate schedule name is refused",
       policy_add_schedule(&p, &biz) != 0, NULL);
    policy_shutdown(&p);
}

/* ═══════════════════ ACL integration ═══════════════════ */

static void test_acl_integration(void) {
    puts("\n-- aliases and schedules inside the ACL engine --");

    vlan_ctx_t v;
    policy_ctx_t p;
    vlan_init(&v);
    policy_init(&p);
    vlan_set_policy(&v, &p);

    vlan_config_t c;
    memset(&c, 0, sizeof(c));
    c.vlan_id = 10; snprintf(c.name, sizeof(c.name), "CORP");
    c.zone = ZONE_LAN; c.inter_vlan_routing = true; c.lease_time = 86400;
    vlan_add(&v, &c);
    memset(&c, 0, sizeof(c));
    c.vlan_id = 20; snprintf(c.name, sizeof(c.name), "SRV");
    c.zone = ZONE_DMZ; c.inter_vlan_routing = true; c.lease_time = 86400;
    vlan_add(&v, &c);

    /* Deny everything LAN -> DMZ by default, so an allow must come from a rule. */
    vlan_set_zone_policy(&v, ZONE_LAN, ZONE_DMZ, IVR_DENY);

    alias_t web;
    memset(&web, 0, sizeof(web));
    snprintf(web.name, sizeof(web.name), "WEB");
    web.kind = ALIAS_PORT;
    policy_parse_entries(&web, "80, 443, 8000-8100");
    policy_add_alias(&p, &web);

    alias_t pool;
    memset(&pool, 0, sizeof(pool));
    snprintf(pool.name, sizeof(pool.name), "POOL");
    pool.kind = ALIAS_NETWORK;
    policy_parse_entries(&pool, "10.10.20.10/32, 10.10.20.20/32");
    policy_add_alias(&p, &pool);

    ivr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.src_vlan = 10; r.dst_vlan = 20; r.protocol = 6;
    snprintf(r.port_alias, sizeof(r.port_alias), "WEB");
    snprintf(r.dst_alias,  sizeof(r.dst_alias),  "POOL");
    r.action = IVR_ALLOW; r.priority = 10;
    snprintf(r.description, sizeof(r.description), "alias rule");
    ivr_add_rule(&v, &r);

    char why[256];
    #define FWD(sp, dp, port) vlan_check_forward(&v, 10, 20, ip(sp), ip(dp), \
                                                 port, 6, why, sizeof(why))

    ok("a port inside the alias and a host inside the alias is allowed",
       FWD("10.10.10.5", "10.10.20.10", 443) == IVR_ALLOW, why);
    ok("a port range entry in the alias also matches",
       FWD("10.10.10.5", "10.10.20.10", 8050) == IVR_ALLOW, why);
    ok("a port outside the alias falls through to deny",
       FWD("10.10.10.5", "10.10.20.10", 3389) == IVR_DENY, why);
    ok("a host outside the destination alias falls through to deny",
       FWD("10.10.10.5", "10.10.20.99", 443) == IVR_DENY, why);

    /* A rule whose alias does not exist must not widen into match-anything. */
    ivr_rule_t ghost;
    memset(&ghost, 0, sizeof(ghost));
    ghost.src_vlan = 10; ghost.dst_vlan = 20; ghost.protocol = 6;
    snprintf(ghost.port_alias, sizeof(ghost.port_alias), "MISSING");
    ghost.action = IVR_ALLOW; ghost.priority = 5;
    snprintf(ghost.description, sizeof(ghost.description), "dangling alias");
    ivr_add_rule(&v, &ghost);
    ok("a rule referencing a missing alias matches nothing",
       FWD("10.10.10.5", "10.10.20.99", 3389) == IVR_DENY, why);

    vlan_shutdown(&v);
    policy_shutdown(&p);

    /* ── schedule gating ── */
    vlan_ctx_t v2;
    policy_ctx_t p2;
    vlan_init(&v2);
    policy_init(&p2);
    vlan_set_policy(&v2, &p2);

    memset(&c, 0, sizeof(c));
    c.vlan_id = 10; snprintf(c.name, sizeof(c.name), "CORP");
    c.zone = ZONE_LAN; c.inter_vlan_routing = true; c.lease_time = 86400;
    vlan_add(&v2, &c);
    memset(&c, 0, sizeof(c));
    c.vlan_id = 20; snprintf(c.name, sizeof(c.name), "SRV");
    c.zone = ZONE_DMZ; c.inter_vlan_routing = true; c.lease_time = 86400;
    vlan_add(&v2, &c);
    vlan_set_zone_policy(&v2, ZONE_LAN, ZONE_DMZ, IVR_DENY);

    /* Always-on and never-on schedules, so the test does not depend on when
     * it runs. */
    schedule_t always, never;
    memset(&always, 0, sizeof(always));
    snprintf(always.name, sizeof(always.name), "ALWAYS");
    always.days = 0x7f;
    always.start_min = always.end_min = 0;      /* whole day, every day */
    always.enabled = true;
    policy_add_schedule(&p2, &always);

    memset(&never, 0, sizeof(never));
    snprintf(never.name, sizeof(never.name), "NEVER");
    never.days = 0x7f;
    never.start_min = 10; never.end_min = 11;   /* 00:10-00:11 */
    never.enabled = true;
    policy_add_schedule(&p2, &never);

    memset(&r, 0, sizeof(r));
    r.src_vlan = 10; r.dst_vlan = 20; r.protocol = 6;
    r.dst_port_start = r.dst_port_end = 22;
    snprintf(r.schedule, sizeof(r.schedule), "ALWAYS");
    r.action = IVR_ALLOW; r.priority = 10;
    snprintf(r.description, sizeof(r.description), "ssh in window");
    ivr_add_rule(&v2, &r);

    memset(&r, 0, sizeof(r));
    r.src_vlan = 10; r.dst_vlan = 20; r.protocol = 6;
    r.dst_port_start = r.dst_port_end = 3389;
    snprintf(r.schedule, sizeof(r.schedule), "NEVER");
    r.action = IVR_ALLOW; r.priority = 11;
    snprintf(r.description, sizeof(r.description), "rdp out of window");
    ivr_add_rule(&v2, &r);

    unsigned long before = v2.schedule_skipped;
    ivr_action_t in  = vlan_check_forward(&v2, 10, 20, ip("10.10.10.5"),
                                          ip("10.10.20.5"), 22, 6, why, sizeof(why));
    ivr_action_t out = vlan_check_forward(&v2, 10, 20, ip("10.10.10.5"),
                                          ip("10.10.20.5"), 3389, 6, why, sizeof(why));

    ok("a rule inside its schedule applies", in == IVR_ALLOW, NULL);
    ok("a rule outside its schedule does not apply", out == IVR_DENY, why);
    ok("the off-hours skip is counted", v2.schedule_skipped > before, NULL);

    vlan_shutdown(&v2);
    policy_shutdown(&p2);
    #undef FWD
}

/* ═══════════════════ failover ═══════════════════ */

static void test_failover(void) {
    puts("\n-- multi-WAN failover selection --");

    wan_config_t w[2];
    gw_state_t   st[2];
    memset(w, 0, sizeof(w));
    memset(st, 0, sizeof(st));

    snprintf(w[0].ifname, IFNAME_LEN, "eth0");
    snprintf(w[1].ifname, IFNAME_LEN, "eth5");
    w[0].mode = WAN_DHCP;   w[0].failover_priority = 10;
    w[1].mode = WAN_STATIC; w[1].failover_priority = 20; w[1].is_backup = true;

    st[0].status = GW_UP;
    st[1].status = GW_UP;
    ok("with both up, the lower priority wins",
       gwmon_select(w, st, 2) == 0, NULL);

    st[0].status = GW_DOWN;
    ok("when the primary is down, the backup takes over",
       gwmon_select(w, st, 2) == 1, NULL);

    st[1].status = GW_DOWN;
    ok("with everything down, nothing is selected",
       gwmon_select(w, st, 2) == -1, NULL);

    st[0].status = GW_UP;
    ok("the primary reclaims the route when it recovers",
       gwmon_select(w, st, 2) == 0, NULL);

    st[0].status = GW_UNKNOWN;
    st[1].status = GW_UP;
    ok("an unprobed link still counts as usable at startup",
       gwmon_select(w, st, 2) == 0, NULL);

    st[0].status = GW_UNMONITORED;
    ok("an unmonitored link counts as usable", gwmon_select(w, st, 2) == 0, NULL);

    w[0].mode = WAN_DISABLED;
    st[0].status = GW_UP;
    ok("a disabled link is never selected", gwmon_select(w, st, 2) == 1, NULL);
    w[0].mode = WAN_DHCP;

    /* Equal priority: the one not flagged as backup should win. */
    w[1].failover_priority = 10;
    st[0].status = GW_UP; st[1].status = GW_UP;
    ok("at equal priority the non-backup link wins",
       gwmon_select(w, st, 2) == 0, NULL);

    w[0].is_backup = true; w[1].is_backup = false;
    ok("and that holds when the flags are the other way round",
       gwmon_select(w, st, 2) == 1, NULL);

    puts("\n-- failover hysteresis --");

    gwmon_ctx_t g;
    memset(&g, 0, sizeof(g));
    g.fail_threshold = 3;
    g.ok_threshold   = 2;

    gw_state_t s;
    memset(&s, 0, sizeof(s));
    s.status = GW_UP;
    s.consecutive_ok = 5;

    ok("one lost probe does not take a link down",
       !gwmon_record(&g, &s, false, -1) && s.status == GW_UP, NULL);
    ok("two lost probes still do not",
       !gwmon_record(&g, &s, false, -1) && s.status == GW_UP, NULL);
    ok("the third consecutive loss does",
       gwmon_record(&g, &s, false, -1) && s.status == GW_DOWN, NULL);

    ok("one reply does not bring it back",
       !gwmon_record(&g, &s, true, 12.0) && s.status == GW_DOWN, NULL);
    ok("the second consecutive reply does",
       gwmon_record(&g, &s, true, 12.0) && s.status == GW_UP, NULL);

    ok("a loss resets the recovery streak",
       !gwmon_record(&g, &s, false, -1) && s.consecutive_ok == 0, NULL);
    ok("a reply resets the failure streak",
       !gwmon_record(&g, &s, true, 10.0) && s.consecutive_fail == 0, NULL);

    /* Seven records so far: fail, fail, fail, ok, ok, fail, ok. */
    char cnt[64];
    snprintf(cnt, sizeof(cnt), "%lu probes, %lu failures, %d%% loss",
             s.probes, s.failures, s.loss_pct);
    ok("probe and failure counts accumulate",
       s.probes == 7 && s.failures == 4, cnt);
    ok("loss is reported as a percentage of the recent window",
       s.loss_pct == (4 * 100) / 7, cnt);
    ok("round-trip time is averaged", s.avg_rtt_ms > 0, NULL);

    /* A long clean run should drive loss back to zero. */
    for (int i = 0; i < GW_RTT_WINDOW; i++) gwmon_record(&g, &s, true, 8.0);
    ok("a clean run clears the loss figure", s.loss_pct == 0, NULL);
    ok("and the link reads as up", s.status == GW_UP, NULL);
}

/* ═══════════════════ ICMP probe ═══════════════════ */

static void test_probe(void) {
    puts("\n-- ICMP probe --");

    double rtt = gwmon_ping("127.0.0.1", NULL, 1000);
    ok("loopback answers", rtt >= 0, NULL);
    ok("the round trip is plausible", rtt >= 0 && rtt < 1000, NULL);

    ok("an unroutable address times out",
       gwmon_ping("203.0.113.199", NULL, 300) < 0, NULL);
    ok("a malformed target is refused",
       gwmon_ping("not-an-address", NULL, 300) < 0, NULL);
    ok("an empty target is refused", gwmon_ping("", NULL, 300) < 0, NULL);

    /* Repeated probes must not leak descriptors or cross-match replies. */
    int good = 0;
    for (int i = 0; i < 20; i++)
        if (gwmon_ping("127.0.0.1", NULL, 1000) >= 0) good++;
    ok("twenty consecutive probes all answer", good == 20, NULL);
}

/* ═══════════════════ validation ═══════════════════ */

static void test_validation(void) {
    puts("\n-- validation --");

    cfg_validate_t res;

    ok("the shipped config, now using Phase 2 features, validates",
       firex_validate_file("config/firex.conf", &res) == 0, res.error);
    ok("it reports the aliases it found",   res.aliases >= 5, NULL);
    ok("it reports the schedules it found", res.schedules >= 2, NULL);
    ok("it reports the routes it found",    res.routes >= 2, NULL);
    ok("the lab config still validates",
       firex_validate_file("config/firex-qemu.conf", &res) == 0, res.error);
}

/* ═══════════════════ round-trip ═══════════════════ */

static void test_roundtrip(void) {
    puts("\n-- Phase 2 round-trip --");

    char dir[] = "/tmp/firex-p2-XXXXXX";
    if (!mkdtemp(dir)) { ok("temp dir", 0, "mkdtemp failed"); return; }
    char path[512];
    snprintf(path, sizeof(path), "%s/out.conf", dir);

    vlan_ctx_t v;  netconf_ctx_t n;  blockpage_ctx_t b;  policy_ctx_t p;
    vlan_init(&v); netconf_init(&n); policy_init(&p);
    vlan_set_policy(&v, &p);
    memset(&b, 0, sizeof(b));
    pthread_mutex_init(&b.lock, NULL);
    b.enabled = true; b.port = 8080;

    vlan_config_t c;
    memset(&c, 0, sizeof(c));
    c.vlan_id = 10; snprintf(c.name, sizeof(c.name), "CORP");
    c.zone = ZONE_LAN; c.lease_time = 86400; c.priority = 3;
    c.subnet = ip("10.10.10.0"); c.netmask = ip("255.255.255.0");
    c.gateway = ip("10.10.10.1");
    vlan_add(&v, &c);

    alias_t a;
    memset(&a, 0, sizeof(a));
    snprintf(a.name, sizeof(a.name), "POOL");
    snprintf(a.description, sizeof(a.description), "App servers");
    a.kind = ALIAS_NETWORK;
    policy_parse_entries(&a, "10.10.20.10/32, 10.10.20.0/24");
    policy_add_alias(&p, &a);

    memset(&a, 0, sizeof(a));
    snprintf(a.name, sizeof(a.name), "WEB");
    a.kind = ALIAS_PORT;
    policy_parse_entries(&a, "80, 443, 8000-8100");
    policy_add_alias(&p, &a);

    schedule_t sc;
    memset(&sc, 0, sizeof(sc));
    snprintf(sc.name, sizeof(sc.name), "NIGHTLY");
    snprintf(sc.description, sizeof(sc.description), "Overnight window");
    policy_parse_days("sat,sun", &sc.days);
    sc.start_min = 23 * 60; sc.end_min = 4 * 60;
    policy_add_schedule(&p, &sc);

    ivr_rule_t r;
    memset(&r, 0, sizeof(r));
    r.src_vlan = 10; r.dst_vlan = 20; r.protocol = 6;
    snprintf(r.port_alias, sizeof(r.port_alias), "WEB");
    snprintf(r.dst_alias,  sizeof(r.dst_alias),  "POOL");
    snprintf(r.schedule,   sizeof(r.schedule),   "NIGHTLY");
    r.action = IVR_ALLOW; r.priority = 10;
    snprintf(r.description, sizeof(r.description), "web to pool, overnight");
    ivr_add_rule(&v, &r);

    static_route_t rt;
    memset(&rt, 0, sizeof(rt));
    rt.dest = ip("192.168.70.0"); rt.mask = ip("255.255.255.0");
    rt.gateway = ip("10.10.10.254");
    snprintf(rt.ifname, IFNAME_LEN, "eth1");
    rt.metric = 15;
    snprintf(rt.description, sizeof(rt.description), "Lab");
    netconf_add_route(&n, &rt);

    n.monitor_interval = 7;
    n.monitor_fail = 4;

    ok("save with policy and routes succeeds",
       firex_save_enterprise_config_ex(path, &v, &n, &b, &p, NULL, NULL) == 0, NULL);

    vlan_ctx_t v2;  netconf_ctx_t n2;  blockpage_ctx_t b2;  policy_ctx_t p2;
    vlan_init(&v2); netconf_init(&n2); policy_init(&p2);
    vlan_set_policy(&v2, &p2);
    memset(&b2, 0, sizeof(b2));
    pthread_mutex_init(&b2.lock, NULL);

    ok("it loads back",
       firex_load_enterprise_config_ex(path, &v2, &n2, &b2, &p2, NULL) == 0, NULL);

    ok("alias count preserved", p2.alias_count == 2, NULL);
    ok("schedule count preserved", p2.schedule_count == 1, NULL);
    ok("route count preserved", n2.route_count == 1, NULL);

    alias_t *pool = policy_find_alias(&p2, "POOL");
    ok("a network alias round-trips",
       pool && pool->count == 2 && pool->kind == ALIAS_NETWORK &&
       pool->nets[0].ip == ip("10.10.20.10"), NULL);
    ok("its description round-trips",
       pool && !strcmp(pool->description, "App servers"), pool ? pool->description : "");

    alias_t *web = policy_find_alias(&p2, "WEB");
    ok("a port alias round-trips, ranges included",
       web && web->kind == ALIAS_PORT && web->count == 3 &&
       web->ports[2].start == 8000 && web->ports[2].end == 8100, NULL);

    schedule_t *s2 = policy_find_schedule(&p2, "NIGHTLY");
    ok("a schedule round-trips, including a window that crosses midnight",
       s2 && s2->start_min == 23 * 60 && s2->end_min == 4 * 60 &&
       s2->days == ((1u << 0) | (1u << 6)), NULL);

    ok("rule alias references round-trip",
       v2.ivr_count == 1 &&
       !strcmp(v2.ivr[0].port_alias, "WEB") &&
       !strcmp(v2.ivr[0].dst_alias,  "POOL"), NULL);
    ok("the rule's schedule reference round-trips",
       v2.ivr_count == 1 && !strcmp(v2.ivr[0].schedule, "NIGHTLY"), NULL);

    ok("a static route round-trips",
       n2.route_count == 1 &&
       n2.routes[0].dest == ip("192.168.70.0") &&
       n2.routes[0].gateway == ip("10.10.10.254") &&
       n2.routes[0].metric == 15 &&
       !strcmp(n2.routes[0].ifname, "eth1"), NULL);

    ok("monitor tuning round-trips",
       n2.monitor_interval == 7 && n2.monitor_fail == 4, NULL);

    /* The serialiser must still be a fixed point with the new sections. */
    char path2[512];
    snprintf(path2, sizeof(path2), "%s/out2.conf", dir);
    firex_save_enterprise_config_ex(path2, &v2, &n2, &b2, &p2, NULL, NULL);

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

    vlan_shutdown(&v);  netconf_shutdown(&n);  policy_shutdown(&p);
    vlan_shutdown(&v2); netconf_shutdown(&n2); policy_shutdown(&p2);

    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) fprintf(stderr, "note: could not clean %s\n", dir);
}

int main(void) {
    test_aliases();
    test_schedules();
    test_acl_integration();
    test_failover();
    test_probe();
    test_validation();
    test_roundtrip();

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
