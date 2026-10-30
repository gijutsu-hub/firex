/*
 * Phase 4 tests: connection-table parsing, the counter history ring, capture
 * bounds, and the syslog / NetFlow wire formats.
 *
 * The wire formats are checked byte by byte against their specifications
 * rather than against whatever this build happens to emit. No root, no
 * network, no collector.
 *   make test-phase4
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "inspect.h"
#include "conntrack.h"
#include "histstats.h"
#include "capture.h"
#include "telemetry.h"
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

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* ═══════════════════ connection table ═══════════════════ */

static void test_conntrack(void) {
    puts("\n-- connection table parsing --");

    /* A real line, as the kernel writes it. */
    const char *tcp_line =
        "ipv4     2 tcp      6 431998 ESTABLISHED "
        "src=10.10.10.5 dst=1.1.1.1 sport=52000 dport=443 packets=12 bytes=1440 "
        "src=1.1.1.1 dst=10.10.10.5 sport=443 dport=52000 packets=10 bytes=5000 "
        "[ASSURED] mark=0 use=1\n";

    ct_entry_t e;
    ok("a TCP line parses", ct_parse_line(tcp_line, &e), NULL);
    ok("the protocol is read", !strcmp(e.proto, "tcp"), e.proto);
    ok("the original source is read", e.src == ip("10.10.10.5"), NULL);
    ok("the original destination is read", e.dst == ip("1.1.1.1"), NULL);
    ok("the source port is read", e.sport == 52000, NULL);
    ok("the destination port is read", e.dport == 443, NULL);
    ok("the state is read", !strcmp(e.state, "ESTABLISHED"), e.state);
    ok("the timeout is read", e.ttl == 431998, NULL);
    ok("original-direction counters are read",
       e.packets == 12 && e.bytes == 1440, NULL);
    /* The reply direction repeats the same key names; the second occurrence
     * is the one that matters. */
    ok("reply-direction counters come from the second occurrence",
       e.rx_packets == 10 && e.rx_bytes == 5000, NULL);
    ok("the ASSURED flag is read", e.assured, NULL);

    const char *udp_line =
        "ipv4     2 udp      17 29 src=10.10.30.9 dst=9.9.9.9 sport=5353 "
        "dport=53 packets=1 bytes=72 [UNREPLIED] src=9.9.9.9 dst=10.10.30.9 "
        "sport=53 dport=5353 packets=0 bytes=0 mark=0 use=1\n";
    ok("a UDP line parses", ct_parse_line(udp_line, &e), NULL);
    ok("UDP is identified", !strcmp(e.proto, "udp"), e.proto);
    ok("an unreplied flow is marked", !strcmp(e.state, "UNREPLIED"), e.state);
    ok("it is not assured", !e.assured, NULL);
    ok("its reply counters are zero",
       e.rx_packets == 0 && e.rx_bytes == 0, NULL);

    /* Some kernels write no state word for ICMP. */
    const char *icmp_line =
        "ipv4     2 icmp     1 29 src=10.10.10.5 dst=8.8.8.8 type=8 code=0 "
        "id=1234 packets=1 bytes=84 src=8.8.8.8 dst=10.10.10.5 type=0 code=0 "
        "id=1234 packets=1 bytes=84 mark=0 use=1\n";
    ok("an ICMP line parses", ct_parse_line(icmp_line, &e), NULL);
    ok("a flow with no state word reads as '-'", !strcmp(e.state, "-"), e.state);

    /* malformed / hostile input */
    ok("an empty line is refused",   !ct_parse_line("", &e), NULL);
    ok("a NULL line is refused",     !ct_parse_line(NULL, &e), NULL);
    ok("a line with no addresses is refused",
       !ct_parse_line("ipv4 2 tcp 6 100 ESTABLISHED mark=0\n", &e), NULL);
    ok("an IPv6 line is skipped rather than mangled",
       !ct_parse_line("ipv6 10 tcp 6 100 ESTABLISHED src=fe80::1 dst=fe80::2\n",
                      &e), NULL);
    ok("a bad address is refused",
       !ct_parse_line("ipv4 2 tcp 6 100 ESTABLISHED src=999.1.1.1 dst=1.1.1.1 "
                      "sport=1 dport=2\n", &e), NULL);

    /* A key must start a token, or "src=" would match inside another word. */
    const char *tricky =
        "ipv4     2 tcp      6 100 ESTABLISHED xsrc=9.9.9.9 src=10.0.0.1 "
        "dst=10.0.0.2 sport=1 dport=2 packets=1 bytes=1\n";
    ok("a key embedded in another word is not mistaken for the field",
       ct_parse_line(tricky, &e) && e.src == ip("10.0.0.1"), NULL);

    /* Reading the live table must report its source rather than pretending. */
    ct_entry_t *buf = calloc(64, sizeof(*buf));
    ct_stats_t st;
    int n = ct_read(buf, 64, &st);
    ok("reading the table never errors", n >= 0, NULL);
    ok("the source is reported",
       st.source == CT_SRC_PROCFS || st.source == CT_SRC_TOOL ||
       st.source == CT_SRC_NONE, ct_source_str(st.source));
    if (st.source == CT_SRC_NONE)
        ok("an unreadable table explains why, rather than looking empty",
           st.source_detail[0] != '\0', st.source_detail);
    else
        ok("a readable table lists what it found", st.listed >= 0, NULL);
    ok("the kernel's own count is still available", ct_count() > 0, NULL);
    ok("bad arguments are refused", ct_read(NULL, 64, &st) == -1, NULL);
    free(buf);
}

/* ═══════════════════ history ring ═══════════════════ */

static void test_history(void) {
    puts("\n-- counter history --");

    hist_ctx_t h;
    hist_init(&h, NULL, 30);
    ok("the interval is kept", h.interval_sec == 30, NULL);

    hist_init(&h, NULL, 0);
    ok("zero falls back to the default",
       h.interval_sec == HIST_DEFAULT_INTERVAL, NULL);
    hist_init(&h, NULL, 1);
    ok("too small is clamped up", h.interval_sec == HIST_MIN_INTERVAL, NULL);
    hist_init(&h, NULL, 999999);
    ok("too large is clamped down", h.interval_sec == HIST_MAX_INTERVAL, NULL);

    hist_init(&h, NULL, 30);
    hist_sample_t out[HIST_SAMPLES];
    ok("an empty ring returns nothing", hist_snapshot(&h, out, 10) == 0, NULL);

    for (int i = 1; i <= 5; i++) {
        hist_sample_t s;
        memset(&s, 0, sizeof(s));
        s.when = 1000 + i;
        s.packets = (uint32_t)i * 10;
        hist_push(&h, &s);
    }
    int n = hist_snapshot(&h, out, HIST_SAMPLES);
    ok("five samples come back", n == 5, NULL);
    ok("they are oldest first",
       out[0].when == 1001 && out[4].when == 1005, NULL);
    ok("their values are intact",
       out[0].packets == 10 && out[4].packets == 50, NULL);

    n = hist_snapshot(&h, out, 2);
    ok("a bounded snapshot returns the newest, not the oldest",
       n == 2 && out[0].when == 1004 && out[1].when == 1005, NULL);

    /* Fill past capacity: the ring must drop the oldest and stay ordered. */
    hist_init(&h, NULL, 30);
    for (int i = 0; i < HIST_SAMPLES + 25; i++) {
        hist_sample_t s;
        memset(&s, 0, sizeof(s));
        s.when = 5000 + i;
        s.packets = (uint32_t)i;
        hist_push(&h, &s);
    }
    n = hist_snapshot(&h, out, HIST_SAMPLES);
    ok("the ring holds exactly its capacity", n == HIST_SAMPLES, NULL);
    ok("the oldest entries were dropped",
       out[0].when == 5000 + 25, NULL);
    ok("the newest entry survived",
       out[n-1].when == 5000 + HIST_SAMPLES + 24, NULL);
    ok("order is preserved across the wrap",
       out[0].when < out[1].when && out[n-2].when < out[n-1].when, NULL);

    /* The first tick establishes a baseline. Recording it as a delta would
     * attribute everything since boot to a single interval. */
    hist_init(&h, NULL, 30);
    vlan_init(&g_vlan);
    memset(&g_blockpage, 0, sizeof(g_blockpage));
    pthread_mutex_init(&g_blockpage.lock, NULL);
    memset(&g_gwmon, 0, sizeof(g_gwmon));
    pthread_mutex_init(&g_gwmon.lock, NULL);

    g_vlan.inter_vlan_allowed = 1000;
    hist_tick(&h);
    ok("the first tick primes rather than records",
       hist_snapshot(&h, out, HIST_SAMPLES) == 0 && h.primed, NULL);

    g_vlan.inter_vlan_allowed = 1025;
    hist_tick(&h);
    n = hist_snapshot(&h, out, HIST_SAMPLES);
    ok("the second tick records the delta, not the total",
       n == 1 && out[0].ivr_allowed == 25, NULL);

    /* A reload can reset a counter; that must read as zero, not as a vast
     * spike from the unsigned wrap. */
    g_vlan.inter_vlan_allowed = 5;
    hist_tick(&h);
    n = hist_snapshot(&h, out, HIST_SAMPLES);
    ok("a counter going backwards records zero, not a wrapped value",
       n == 2 && out[1].ivr_allowed == 0, NULL);

    g_vlan.inter_vlan_allowed = 30;
    hist_tick(&h);
    n = hist_snapshot(&h, out, HIST_SAMPLES);
    ok("counting resumes from the new baseline",
       n == 3 && out[2].ivr_allowed == 25, NULL);

    vlan_shutdown(&g_vlan);
    hist_shutdown(&h);
}

/* ═══════════════════ capture bounds ═══════════════════ */

static void test_capture(void) {
    puts("\n-- capture bounds --");

    capture_req_t r;

    memset(&r, 0, sizeof(r));
    capture_clamp(&r);
    ok("an empty request gets the defaults",
       r.max_packets == CAP_DEFAULT_PACKETS &&
       r.max_seconds == CAP_DEFAULT_SECONDS &&
       r.snaplen     == CAP_DEFAULT_SNAPLEN, NULL);

    memset(&r, 0, sizeof(r));
    r.max_packets = 10 * CAP_MAX_PACKETS;
    r.max_seconds = 10 * CAP_MAX_SECONDS;
    r.snaplen     = 10 * CAP_DEFAULT_SNAPLEN;
    capture_clamp(&r);
    ok("an oversized packet count is capped",
       r.max_packets == CAP_MAX_PACKETS, NULL);
    ok("an oversized duration is capped",
       r.max_seconds == CAP_MAX_SECONDS, NULL);
    ok("an oversized snaplen is capped",
       r.snaplen == CAP_DEFAULT_SNAPLEN, NULL);

    memset(&r, 0, sizeof(r));
    r.max_packets = -5; r.max_seconds = -5; r.snaplen = -5;
    capture_clamp(&r);
    ok("negatives fall back to the defaults",
       r.max_packets == CAP_DEFAULT_PACKETS &&
       r.max_seconds == CAP_DEFAULT_SECONDS &&
       r.snaplen     == CAP_DEFAULT_SNAPLEN, NULL);

    memset(&r, 0, sizeof(r));
    r.snaplen = 8;
    capture_clamp(&r);
    ok("a tiny snaplen is raised to the floor",
       r.snaplen == CAP_MIN_SNAPLEN, NULL);

    memset(&r, 0, sizeof(r));
    r.max_packets = 1; r.max_seconds = 1; r.snaplen = CAP_MIN_SNAPLEN;
    capture_clamp(&r);
    ok("legal small values are left alone",
       r.max_packets == 1 && r.max_seconds == 1 &&
       r.snaplen == CAP_MIN_SNAPLEN, NULL);

    ok("the byte cap is a real bound", CAP_MAX_BYTES > 0 &&
       CAP_MAX_BYTES <= 256UL * 1024 * 1024, NULL);

    /* The pcap constants have to match what libpcap expects, or the file
     * opens as garbage in Wireshark no matter how correct the packets are. */
    ok("the pcap magic is the classic little-endian one",
       PCAP_MAGIC == 0xa1b2c3d4u, NULL);
    ok("the link type is Ethernet",
       PCAP_LINKTYPE_ETHERNET == 1, NULL);

    capture_ctx_t c;
    capture_init(&c);
    ok("a fresh context is idle", c.state == CAP_IDLE, capture_state_str(c.state));

    /* An unsafe interface name must be refused before any socket is opened. */
    memset(&r, 0, sizeof(r));
    snprintf(r.ifname, IFNAME_LEN, "eth0; rm -rf /");
    ok("an unsafe interface name is refused",
       capture_start(&c, &r, "/tmp") != 0, c.error);

    memset(&r, 0, sizeof(r));
    ok("a missing interface name is refused",
       capture_start(&c, &r, "/tmp") != 0, c.error);

    /*
     * Starting a real capture needs CAP_NET_RAW. Running unprivileged, this
     * must fail with an explanation rather than crash or hang.
     */
    memset(&r, 0, sizeof(r));
    snprintf(r.ifname, IFNAME_LEN, "lo");
    r.max_packets = 1; r.max_seconds = 1;
    int rc = capture_start(&c, &r, "/tmp/firex-captest");
    if (rc != 0) {
        ok("without CAP_NET_RAW the failure is explained, not silent",
           c.error[0] != '\0' && c.state == CAP_FAILED, c.error);
    } else {
        capture_stop(&c);
        ok("a privileged run captures and stops cleanly",
           c.state == CAP_DONE, NULL);
    }
    capture_shutdown(&c);
}

/* ═══════════════════ syslog wire format ═══════════════════ */

static void test_syslog(void) {
    puts("\n-- RFC 5424 syslog --");

    char out[512];
    /* A fixed instant, so the stamp is deterministic: 2026-01-02 in UTC. */
    const time_t when = 1767322445;

    int n = syslog_format(out, sizeof(out), 16, SYSLOG_WARNING, when,
                          "firex", "firexd", "BLOCK", "something happened");
    ok("a frame is produced", n > 0, NULL);

    /* PRI = facility * 8 + severity = 16*8 + 4 = 132 */
    ok("the priority is facility*8 + severity",
       strncmp(out, "<132>1 ", 7) == 0, out);

    ok("the version is 1", strstr(out, ">1 ") != NULL, NULL);
    ok("the timestamp is RFC 3339 in UTC",
       strstr(out, "2026-01-02T") != NULL && strstr(out, "Z ") != NULL, out);
    ok("the hostname is present", strstr(out, " firex ") != NULL, NULL);
    ok("the app name is present", strstr(out, " firexd ") != NULL, NULL);
    ok("the message id is present", strstr(out, " BLOCK ") != NULL, NULL);
    ok("the message is last",
       strstr(out, "something happened") ==
         out + strlen(out) - strlen("something happened"), NULL);

    /* PROCID and STRUCTURED-DATA are absent, which RFC 5424 writes as '-'. */
    ok("absent fields are written as '-'", strstr(out, " - ") != NULL, NULL);

    n = syslog_format(out, sizeof(out), 0, 0, when, NULL, NULL, NULL, "x");
    ok("facility 0 severity 0 gives priority 0",
       n > 0 && strncmp(out, "<0>1 ", 5) == 0, out);
    ok("a missing hostname becomes '-'", strstr(out, " - ") != NULL, NULL);

    n = syslog_format(out, sizeof(out), 99, 99, when, "h", "a", "m", "x");
    ok("an out-of-range facility is corrected",
       n > 0 && strncmp(out, "<134>1 ", 7) == 0, out);

    char tiny[32];
    ok("a buffer that cannot hold the frame is refused",
       syslog_format(tiny, sizeof(tiny), 16, 6, when, "host", "app", "id",
                     "a message far longer than the buffer provided") < 0, NULL);
    ok("a null buffer is refused",
       syslog_format(NULL, 512, 16, 6, when, "h", "a", "i", "m") < 0, NULL);
}

/* ═══════════════════ NetFlow v5 wire format ═══════════════════ */

static void test_netflow(void) {
    puts("\n-- NetFlow v5 --");

    ct_entry_t e[3];
    memset(e, 0, sizeof(e));

    snprintf(e[0].proto, CT_PROTO_LEN, "tcp");
    e[0].src = ip("10.10.10.5"); e[0].dst = ip("1.1.1.1");
    e[0].sport = 52000; e[0].dport = 443;
    e[0].packets = 12; e[0].bytes = 1440;

    snprintf(e[1].proto, CT_PROTO_LEN, "udp");
    e[1].src = ip("10.10.30.9"); e[1].dst = ip("9.9.9.9");
    e[1].sport = 5353; e[1].dport = 53;
    e[1].packets = 1; e[1].bytes = 72;

    snprintf(e[2].proto, CT_PROTO_LEN, "icmp");
    e[2].src = ip("10.10.10.1"); e[2].dst = ip("8.8.8.8");
    /* Deliberately beyond 32 bits: v5 counters must saturate, not wrap. */
    e[2].packets = 0x1FFFFFFFFULL; e[2].bytes = 0x2FFFFFFFFULL;

    uint8_t pkt[2048];
    int len = netflow_v5_build(pkt, sizeof(pkt), e, 3, 123456, 1767322445, 42);

    ok("a datagram is produced", len > 0, NULL);
    ok("its length is the header plus three records",
       len == NETFLOW_V5_HDR_LEN + 3 * NETFLOW_V5_REC_LEN, NULL);

    ok("the version is 5",              be16(pkt + 0) == 5, NULL);
    ok("the record count is 3",         be16(pkt + 2) == 3, NULL);
    ok("sysUptime is carried",          be32(pkt + 4) == 123456, NULL);
    ok("the unix time is carried",      be32(pkt + 8) == 1767322445u, NULL);
    ok("the flow sequence is carried",  be32(pkt + 16) == 42, NULL);

    const uint8_t *r0 = pkt + NETFLOW_V5_HDR_LEN;
    uint32_t src, dst;
    memcpy(&src, r0 + 0, 4);
    memcpy(&dst, r0 + 4, 4);
    ok("the source address is in the record",  src == ip("10.10.10.5"), NULL);
    ok("the destination address is too",       dst == ip("1.1.1.1"), NULL);
    ok("packet and byte counts are carried",
       be32(r0 + 16) == 12 && be32(r0 + 20) == 1440, NULL);
    ok("the ports are carried",
       be16(r0 + 32) == 52000 && be16(r0 + 34) == 443, NULL);
    ok("TCP is protocol 6",  r0[38] == 6, NULL);

    const uint8_t *r1 = r0 + NETFLOW_V5_REC_LEN;
    ok("UDP is protocol 17", r1[38] == 17, NULL);
    ok("the second record carries its own ports",
       be16(r1 + 32) == 5353 && be16(r1 + 34) == 53, NULL);

    const uint8_t *r2 = r1 + NETFLOW_V5_REC_LEN;
    ok("ICMP is protocol 1", r2[38] == 1, NULL);
    ok("a count beyond 32 bits saturates rather than wrapping",
       be32(r2 + 16) == 0xffffffffu && be32(r2 + 20) == 0xffffffffu, NULL);

    /* Bounds. */
    ok("a buffer too small is refused",
       netflow_v5_build(pkt, 32, e, 3, 0, 0, 0) < 0, NULL);
    ok("zero records are refused",
       netflow_v5_build(pkt, sizeof(pkt), e, 0, 0, 0, 0) < 0, NULL);
    ok("a null buffer is refused",
       netflow_v5_build(NULL, sizeof(pkt), e, 3, 0, 0, 0) < 0, NULL);

    /* More than one datagram's worth must be truncated to the batch limit,
     * because a larger datagram would fragment. */
    ct_entry_t many[NETFLOW_MAX_RECORDS + 10];
    memset(many, 0, sizeof(many));
    for (size_t i = 0; i < sizeof(many)/sizeof(many[0]); i++) {
        snprintf(many[i].proto, CT_PROTO_LEN, "tcp");
        many[i].src = ip("10.0.0.1");
        many[i].dst = ip("10.0.0.2");
    }
    len = netflow_v5_build(pkt, sizeof(pkt), many,
                           (int)(sizeof(many)/sizeof(many[0])), 0, 0, 0);
    ok("a batch larger than one datagram is truncated to the limit",
       len == NETFLOW_V5_HDR_LEN + NETFLOW_MAX_RECORDS * NETFLOW_V5_REC_LEN,
       NULL);
    ok("and still fits inside a 1500-byte MTU", len <= 1472, NULL);
}

/* ═══════════════════ exporter behaviour ═══════════════════ */

static void test_telemetry(void) {
    puts("\n-- exporter --");

    telemetry_ctx_t t;
    telemetry_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    telemetry_init(&t, &cfg);
    ok("with no collectors, syslog is off",  !telemetry_has_syslog(&t), NULL);
    ok("with no collectors, netflow is off", !telemetry_has_netflow(&t), NULL);
    ok("starting is a no-op",  telemetry_start(&t) == 0 && !t.running, NULL);
    ok("logging to nowhere is harmless",
       (telemetry_log(&t, SYSLOG_INFO, "T", "ignored"), t.syslog_sent == 0), NULL);
    ok("exporting with no collector sends nothing",
       telemetry_export_flows(&t) == 0, NULL);
    telemetry_shutdown(&t);

    /* Defaults must be filled in rather than left as zero. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.syslog_host, TELEM_HOST_LEN, "127.0.0.1");
    snprintf(cfg.netflow_host, TELEM_HOST_LEN, "127.0.0.1");
    telemetry_init(&t, &cfg);
    ok("the syslog port defaults to 514",   t.cfg.syslog_port == 514, NULL);
    ok("the netflow port defaults to 2055", t.cfg.netflow_port == 2055, NULL);
    ok("the netflow interval gets a default", t.cfg.netflow_interval == 60, NULL);
    ok("the facility defaults to local0",   t.cfg.syslog_facility == 16, NULL);
    ok("syslog is now configured",  telemetry_has_syslog(&t), NULL);
    ok("netflow is now configured", telemetry_has_netflow(&t), NULL);

    /* UDP to a local port nobody is listening on still "sends" -- that is
     * UDP. What matters is that it is counted and never blocks. */
    telemetry_log(&t, SYSLOG_WARNING, "TEST", "a test message");
    ok("a message is accounted for either way",
       t.syslog_sent + t.syslog_dropped == 1, NULL);
    telemetry_shutdown(&t);

    /* Severity filtering: only this severity and worse are sent. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.syslog_host, TELEM_HOST_LEN, "127.0.0.1");
    cfg.syslog_min_severity = SYSLOG_WARNING;
    telemetry_init(&t, &cfg);
    unsigned long before = t.syslog_sent + t.syslog_dropped;
    telemetry_log(&t, SYSLOG_INFO, "T", "too chatty to send");
    ok("a message below the threshold is not sent",
       t.syslog_sent + t.syslog_dropped == before, NULL);
    telemetry_log(&t, SYSLOG_ALERT, "T", "serious enough");
    ok("a message at or above it is",
       t.syslog_sent + t.syslog_dropped == before + 1, NULL);
    telemetry_shutdown(&t);
}

int main(void) {
    test_conntrack();
    test_history();
    test_capture();
    test_syslog();
    test_netflow();
    test_telemetry();

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
