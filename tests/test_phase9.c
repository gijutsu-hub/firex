/*
 * Phase 9 tests: live malware protection, air gap, interface inventory.
 * No root, no network -- packets are synthesised in memory and the only
 * file touched is a signature database in a temporary directory.
 *   make test-phase9
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "malware.h"
#include "airgap.h"
#include "netif.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-58s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-58s %s\n", what, detail ? detail : ""); fail++; }
}

static char g_dir[256];
static const char *P(const char *leaf) {
    static char pool[4][512];
    static int  n = 0;
    char *b = pool[n++ & 3];
    snprintf(b, sizeof(pool[0]), "%s/%s", g_dir, leaf);
    return b;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static void hexof(const void *data, size_t len, char *out) {
    uint8_t d[MW_DIGEST_LEN];
    mw_sha256(data, len, d);
    mw_hex(d, out, MW_HEXLEN);
}

/* A TCP packet carrying `payload`. Everything the scanner reads is set;
 * the rest stays zero, which is what a real capture looks like for the
 * fields it does not use. */
static packet_info_t mkpkt(const char *payload, size_t len, uint8_t flags) {
    packet_info_t p;
    memset(&p, 0, sizeof(p));
    p.has_ip      = true;
    p.protocol    = IPPROTO_TCP;
    p.src_ip      = 0x0A000001;        /* 10.0.0.1 */
    p.dst_ip      = 0xC0A80164;        /* 192.168.1.100 */
    p.src_port    = 80;
    p.dst_port    = 50000;
    p.tcp_flags   = flags;
    p.payload     = (unsigned char *)(uintptr_t)payload;
    p.payload_len = (int)len;
    p.timestamp   = 1000000;
    return p;
}

/* ── SHA-256 ─────────────────────────────────────────────────────────── */

static void test_sha256(void) {
    puts("\n--- SHA-256 (FIPS 180-4 vectors) ---");

    struct { const char *in; const char *want; } v[] = {
        { "",    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
    };
    for (size_t i = 0; i < sizeof v / sizeof *v; i++) {
        char got[MW_HEXLEN];
        hexof(v[i].in, strlen(v[i].in), got);
        char what[80];
        snprintf(what, sizeof(what), "vector %zu (%zu bytes)", i + 1, strlen(v[i].in));
        ok(what, strcmp(got, v[i].want) == 0, got);
    }

    /* The multi-block path, which single-block vectors never exercise. */
    mw_sha256_t s;
    char buf[1000];
    uint8_t d[MW_DIGEST_LEN];
    char got[MW_HEXLEN];
    memset(buf, 'a', sizeof buf);
    mw_sha256_init(&s);
    for (int i = 0; i < 1000; i++) mw_sha256_update(&s, buf, sizeof buf);
    mw_sha256_final(&s, d);
    mw_hex(d, got, sizeof got);
    ok("one million 'a' (streamed in 1000-byte pieces)",
       strcmp(got, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0,
       got);

    /* Streaming in odd-sized pieces must equal hashing in one go: this is
     * what the reassembler relies on, and a buffering bug would show up
     * here rather than as a missed detection months later. */
    const char *msg = "the quick brown fox jumps over the lazy dog, repeatedly";
    char whole[MW_HEXLEN], piecewise[MW_HEXLEN];
    hexof(msg, strlen(msg), whole);
    mw_sha256_init(&s);
    for (size_t i = 0; i < strlen(msg); i += 7)
        mw_sha256_update(&s, msg + i, (strlen(msg) - i) < 7 ? strlen(msg) - i : 7);
    mw_sha256_final(&s, d);
    mw_hex(d, piecewise, sizeof piecewise);
    ok("streamed in 7-byte pieces matches one call",
       strcmp(whole, piecewise) == 0, piecewise);
}

/* ── signature database ──────────────────────────────────────────────── */

static void test_database(void) {
    puts("\n--- signature database ---");

    mw_ctx_t m;
    ok("init", mw_init(&m) == 0, NULL);

    const char *sample = "this is a pretend malware sample body";
    char sample_hex[MW_HEXLEN];
    hexof(sample, strlen(sample), sample_hex);

    FILE *f = fopen(P("hashes.db"), "w");
    fprintf(f, "# version: 2026-10-29\n");
    fprintf(f, "# a comment line\n\n");
    fprintf(f, "%s 4 Pretend.Trojan.A\n", sample_hex);
    fprintf(f, "not-a-hash 3 should be skipped\n");
    fprintf(f, "%064d 1 Zero.Sample\n", 0);
    fclose(f);

    int n = mw_load_hashes(&m, P("hashes.db"));
    ok("loads the good rows and skips the malformed one", n == 2, NULL);
    ok("reads the version comment",
       strcmp(m.db_version, "2026-10-29") == 0, m.db_version);

    /* A file that cannot be read must not empty the database -- the same
     * rule feeds.c follows, and for the same reason. */
    int before = m.hash_count;
    int rc = mw_load_hashes(&m, P("no-such-file.db"));
    ok("an unreadable file is refused", rc == -1, NULL);
    ok("and the previous database is still loaded", m.hash_count == before, NULL);

    mw_shutdown(&m);
}

/* ── detection ───────────────────────────────────────────────────────── */

static void test_detection(void) {
    puts("\n--- detection ---");

    mw_ctx_t m;
    mw_init(&m);
    m.enabled = true;
    m.block   = true;

    const char *body = "MZ\x90\x00 this is a pretend malware sample body";
    size_t blen = strlen(body);
    char hex[MW_HEXLEN];
    hexof(body, blen, hex);

    FILE *f = fopen(P("d.db"), "w");
    fprintf(f, "%s 4 Pretend.Trojan.A\n", hex);
    fclose(f);
    mw_load_hashes(&m, P("d.db"));

    /* 1. the whole object in one packet */
    char pkt[512];
    int hn = snprintf(pkt, sizeof(pkt),
                      "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                      "Content-Length: %zu\r\n\r\n", blen);
    memcpy(pkt + hn, body, blen);
    packet_info_t p = mkpkt(pkt, (size_t)hn + blen, 0);

    mw_event_t ev;
    memset(&ev, 0, sizeof(ev));
    mw_verdict_t v = mw_scan_packet(&m, &p, &ev);
    ok("a known sample in one packet is blocked", v == MW_BLOCK, ev.name);
    ok("  it is named from the database",
       strcmp(ev.name, "Pretend.Trojan.A") == 0, ev.name);
    ok("  the digest is reported", strcmp(ev.sha256, hex) == 0, NULL);
    ok("  severity comes from the database", ev.severity == 4, NULL);
    ok("  it is attributed to the hash source", ev.source == MW_SRC_HASH, NULL);

    /* 2. THE POINT OF THE WHOLE MODULE: the same object split across
     *    packets, which the per-packet signature engine cannot see. */
    mw_ctx_t m2;
    mw_init(&m2);
    m2.enabled = true; m2.block = true;
    mw_load_hashes(&m2, P("d.db"));

    char head[256];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", blen);
    packet_info_t h = mkpkt(head, (size_t)hl, 0);
    memset(&ev, 0, sizeof(ev));
    v = mw_scan_packet(&m2, &h, &ev);
    ok("headers alone are clean", v == MW_CLEAN, NULL);

    size_t half = blen / 2;
    packet_info_t s1 = mkpkt(body, half, 0);
    v = mw_scan_packet(&m2, &s1, &ev);
    ok("the first half alone is clean", v == MW_CLEAN, NULL);

    packet_info_t s2 = mkpkt(body + half, blen - half, 0);
    memset(&ev, 0, sizeof(ev));
    v = mw_scan_packet(&m2, &s2, &ev);
    ok("the object is caught once the last segment arrives",
       v == MW_BLOCK, ev.name);
    ok("  reassembled to the right length", ev.size == blen, NULL);
    mw_shutdown(&m2);

    /* 3. detect-only must report without dropping */
    mw_ctx_t m3;
    mw_init(&m3);
    m3.enabled = true; m3.block = false;
    mw_load_hashes(&m3, P("d.db"));
    packet_info_t p3 = mkpkt(pkt, (size_t)hn + blen, 0);
    memset(&ev, 0, sizeof(ev));
    v = mw_scan_packet(&m3, &p3, &ev);
    ok("detect-only alerts instead of blocking", v == MW_ALERT, NULL);
    ok("  and still records the detection", m3.detections == 1, NULL);
    ok("  but counts nothing as blocked", m3.blocked == 0, NULL);
    mw_shutdown(&m3);

    /* 4. a clean object stays clean */
    mw_ctx_t m4;
    mw_init(&m4);
    m4.enabled = true;
    mw_load_hashes(&m4, P("d.db"));
    const char *clean = "an entirely ordinary file";
    char cpkt[512];
    int cn = snprintf(cpkt, sizeof(cpkt),
                      "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%s",
                      strlen(clean), clean);
    packet_info_t p4 = mkpkt(cpkt, (size_t)cn, 0);
    v = mw_scan_packet(&m4, &p4, &ev);
    ok("an unknown object is not a detection", v == MW_CLEAN, NULL);
    ok("  but it was scanned", m4.objects_scanned == 1, NULL);
    mw_shutdown(&m4);

    /* 5. disabled means disabled */
    m.enabled = false;
    packet_info_t p5 = mkpkt(pkt, (size_t)hn + blen, 0);
    ok("disabled scans nothing", mw_scan_packet(&m, &p5, &ev) == MW_CLEAN, NULL);

    mw_shutdown(&m);
}

static void test_eicar(void) {
    puts("\n--- EICAR, the one sample an operator can safely test with ---");

    mw_ctx_t m;
    mw_init(&m);
    m.enabled = true;
    m.block   = true;
    int n = mw_load_builtin_patterns(&m);
    ok("a built-in pattern is installed", n == 1, NULL);

    /* Assembled here for the same reason the engine assembles it: a test
     * binary containing the literal string gets quarantined by whatever
     * is running on the build host. */
    static const char a[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}";
    static const char b[] = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    char eicar[128];
    snprintf(eicar, sizeof(eicar), "%s%s", a, b);

    char pkt[512];
    int hn = snprintf(pkt, sizeof(pkt),
                      "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%s",
                      strlen(eicar), eicar);
    packet_info_t p = mkpkt(pkt, (size_t)hn, 0);

    mw_event_t ev;
    memset(&ev, 0, sizeof(ev));
    mw_verdict_t v = mw_scan_packet(&m, &p, &ev);
    ok("the test file is detected", v == MW_BLOCK, ev.name);
    ok("  as a pattern match, not a hash", ev.source == MW_SRC_PATTERN, NULL);
    ok("  and is labelled as not being malware",
       strstr(ev.name, "not malware") != NULL, ev.name);

    mw_shutdown(&m);
}

static void test_limits(void) {
    puts("\n--- bounds and failure modes ---");

    mw_ctx_t m;
    mw_init(&m);
    m.enabled = true;

    /* Encrypted ports are counted as unscanned rather than pretended at. */
    const char *tls = "\x16\x03\x01\x02\x00 this is a TLS record, not readable";
    packet_info_t p = mkpkt(tls, strlen(tls), 0);
    p.src_port = 443;
    mw_scan_packet(&m, &p, NULL);
    ok("TLS is counted as opaque, not scanned", m.bytes_opaque > 0, NULL);
    ok("  and starts no flow", mw_active_flows(&m) == 0, NULL);

    /* Something that is not an HTTP response is ignored entirely. */
    mw_ctx_t m2; mw_init(&m2); m2.enabled = true;
    const char *junk = "SSH-2.0-OpenSSH_9.6";
    packet_info_t p2 = mkpkt(junk, strlen(junk), 0);
    p2.src_port = 2222;
    mw_scan_packet(&m2, &p2, NULL);
    ok("a non-HTTP stream is not followed", mw_active_flows(&m2) == 0, NULL);
    mw_shutdown(&m2);

    /* The flow table is a hard ceiling: when it is full, new flows are
     * dropped rather than evicting one that is mid-scan. */
    mw_ctx_t m3; mw_init(&m3); m3.enabled = true;
    char head[128];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n");
    for (int i = 0; i < MW_MAX_FLOWS + 10; i++) {
        packet_info_t f = mkpkt(head, (size_t)hl, 0);
        f.dst_port = (uint16_t)(40000 + i);
        mw_scan_packet(&m3, &f, NULL);
    }
    ok("the flow table stops at its ceiling",
       mw_active_flows(&m3) == MW_MAX_FLOWS, NULL);
    ok("  and the overflow is counted, not hidden",
       m3.flows_dropped == 10, NULL);

    /* Idle flows are released. */
    int freed = mw_gc(&m3, 1000000 + m3.flow_idle_seconds + 1);
    ok("idle flows are released", freed == MW_MAX_FLOWS, NULL);
    ok("  leaving the table empty", mw_active_flows(&m3) == 0, NULL);
    mw_shutdown(&m3);

    /* An object past the cap is truncated and counted. */
    mw_ctx_t m4; mw_init(&m4); m4.enabled = true;
    m4.max_object = 1024;
    char *big = malloc(4096);
    memset(big, 'A', 4096);
    char bhead[128];
    int bl = snprintf(bhead, sizeof(bhead),
                      "HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n");
    packet_info_t bp = mkpkt(bhead, (size_t)bl, 0);
    mw_scan_packet(&m4, &bp, NULL);
    packet_info_t bb = mkpkt(big, 4000, 0);
    mw_scan_packet(&m4, &bb, NULL);
    ok("an oversized object is truncated, and says so", m4.truncated == 1, NULL);
    free(big);
    mw_shutdown(&m4);

    /*
     * The console lets an operator change max_object at any moment, so it
     * can shrink BELOW what a flow has already buffered. Written as one
     * expression, "cap - have" underflows there and the clamp becomes
     * SIZE_MAX, so the cap stops applying and the flow keeps buffering
     * past its slice into the next flow's.
     *
     * ASan does not catch this: every flow buffer is a slice of ONE
     * calloc'd arena, so the write is still inside that allocation. The
     * damage is one transfer's bytes landing in another transfer's hash,
     * which a scanner reports as a confident wrong answer rather than a
     * crash -- the worse of the two outcomes. So the assertion is on the
     * counter: with the bug, nothing is marked truncated because the
     * clamp never fires.
     */
    mw_ctx_t m5; mw_init(&m5); m5.enabled = true;
    m5.max_object = 8192;
    char h5[128];
    int l5 = snprintf(h5, sizeof(h5),
                      "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n");
    packet_info_t p5h = mkpkt(h5, (size_t)l5, 0);
    mw_scan_packet(&m5, &p5h, NULL);

    char *chunk = malloc(4096);
    memset(chunk, 'B', 4096);
    packet_info_t c1 = mkpkt(chunk, 4096, 0);
    mw_scan_packet(&m5, &c1, NULL);          /* 4096 buffered, cap 8192 */

    m5.max_object = 1024;                    /* now below what is held */
    packet_info_t c2 = mkpkt(chunk, 4096, 0);
    mw_verdict_t v5 = mw_scan_packet(&m5, &c2, NULL);
    ok("shrinking the object cap below a live flow is survivable",
       v5 == MW_CLEAN || v5 == MW_ALERT || v5 == MW_BLOCK, NULL);
    ok("  and the cap still applies, so the flow is truncated",
       m5.truncated >= 1, NULL);
    free(chunk);
    mw_shutdown(&m5);

    /* Content-Type is lifted from the response header for the event. */
    mw_ctx_t m6; mw_init(&m6); m6.enabled = true; m6.block = true;
    mw_load_builtin_patterns(&m6);
    static const char ea[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}";
    static const char eb[] = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    char eic[128];
    snprintf(eic, sizeof(eic), "%s%s", ea, eb);
    char p6[512];
    int n6 = snprintf(p6, sizeof(p6),
                      "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                      "Content-Length: %zu\r\n\r\n%s", strlen(eic), eic);
    packet_info_t pk6 = mkpkt(p6, (size_t)n6, 0);
    mw_event_t ev6;
    memset(&ev6, 0, sizeof(ev6));
    mw_scan_packet(&m6, &pk6, &ev6);
    ok("the Content-Type is recorded with the detection",
       strcmp(ev6.ctype, "application/octet-stream") == 0, ev6.ctype);
    mw_shutdown(&m6);

    mw_shutdown(&m);
}

/* ── air gap ─────────────────────────────────────────────────────────── */

static time_t at(int wday, int hour, int min) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = 126;      /* 2026 */
    tm.tm_mon  = 0;
    /* 1 Jan 2026 is a Thursday (wday 4); walk to the weekday asked for. */
    tm.tm_mday = 4 + wday;  /* 4 Jan 2026 is a Sunday */
    tm.tm_hour = hour;
    tm.tm_min  = min;
    tm.tm_isdst = -1;
    return mktime(&tm);
}

static void test_airgap_modes(void) {
    puts("\n--- air gap modes ---");

    ag_ctx_t a;
    ok("init", airgap_init(&a) == 0, NULL);
    ok("starts connected", a.mode == AG_CONNECTED, NULL);
    ok("  and open", a.open_now, a.state_reason);

    char why[AG_REASON_LEN];

    /* connected: everything crosses */
    ok("connected lets traffic out",
       airgap_verdict(&a, AG_CROSS_OUT, at(1, 12, 0), why, sizeof why) == AG_PASS, NULL);
    ok("connected lets traffic in",
       airgap_verdict(&a, AG_CROSS_IN, at(1, 12, 0), why, sizeof why) == AG_PASS, NULL);

    /* isolated: nothing crosses, either way */
    airgap_set_mode(&a, AG_ISOLATED, "test");
    ok("isolated denies outbound",
       airgap_verdict(&a, AG_CROSS_OUT, at(1,12,0), why, sizeof why) == AG_DENY, why);
    ok("isolated denies inbound",
       airgap_verdict(&a, AG_CROSS_IN, at(1,12,0), why, sizeof why) == AG_DENY, NULL);
    ok("  internal traffic is untouched",
       airgap_verdict(&a, AG_CROSS_NONE, at(1,12,0), why, sizeof why) == AG_PASS, NULL);
    ok("  and the appliance may not fetch for itself",
       !airgap_network_permitted(&a, at(1,12,0), true), NULL);

    /* diodes */
    airgap_set_mode(&a, AG_INBOUND_ONLY, "test");
    ok("inbound diode allows in",
       airgap_verdict(&a, AG_CROSS_IN, at(1,12,0), why, sizeof why) == AG_PASS, NULL);
    ok("inbound diode denies out",
       airgap_verdict(&a, AG_CROSS_OUT, at(1,12,0), why, sizeof why) == AG_DENY, why);
    ok("  so it will not fetch either, which would mean talking out",
       !airgap_network_permitted(&a, at(1,12,0), false), NULL);

    airgap_set_mode(&a, AG_OUTBOUND_ONLY, "test");
    ok("outbound diode allows out",
       airgap_verdict(&a, AG_CROSS_OUT, at(1,12,0), why, sizeof why) == AG_PASS, NULL);
    ok("outbound diode denies in",
       airgap_verdict(&a, AG_CROSS_IN, at(1,12,0), why, sizeof why) == AG_DENY, why);
    ok("  but it may still fetch",
       airgap_network_permitted(&a, at(1,12,0), false), NULL);

    /* manual: the distinction that matters */
    airgap_set_mode(&a, AG_MANUAL, "test");
    ok("manual denies user traffic",
       airgap_verdict(&a, AG_CROSS_OUT, at(1,12,0), why, sizeof why) == AG_DENY, NULL);
    ok("manual also closes the appliance's own update path",
       !airgap_network_permitted(&a, at(1,12,0), true), NULL);
    ok("  and the refusals are counted", a.blocked_fetches == 2, NULL);

    /* counters */
    ok("denials are counted by direction",
       a.denied_out > 0 && a.denied_in > 0, NULL);

    /* classification */
    ok("LAN to WAN is outbound",
       airgap_classify(ZONE_LAN, ZONE_WAN) == AG_CROSS_OUT, NULL);
    ok("WAN to LAN is inbound",
       airgap_classify(ZONE_WAN, ZONE_LAN) == AG_CROSS_IN, NULL);
    ok("LAN to DMZ does not cross the gap",
       airgap_classify(ZONE_LAN, ZONE_DMZ) == AG_CROSS_NONE, NULL);
    ok("WAN to WAN does not cross",
       airgap_classify(ZONE_WAN, ZONE_WAN) == AG_CROSS_NONE, NULL);

    airgap_shutdown(&a);
}

static void test_airgap_schedule(void) {
    puts("\n--- scheduled windows ---");

    ag_ctx_t a;
    airgap_init(&a);
    a.require_time_sync = false;      /* tested separately below */

    /* Mon-Fri 02:00-04:00, both directions. */
    uint8_t weekdays = (1u<<1)|(1u<<2)|(1u<<3)|(1u<<4)|(1u<<5);
    ok("a window is accepted",
       airgap_add_window(&a, "nightly sync", weekdays, 120, 240, true, true) == 0, NULL);
    airgap_set_mode(&a, AG_SCHEDULED, "test");

    char why[AG_REASON_LEN];

    airgap_tick(&a, at(1, 3, 0));
    ok("inside the window the gap is open", a.open_now, a.state_reason);
    ok("  and traffic crosses",
       airgap_verdict(&a, AG_CROSS_OUT, at(1,3,0), why, sizeof why) == AG_PASS, NULL);

    airgap_tick(&a, at(1, 12, 0));
    ok("outside the window it is shut", !a.open_now, a.state_reason);
    ok("  and traffic is refused",
       airgap_verdict(&a, AG_CROSS_OUT, at(1,12,0), why, sizeof why) == AG_DENY, why);

    airgap_tick(&a, at(0, 3, 0));     /* Sunday, same hour */
    ok("the window does not apply on a day it excludes", !a.open_now, NULL);

    ok("a next change is computed", a.next_change > 0, NULL);

    /* A window that wraps midnight: 22:00 to 04:00 on Friday is ONE
     * opening that runs into Saturday morning. */
    ag_ctx_t b;
    airgap_init(&b);
    b.require_time_sync = false;
    airgap_add_window(&b, "overnight", 1u << 5 /* Fri */, 22 * 60, 4 * 60, true, true);
    airgap_set_mode(&b, AG_SCHEDULED, "test");

    airgap_tick(&b, at(5, 23, 0));
    ok("a wrapping window is open before midnight", b.open_now, NULL);
    airgap_tick(&b, at(6, 2, 0));     /* Saturday 02:00 */
    ok("  and still open after midnight", b.open_now, NULL);
    airgap_tick(&b, at(6, 5, 0));
    ok("  but shut once it ends", !b.open_now, NULL);
    airgap_tick(&b, at(5, 12, 0));
    ok("  and shut during the day", !b.open_now, NULL);
    airgap_shutdown(&b);

    /* Direction can be restricted per window. */
    ag_ctx_t c;
    airgap_init(&c);
    c.require_time_sync = false;
    airgap_add_window(&c, "collect only", 0x7F, 0, 1439, true, false);
    airgap_set_mode(&c, AG_SCHEDULED, "test");
    airgap_tick(&c, at(1, 12, 0));
    ok("a window may allow in and not out",
       airgap_verdict(&c, AG_CROSS_IN,  at(1,12,0), why, sizeof why) == AG_PASS &&
       airgap_verdict(&c, AG_CROSS_OUT, at(1,12,0), why, sizeof why) == AG_DENY, NULL);
    airgap_shutdown(&c);

    /* No windows at all means the gap never opens -- failing shut. */
    ag_ctx_t d;
    airgap_init(&d);
    d.require_time_sync = false;
    airgap_set_mode(&d, AG_SCHEDULED, "test");
    airgap_tick(&d, at(1, 12, 0));
    ok("scheduled with no windows stays shut", !d.open_now, d.state_reason);
    airgap_shutdown(&d);

    airgap_shutdown(&a);
}

static void test_airgap_clock(void) {
    puts("\n--- the clock a schedule depends on ---");

    ag_ctx_t a;
    airgap_init(&a);
    a.require_time_sync = true;
    a.time_synced       = false;
    airgap_add_window(&a, "always", 0x7F, 0, 1439, true, true);
    airgap_set_mode(&a, AG_SCHEDULED, "test");

    airgap_tick(&a, at(1, 12, 0));
    ok("an unsynchronised clock fails shut, not open", !a.open_now, a.state_reason);
    ok("  and says why", strstr(a.state_reason, "clock") != NULL, a.state_reason);

    a.time_synced = true;
    airgap_tick(&a, at(1, 12, 0));
    ok("once the clock is trusted the window applies", a.open_now, a.state_reason);

    airgap_shutdown(&a);
}

static void test_airgap_names(void) {
    puts("\n--- modes round-trip through the config ---");

    const char *names[] = { "connected","scheduled","inbound-only",
                            "outbound-only","isolated","manual" };
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        ag_mode_t m;
        bool okk = airgap_mode_from_name(names[i], &m);
        char what[80];
        snprintf(what, sizeof(what), "\"%s\" parses and formats back", names[i]);
        ok(what, okk && strcmp(airgap_mode_name(m), names[i]) == 0, NULL);
    }
    ag_mode_t m;
    ok("an unknown mode is rejected rather than defaulted",
       !airgap_mode_from_name("off", &m), NULL);
    ok("  and so is an empty one", !airgap_mode_from_name("", &m), NULL);

    char days[32];
    airgap_days_text(0x7F, days, sizeof days);
    ok("every day reads as 'Every day'", strcmp(days, "Every day") == 0, days);
    airgap_days_text(0x3E, days, sizeof days);
    ok("the working week reads as 'Mon-Fri'", strcmp(days, "Mon-Fri") == 0, days);
    airgap_days_text(0x41, days, sizeof days);
    ok("Saturday and Sunday read as 'Weekends'", strcmp(days, "Weekends") == 0, days);
    airgap_days_text(1u << 3, days, sizeof days);
    ok("a single day is named", strcmp(days, "Wed") == 0, days);
}

/* ── the findings from the external review ───────────────────────────── */

static void test_partial_objects(void) {
    puts("\n--- a truncated object gets no hash verdict ---");

    mw_ctx_t m;
    mw_init(&m);
    m.enabled = true;
    m.block   = true;
    m.max_object = 1024;

    /*
     * The trap this guards against: hash the first 1 KB of a larger file,
     * compare that digest against a database of WHOLE-file digests, find
     * nothing, and report "clean". It looks like an inspection, it can
     * never match, and it is a false negative by construction.
     *
     * The body below is built so that its FIRST 1024 bytes have a known
     * digest. If the engine ever hashes the prefix again, that digest is
     * in the database and the test fails loudly.
     */
    char prefix[1024];
    memset(prefix, 'P', sizeof(prefix));
    char prefix_hex[MW_HEXLEN];
    hexof(prefix, sizeof(prefix), prefix_hex);

    FILE *f = fopen(P("p.db"), "w");
    fprintf(f, "%s 4 Prefix.Should.Never.Match\n", prefix_hex);
    fclose(f);
    ok("the prefix digest is in the database", mw_load_hashes(&m, P("p.db")) == 1, NULL);

    char head[128];
    int hl = snprintf(head, sizeof(head),
                      "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n");
    packet_info_t h = mkpkt(head, (size_t)hl, 0);
    mw_scan_packet(&m, &h, NULL);

    char *body = malloc(4096);
    memset(body, 'P', 4096);
    packet_info_t b = mkpkt(body, 4096, 0x01 /* FIN */);
    mw_event_t ev;
    memset(&ev, 0, sizeof(ev));
    mw_verdict_t v = mw_scan_packet(&m, &b, &ev);

    ok("a prefix is NOT compared against whole-file hashes",
       v == MW_CLEAN, ev.name[0] ? ev.name : "(no detection)");
    ok("  it is counted as partial, not as inspected", m.partial == 1, NULL);
    ok("  and not counted among the objects that were inspected",
       m.objects_scanned == 0, NULL);
    free(body);
    mw_shutdown(&m);

    /* Byte patterns are different: a pattern found inside the buffered
     * prefix really was found, so those still report. */
    mw_ctx_t m2;
    mw_init(&m2);
    m2.enabled = true; m2.block = true;
    m2.max_object = 512;
    mw_add_pattern(&m2, (const unsigned char *)"INSIDE-THE-PREFIX", 17,
                   "Test.Pattern", 3, false);

    char h2[128];
    int hl2 = snprintf(h2, sizeof(h2),
                       "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n");
    packet_info_t ph = mkpkt(h2, (size_t)hl2, 0);
    mw_scan_packet(&m2, &ph, NULL);

    char *big = malloc(4096);
    memset(big, 'x', 4096);
    memcpy(big, "INSIDE-THE-PREFIX", 17);
    packet_info_t pb = mkpkt(big, 4096, 0x01);
    memset(&ev, 0, sizeof(ev));
    v = mw_scan_packet(&m2, &pb, &ev);
    ok("a byte pattern inside a truncated object still reports",
       v == MW_BLOCK, ev.name);
    ok("  with no digest claimed for it", ev.sha256[0] == 0, ev.sha256);
    free(big);
    mw_shutdown(&m2);
}

static void test_airgap_modes_count(void) {
    puts("\n--- the modes are enumerable, and there are six ---");

    int n = 0;
    for (int i = 0; i < AG_MODE_MAX; i++) {
        const char *nm = airgap_mode_name((ag_mode_t)i);
        ag_mode_t back;
        if (strcmp(nm, "unknown") && airgap_mode_from_name(nm, &back) &&
            back == (ag_mode_t)i)
            n++;
    }
    ok("every mode has a name that parses back to it", n == AG_MODE_MAX, NULL);
    ok("there are six of them", AG_MODE_MAX == 6, NULL);

    /*
     * The column that decides whether a mode is an air gap or just a
     * strict firewall: may the APPLIANCE itself reach the network?
     */
    struct { ag_mode_t m; bool fetch; } expect[] = {
        { AG_CONNECTED,     true  },
        { AG_OUTBOUND_ONLY, true  },
        { AG_INBOUND_ONLY,  false },
        { AG_ISOLATED,      false },
        { AG_MANUAL,        false },
    };
    int good = 0;
    for (size_t i = 0; i < sizeof expect / sizeof *expect; i++) {
        ag_ctx_t a;
        airgap_init(&a);
        airgap_set_mode(&a, expect[i].m, "test");
        if (airgap_network_permitted(&a, time(NULL), false) == expect[i].fetch)
            good++;
        airgap_shutdown(&a);
    }
    ok("each mode agrees with the documented fetch column",
       good == (int)(sizeof expect / sizeof *expect), NULL);
}

/* ── interfaces ──────────────────────────────────────────────────────── */

static void test_netif(void) {
    puts("\n--- interface inventory ---");

    netif_t list[NETIF_MAX];
    int n = netif_list(list, NETIF_MAX);
    ok("at least the loopback is found", n >= 1, NULL);

    bool saw_lo = false;
    for (int i = 0; i < n; i++)
        if (strcmp(list[i].name, "lo") == 0) { saw_lo = true; break; }
    ok("the loopback is listed", saw_lo, NULL);

    netif_t lo;
    ok("one interface can be fetched by name", netif_get("lo", &lo), NULL);
    ok("  it is classified as loopback", lo.kind == NETIF_KIND_LOOPBACK,
       netif_kind_name(lo.kind));
    ok("  with an MTU", lo.mtu > 0, NULL);
    ok("  and an address", strcmp(lo.ipv4, "127.0.0.1") == 0, lo.ipv4);

    /* Ordering: the loopback goes last, so real ports are at the top. */
    if (n > 1)
        ok("the loopback sorts last", strcmp(list[n-1].name, "lo") == 0,
           list[n-1].name);

    ok("a name that does not exist is reported, not invented",
       !netif_get("definitely-not-here", &lo), NULL);

    /* Name validation -- this guards a path and an ioctl. */
    ok("a normal name passes", netif_name_ok("enp0s3"), NULL);
    ok("a dotted VLAN name passes", netif_name_ok("eth0.100"), NULL);
    ok("an empty name is refused", !netif_name_ok(""), NULL);
    ok("a traversal is refused", !netif_name_ok("../../etc/passwd"), NULL);
    ok("a dot is refused", !netif_name_ok("."), NULL);
    ok("a slash is refused", !netif_name_ok("eth0/x"), NULL);
    ok("a space is refused", !netif_name_ok("eth 0"), NULL);
    ok("a shell metacharacter is refused", !netif_name_ok("eth0;reboot"), NULL);
    ok("an over-long name is refused",
       !netif_name_ok("abcdefghijklmnopqrstuvwxyz"), NULL);
    ok("NULL is refused", !netif_name_ok(NULL), NULL);
}

int main(void) {
    printf("\n=== FireX phase 9: malware protection, air gap, interfaces ===\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/firex-p9-%d", (int)getpid());
    if (mkdir(g_dir, 0700) != 0) { perror("mkdir"); return 1; }

    test_sha256();
    test_database();
    test_detection();
    test_eicar();
    test_limits();
    test_airgap_modes();
    test_airgap_schedule();
    test_airgap_clock();
    test_airgap_names();
    test_partial_objects();
    test_airgap_modes_count();
    test_netif();

    unlink(P("hashes.db"));
    unlink(P("p.db"));
    unlink(P("d.db"));
    rmdir(g_dir);

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
