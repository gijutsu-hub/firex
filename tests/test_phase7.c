/*
 * Phase 7 tests: the Aho-Corasick matcher, signature parsing and scanning,
 * blocklist range merging and lookups, and automatic response scoring.
 *
 * The matcher is checked against the canonical worked example from the
 * original paper, because a multi-pattern automaton that is subtly wrong
 * silently stops detecting things.
 *   make test-phase7
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "inspect.h"
#include "enterprise.h"
#include "reload.h"
#include "ids.h"
#include "feeds.h"
#include "response.h"
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
static const char *tpath(const char *name) {
    static char pool[4][512];
    static int idx;
    char *b = pool[idx++ % 4];
    snprintf(b, 512, "%s/%s", tmpdir, name);
    return b;
}

/* ═══════════════════ the matcher ═══════════════════ */

struct collected { int sig[64]; int end[64]; int n; };

static void collect(int sig, int end, void *user) {
    struct collected *c = user;
    if (c->n < 64) { c->sig[c->n] = sig; c->end[c->n] = end; c->n++; }
}

static bool got(const struct collected *c, int sig, int end) {
    for (int i = 0; i < c->n; i++)
        if (c->sig[i] == sig && c->end[i] == end) return true;
    return false;
}

static void test_matcher(void) {
    puts("\n-- multi-pattern matching --");

    /* The worked example from Aho and Corasick, 1975. */
    static const char *P[] = { "he", "she", "his", "hers" };
    ac_t a;
    ac_init(&a);
    for (int i = 0; i < 4; i++)
        ok("pattern added", ac_add(&a, (const unsigned char *)P[i],
                                   (int)strlen(P[i]), i) == 0, P[i]);

    struct collected c = { .n = 0 };
    ok("searching before build finds nothing",
       ac_search(&a, (const unsigned char *)"ushers", 6, collect, &c) == 0, NULL);

    ac_build(&a);
    c.n = 0;
    int n = ac_search(&a, (const unsigned char *)"ushers", 6, collect, &c);

    ok("the canonical example finds three matches", n == 3, NULL);
    ok("\"she\" is found at 1..3", got(&c, 1, 3), NULL);
    /* "he" is a suffix of "she": finding it is what the output links exist
     * for, and missing it is the classic way to get this wrong. */
    ok("\"he\" inside \"she\" is also found", got(&c, 0, 3), NULL);
    ok("\"hers\" is found at 2..5", got(&c, 3, 5), NULL);
    ok("\"his\" is not found", !got(&c, 2, -1) && c.n == 3, NULL);

    c.n = 0;
    ac_search(&a, (const unsigned char *)"hehehers", 8, collect, &c);
    ok("repeated and overlapping matches are all reported", c.n == 4, NULL);

    c.n = 0;
    ok("text with no match reports none",
       ac_search(&a, (const unsigned char *)"xyzzy", 5, collect, &c) == 0, NULL);
    ok("an empty text is safe",
       ac_search(&a, (const unsigned char *)"", 0, collect, &c) == 0, NULL);
    ok("a null text is safe", ac_search(&a, NULL, 10, collect, &c) == 0, NULL);
    ok("an empty pattern is refused",
       ac_add(&a, (const unsigned char *)"", 0, 9) < 0, NULL);
    ok("prefixes are shared, not duplicated", a.count == 10, NULL);
    ac_free(&a);

    /* Binary patterns: a signature is bytes, not text. */
    ac_t b;
    ac_init(&b);
    const unsigned char nul[] = { 0x00, 0xff, 0x90, 0x00 };
    const unsigned char hay[] = { 0x41, 0x00, 0xff, 0x90, 0x00, 0x42 };
    ac_add(&b, nul, 4, 0);
    ac_build(&b);
    c.n = 0;
    ok("a pattern containing NUL and high bytes matches",
       ac_search(&b, hay, 6, collect, &c) == 1 && got(&c, 0, 4), NULL);
    ac_free(&b);

    /* A pattern at either edge of the text. */
    ac_t e;
    ac_init(&e);
    ac_add(&e, (const unsigned char *)"abc", 3, 0);
    ac_build(&e);
    c.n = 0;
    ac_search(&e, (const unsigned char *)"abcxxx", 6, collect, &c);
    ok("a match at the very start is found", got(&c, 0, 2), NULL);
    c.n = 0;
    ac_search(&e, (const unsigned char *)"xxxabc", 6, collect, &c);
    ok("a match at the very end is found", got(&c, 0, 5), NULL);
    c.n = 0;
    ac_search(&e, (const unsigned char *)"ababc", 5, collect, &c);
    ok("a match after a false start is found", got(&c, 0, 4), NULL);
    ac_free(&e);
}

/* ═══════════════════ rule parsing ═══════════════════ */

static void test_rules(void) {
    puts("\n-- rule parsing --");

    ids_sig_t s;
    char why[192];

    const char *rule =
        "alert tcp any any -> any 80 (msg:\"Admin probe\"; content:\"GET /admin\"; "
        "nocase; offset:0; depth:64; class:recon; severity:3; sid:42; rev:2; "
        "reference:\"internal\";)";

    ok("a full rule parses", ids_parse_rule(rule, &s, why, sizeof(why)) == 0, why);
    ok("the action is read", s.action == SIG_ALERT, NULL);
    ok("the protocol is read", s.protocol == 6, NULL);
    ok("the destination port is read", s.dst_port == 80, NULL);
    ok("'any' means any port", s.src_port == 0, NULL);
    ok("the message is read", !strcmp(s.msg, "Admin probe"), s.msg);
    ok("the content is read",
       s.content_len == 10 && !memcmp(s.content, "GET /admin", 10), NULL);
    ok("nocase is read", s.nocase, NULL);
    ok("depth is read", s.depth == 64, NULL);
    ok("the class is read", s.cls == SIG_CLASS_RECON, NULL);
    ok("the severity is read", s.severity == 3, NULL);
    ok("the sid is read", s.sid == 42, NULL);
    ok("the revision is read", s.rev == 2, NULL);
    ok("the reference is read", !strcmp(s.reference, "internal"), s.reference);

    ok("a drop rule parses as drop",
       ids_parse_rule("drop udp any any -> any any (msg:\"x\"; content:\"y\"; "
                      "sid:1;)", &s, why, sizeof(why)) == 0 &&
       s.action == SIG_DROP && s.protocol == 17, why);
    ok("a reject rule parses as reject",
       ids_parse_rule("reject ip any any -> any any (msg:\"x\"; content:\"y\"; "
                      "sid:2;)", &s, why, sizeof(why)) == 0 &&
       s.action == SIG_REJECT && s.protocol == 0, why);

    /* Hex content, and hex mixed with text. */
    ok("hex content decodes",
       ids_parse_rule("alert tcp any any -> any any (msg:\"n\"; "
                      "content:\"|90 90 90 90|\"; sid:3;)", &s,
                      why, sizeof(why)) == 0 &&
       s.content_len == 4 && s.content[0] == 0x90 && s.content[3] == 0x90, why);
    ok("hex without spaces decodes",
       ids_parse_rule("alert tcp any any -> any any (msg:\"n\"; "
                      "content:\"|deadbeef|\"; sid:4;)", &s,
                      why, sizeof(why)) == 0 &&
       s.content_len == 4 && s.content[0] == 0xde && s.content[3] == 0xef, why);
    /* No literal spaces around the hex block, so the byte count is not
     * ambiguous: G E T + 0x20 + / is five bytes. */
    ok("text and hex mix",
       ids_parse_rule("alert tcp any any -> any any (msg:\"n\"; "
                      "content:\"GET|20|/\"; sid:5;)", &s,
                      why, sizeof(why)) == 0 &&
       s.content_len == 5 && s.content[3] == 0x20 && s.content[4] == '/', why);

    /* malformed */
    ok("a rule with no content is refused",
       ids_parse_rule("alert tcp any any -> any any (msg:\"x\"; sid:6;)",
                      &s, why, sizeof(why)) != 0, why);
    ok("a rule with no sid is refused",
       ids_parse_rule("alert tcp any any -> any any (msg:\"x\"; content:\"y\";)",
                      &s, why, sizeof(why)) != 0, why);
    ok("an unknown action is refused",
       ids_parse_rule("permit tcp any any -> any any (content:\"y\"; sid:7;)",
                      &s, why, sizeof(why)) != 0, why);
    ok("an unknown protocol is refused",
       ids_parse_rule("alert sctp any any -> any any (content:\"y\"; sid:8;)",
                      &s, why, sizeof(why)) != 0, why);
    ok("a missing arrow is refused",
       ids_parse_rule("alert tcp any any <- any any (content:\"y\"; sid:9;)",
                      &s, why, sizeof(why)) != 0, why);
    ok("a missing option block is refused",
       ids_parse_rule("alert tcp any any -> any any", &s, why, sizeof(why)) != 0,
       why);
    ok("an unterminated hex block is refused",
       ids_parse_rule("alert tcp any any -> any any (content:\"|90 90\"; "
                      "sid:10;)", &s, why, sizeof(why)) != 0, why);
    ok("an odd number of hex digits is refused",
       ids_parse_rule("alert tcp any any -> any any (content:\"|909|\"; "
                      "sid:11;)", &s, why, sizeof(why)) != 0, why);
    ok("a non-hex digit inside a hex block is refused",
       ids_parse_rule("alert tcp any any -> any any (content:\"|zz|\"; "
                      "sid:12;)", &s, why, sizeof(why)) != 0, why);

    /* A depth smaller than the pattern can never match, which is a mistake
     * worth catching at load rather than puzzling over later. */
    ok("a depth too small for its pattern is refused",
       ids_parse_rule("alert tcp any any -> any any (content:\"abcdefgh\"; "
                      "depth:4; sid:13;)", &s, why, sizeof(why)) != 0, why);
    ok("the reason says the rule could never match",
       strstr(why, "never match") != NULL, why);

    ok("severity above 4 is clamped",
       ids_parse_rule("alert tcp any any -> any any (content:\"y\"; "
                      "severity:99; sid:14;)", &s, why, sizeof(why)) == 0 &&
       s.severity == 4, why);
}

/* ═══════════════════ scanning ═══════════════════ */

static void add(ids_ctx_t *c, const char *rule) {
    ids_sig_t s;
    char why[192];
    if (ids_parse_rule(rule, &s, why, sizeof(why)) == 0) ids_add(c, &s);
    else fprintf(stderr, "  (test rule rejected: %s)\n", why);
}

static void test_scanning(void) {
    puts("\n-- scanning --");

    ids_ctx_t c;
    ids_init(&c);

    add(&c, "alert tcp any any -> any 80 (msg:\"plain\"; content:\"SECRET\"; "
            "class:policy; severity:1; sid:100;)");
    add(&c, "alert tcp any any -> any any (msg:\"folded\"; content:\"eicar\"; "
            "nocase; class:malware; severity:2; sid:101;)");
    add(&c, "drop tcp any any -> any any (msg:\"serious\"; content:\"${jndi:\"; "
            "class:exploit; severity:4; sid:102;)");
    add(&c, "alert tcp any any -> any any (msg:\"windowed\"; content:\"HEAD\"; "
            "offset:0; depth:8; class:recon; severity:2; sid:103;)");
    add(&c, "alert udp any any -> any 53 (msg:\"dns only\"; content:\"evil\"; "
            "class:c2; severity:3; sid:104;)");

    c.enabled = true;
    c.inline_mode = true;
    ok("the ruleset compiles", ids_compile(&c) == 0, NULL);

    ids_hit_t h[8];
    #define SCAN(p, proto, dp) \
        ids_scan(&c, (const unsigned char *)(p), (int)strlen(p), proto, 1234, dp, h, 8)

    ok("an exact pattern matches", SCAN("xx SECRET xx", 6, 80) == 1, NULL);
    ok("it respects the port", SCAN("xx SECRET xx", 6, 443) == 0, NULL);
    ok("a nocase pattern matches any case",
       SCAN("EiCaR", 6, 80) == 1 && SCAN("eicar", 6, 80) == 1 &&
       SCAN("EICAR", 6, 80) == 1, NULL);
    ok("a protocol filter is honoured",
       SCAN("evil", 17, 53) == 1 && SCAN("evil", 6, 53) == 0, NULL);

    ok("a windowed pattern matches inside its window",
       SCAN("HEAD / HTTP", 6, 80) == 1, NULL);
    ok("and not outside it",
       SCAN("........................HEAD / HTTP", 6, 80) == 0, NULL);

    ok("benign traffic matches nothing", SCAN("hello world", 6, 80) == 0, NULL);
    ok("an empty payload is safe", ids_scan(&c, (const unsigned char *)"", 0,
                                            6, 1, 80, h, 8) == 0, NULL);

    /* Several hits in one payload, worst first. */
    int n = SCAN("SECRET and ${jndi:ldap://x} and eicar", 6, 80);
    ok("multiple signatures hit one payload", n == 3, NULL);
    ok("the worst is reported first", n == 3 && h[0].severity == 4 &&
       h[0].sid == 102, NULL);
    ok("severity descends", n == 3 && h[0].severity >= h[1].severity &&
       h[1].severity >= h[2].severity, NULL);

    /* A signature that matches twice in one packet reports once. */
    ok("a repeated pattern reports a single hit",
       SCAN("eicar eicar eicar", 6, 80) == 1, NULL);

    ok("the verdict is the worst action",
       SCAN("SECRET ${jndi:x}", 6, 80) == 2 &&
       ids_verdict(&c, h, 2) == SIG_DROP, NULL);

    /* Out of inline mode a drop rule only reports: that is how a new
     * ruleset is deployed without taking the network down. */
    c.inline_mode = false;
    ok("alert-only mode downgrades a drop to an alert",
       SCAN("${jndi:x}", 6, 80) == 1 &&
       ids_verdict(&c, h, 1) == SIG_ALERT, NULL);
    c.inline_mode = true;

    c.enabled = false;
    ok("a disabled engine scans nothing", SCAN("${jndi:x}", 6, 80) == 0, NULL);
    c.enabled = true;

    ok("hits are counted on the signature",
       c.sigs[2].hits > 0 && c.sigs[2].last_hit > 0, NULL);

    ok("a duplicate sid is refused", ({
        ids_sig_t d;
        char w[128];
        ids_parse_rule("alert tcp any any -> any any (content:\"z\"; sid:100;)",
                       &d, w, sizeof(w));
        ids_add(&c, &d) != 0; }), NULL);

    #undef SCAN
    ids_shutdown(&c);
}

/* ═══════════════════ blocklists ═══════════════════ */

static void test_feeds(void) {
    puts("\n-- blocklist ranges --");

    uint32_t lo, hi;
    ok("a CIDR parses",
       feed_parse_cidr("10.0.0.0/8", &lo, &hi) &&
       lo == 0x0a000000 && hi == 0x0affffff, NULL);
    ok("a bare address is a single host",
       feed_parse_cidr("1.2.3.4", &lo, &hi) && lo == hi, NULL);
    ok("/32 is a single host",
       feed_parse_cidr("1.2.3.4/32", &lo, &hi) && lo == hi, NULL);
    ok("/0 is everything",
       feed_parse_cidr("0.0.0.0/0", &lo, &hi) &&
       lo == 0 && hi == 0xffffffff, NULL);
    ok("host bits are masked off",
       feed_parse_cidr("10.1.2.3/24", &lo, &hi) && lo == 0x0a010200, NULL);
    ok("a trailing comment is ignored",
       feed_parse_cidr("10.0.0.0/8 # a comment", &lo, &hi) &&
       lo == 0x0a000000, NULL);
    ok("a bad address is refused", !feed_parse_cidr("999.1.1.1", &lo, &hi), NULL);
    ok("a bad prefix is refused", !feed_parse_cidr("10.0.0.0/33", &lo, &hi), NULL);
    ok("a non-numeric prefix is refused",
       !feed_parse_cidr("10.0.0.0/abc", &lo, &hi), NULL);
    ok("an empty string is refused", !feed_parse_cidr("", &lo, &hi), NULL);

    /* Merging is where a range table goes wrong. */
    feed_range_t r[8];

    r[0] = (feed_range_t){ 10, 20 };
    r[1] = (feed_range_t){ 15, 25 };
    ok("overlapping ranges merge",
       feed_merge_ranges(r, 2) == 1 && r[0].lo == 10 && r[0].hi == 25, NULL);

    r[0] = (feed_range_t){ 1, 5 };
    r[1] = (feed_range_t){ 6, 9 };
    ok("adjacent ranges merge",
       feed_merge_ranges(r, 2) == 1 && r[0].lo == 1 && r[0].hi == 9, NULL);

    r[0] = (feed_range_t){ 1, 5 };
    r[1] = (feed_range_t){ 8, 9 };
    ok("disjoint ranges stay apart", feed_merge_ranges(r, 2) == 2, NULL);

    r[0] = (feed_range_t){ 1, 100 };
    r[1] = (feed_range_t){ 10, 20 };
    ok("a nested range is absorbed",
       feed_merge_ranges(r, 2) == 1 && r[0].hi == 100, NULL);

    r[0] = (feed_range_t){ 50, 60 };
    r[1] = (feed_range_t){ 10, 20 };
    r[2] = (feed_range_t){ 30, 40 };
    ok("unsorted input is sorted and kept apart",
       feed_merge_ranges(r, 3) == 3 && r[0].lo == 10 && r[2].lo == 50, NULL);

    /* The top of the address space must not wrap when testing adjacency. */
    r[0] = (feed_range_t){ 0xfffffff0u, 0xffffffffu };
    r[1] = (feed_range_t){ 1, 2 };
    ok("adjacency at the top of the space does not wrap",
       feed_merge_ranges(r, 2) == 2, NULL);

    ok("one range is left alone", feed_merge_ranges(r, 1) == 1, NULL);
    ok("zero ranges is safe", feed_merge_ranges(r, 0) == 0, NULL);

    puts("\n-- blocklist lookups --");

    feeds_ctx_t f;
    feeds_init(&f);
    f.enabled = true;

    feed_t fd;
    memset(&fd, 0, sizeof(fd));
    snprintf(fd.name, FEED_NAME_LEN, "test-ip");
    snprintf(fd.url, FEED_URL_LEN, "file:///dev/null");
    fd.kind = FEED_IP;
    fd.enabled = true;
    fd.refresh_minutes = 60;
    ok("a feed is accepted", feeds_add(&f, &fd) == 0, NULL);
    ok("the same name twice is refused", feeds_add(&f, &fd) != 0, NULL);

    const char *list =
        "# a comment line\n"
        "203.0.113.0/24\n"
        "198.51.100.5\n"
        "10.0.0.0/8   trailing junk\n"
        "\n"
        "not-an-address\n";
    ok("a list body loads", feeds_load_body(&f, 0, list, strlen(list)) == 3, NULL);

    ok("an address inside a range matches",
       feeds_match_ip(&f, ip("203.0.113.77")), NULL);
    ok("a single-host entry matches",
       feeds_match_ip(&f, ip("198.51.100.5")), NULL);
    ok("its neighbour does not",
       !feeds_match_ip(&f, ip("198.51.100.6")), NULL);
    ok("a large range matches",
       feeds_match_ip(&f, ip("10.254.254.254")), NULL);
    ok("an address outside every range does not match",
       !feeds_match_ip(&f, ip("8.8.8.8")), NULL);
    ok("the junk line was skipped, not mangled",
       !feeds_match_ip(&f, ip("0.0.0.0")), NULL);
    ok("lookups are counted", f.lookups >= 6 && f.ip_hits == 3, NULL);

    /* ── domains ── */
    feed_t dfd;
    memset(&dfd, 0, sizeof(dfd));
    snprintf(dfd.name, FEED_NAME_LEN, "test-domain");
    snprintf(dfd.url, FEED_URL_LEN, "file:///dev/null");
    dfd.kind = FEED_DOMAIN;
    dfd.enabled = true;
    dfd.refresh_minutes = 60;
    feeds_add(&f, &dfd);

    const char *dlist =
        "# hosts-file style and bare names both work\n"
        "0.0.0.0 ads.example\n"
        "evil.test\n"
        "TRACKER.Example\n";
    ok("a domain list loads",
       feeds_load_body(&f, 1, dlist, strlen(dlist)) == 3, NULL);

    ok("an exact domain matches", feeds_match_domain(&f, "evil.test"), NULL);
    ok("a hosts-file entry matches", feeds_match_domain(&f, "ads.example"), NULL);
    ok("matching is case-insensitive",
       feeds_match_domain(&f, "TRACKER.EXAMPLE"), NULL);
    /* One entry should cover the subtree beneath it. */
    ok("a subdomain of a listed name matches",
       feeds_match_domain(&f, "a.b.evil.test"), NULL);
    ok("a trailing root dot is tolerated",
       feeds_match_domain(&f, "evil.test."), NULL);
    ok("a port suffix is stripped",
       feeds_match_domain(&f, "evil.test:8080"), NULL);
    ok("an unrelated name does not match",
       !feeds_match_domain(&f, "example.com"), NULL);
    /*
     * The parent walk advances past a dot, so it only ever tests whole
     * labels: "notevil.test" tries "notevil.test" then "test", never
     * "evil.test". A substring match here would block half the internet.
     */
    ok("a name that merely ends in a listed name does not match",
       !feeds_match_domain(&f, "notevil.test"), NULL);
    ok("nor does one that contains it without a label boundary",
       !feeds_match_domain(&f, "xevil.test"), NULL);
    ok("but a real label boundary still matches",
       feeds_match_domain(&f, "x.evil.test"), NULL);
    ok("an empty name is safe", !feeds_match_domain(&f, ""), NULL);

    feeds_shutdown(&f);

    puts("\n-- fetching --");

    const char *lp = tpath("list.txt");
    FILE *w = fopen(lp, "w");
    fprintf(w, "192.0.2.0/24\n203.0.113.0/24\n");
    fclose(w);

    char url[640], why[192];
    snprintf(url, sizeof(url), "file://%s", lp);
    char *body = NULL;
    long n = feed_fetch(url, &body, why, sizeof(why));
    ok("a file:// URL is fetched", n > 0 && body, why);
    ok("its contents arrive", body && strstr(body, "192.0.2.0/24") != NULL, NULL);
    free(body);

    ok("a missing file is reported",
       feed_fetch("file:///no/such/list", &body, why, sizeof(why)) < 0, why);
    ok("an unsupported scheme is refused",
       feed_fetch("ftp://example.com/list", &body, why, sizeof(why)) < 0, why);
    ok("a URL with no host is refused",
       feed_fetch("https://", &body, why, sizeof(why)) < 0, why);
}

/* ═══════════════════ automatic response ═══════════════════ */

static void test_response(void) {
    puts("\n-- automatic response --");

    ok("severity drives the score",
       response_score_for(4) == 10 && response_score_for(3) == 5 &&
       response_score_for(2) == 2 && response_score_for(1) == 1, NULL);

    response_ctx_t r;
    response_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = true;
    cfg.threshold = 10;
    cfg.block_minutes = 15;
    cfg.escalate = true;
    cfg.max_block_minutes = 60;
    cfg.decay_minutes = 30;
    cfg.quarantine = true;
    response_init(&r, &cfg, false);   /* false: never touch ipset */

    uint32_t host = ip("10.10.30.5");

    /* A single low-severity detection must not block anything. */
    ok("one minor detection does not block",
       !response_record(&r, host, 1, "minor") &&
       !response_is_blocked(&r, host), NULL);
    for (int i = 0; i < 8; i++) response_record(&r, host, 1, "minor");
    ok("nine minor detections still do not", !response_is_blocked(&r, host), NULL);
    ok("the tenth does", response_record(&r, host, 1, "minor") &&
       response_is_blocked(&r, host), NULL);

    /* A serious one should not need ten repeats. */
    uint32_t bad = ip("10.10.30.9");
    ok("one serious detection blocks on its own",
       response_record(&r, bad, 4, "log4shell") &&
       response_is_blocked(&r, bad), NULL);

    ok("a quarantined host is reclassified",
       response_zone_for(&r, bad) == ZONE_QUARANTINE, NULL);
    ok("an innocent host is not",
       response_zone_for(&r, ip("10.10.30.200")) == ZONE_MAX, NULL);

    /* Blocking is reported once, not on every packet after. */
    ok("a further detection does not re-report the block",
       !response_record(&r, bad, 4, "again"), NULL);

    offender_t snap[16];
    int n = response_snapshot(&r, snap, 16);
    ok("offenders are listed", n == 2, NULL);

    /* Escalation. */
    time_t now = time(NULL);
    ok("the block expires when its time is up",
       response_reap(&r, now + 16 * 60) >= 1 &&
       !response_is_blocked(&r, bad), NULL);

    response_record(&r, bad, 4, "back again");
    n = response_snapshot(&r, snap, 16);
    offender_t *o = NULL;
    for (int i = 0; i < n; i++) if (snap[i].ip == bad) o = &snap[i];
    ok("a repeat offender is blocked again", o && o->blocked_until > 0, NULL);
    ok("and held for longer the second time",
       o && o->blocked_until - time(NULL) > 15 * 60, NULL);
    ok("escalation is counted", r.escalations >= 1, NULL);

    /* The ceiling must hold. */
    for (int i = 0; i < 6; i++) {
        response_reap(&r, time(NULL) + 7200);
        response_record(&r, bad, 4, "persistent");
    }
    n = response_snapshot(&r, snap, 16);
    o = NULL;
    for (int i = 0; i < n; i++) if (snap[i].ip == bad) o = &snap[i];
    ok("escalation is capped",
       o && o->blocked_until - time(NULL) <= (time_t)cfg.max_block_minutes * 60,
       NULL);

    ok("a host can be released by hand",
       response_release(&r, bad) == 0 && !response_is_blocked(&r, bad), NULL);
    ok("releasing an unknown host fails",
       response_release(&r, ip("1.1.1.1")) != 0, NULL);

    /* Decay: a quiet host should drift back toward zero. */
    uint32_t quiet = ip("10.10.30.77");
    response_record(&r, quiet, 3, "once");
    response_reap(&r, time(NULL) + 31 * 60);
    n = response_snapshot(&r, snap, 16);
    o = NULL;
    for (int i = 0; i < n; i++) if (snap[i].ip == quiet) o = &snap[i];
    ok("an idle score decays", o && o->score < 5, NULL);

    response_shutdown(&r);

    /* Disabled must do nothing at all. */
    response_ctx_t off;
    response_cfg_t offcfg;
    memset(&offcfg, 0, sizeof(offcfg));
    response_init(&off, &offcfg, false);
    ok("a disabled responder records nothing",
       !response_record(&off, host, 4, "x") && !response_is_blocked(&off, host),
       NULL);
    ok("and never quarantines",
       response_zone_for(&off, host) == ZONE_MAX, NULL);
    response_shutdown(&off);
}

/* ═══════════════════ validation ═══════════════════ */

static void test_validation(void) {
    puts("\n-- validation --");

    cfg_validate_t res;
    char localcfg[512];
    snprintf(localcfg, sizeof(localcfg), "%s/local.conf", tmpdir);

    /* Rewrite the shipped config so its file:// paths resolve here. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "sed 's|file:///etc/firex/blocklist.txt|file://%s/config/blocklist.txt|; "
             "s|/etc/firex/rules.ids|%s/config/rules.ids|' config/firex.conf > %s",
             getenv("PWD") ? getenv("PWD") : ".",
             getenv("PWD") ? getenv("PWD") : ".", localcfg);
    if (system(cmd) != 0) { ok("could rewrite the shipped config", 0, NULL); return; }

    ok("the shipped config, now with a threat layer, validates",
       firex_validate_file(localcfg, &res) == 0, res.error);
    ok("alert-only mode is warned about",
       res.warnings > 0, res.warning);
    ok("the lab config still validates",
       firex_validate_file("config/firex-qemu.conf", &res) == 0, res.error);
}

int main(void) {
    snprintf(tmpdir, sizeof(tmpdir), "/tmp/firex-p7-XXXXXX");
    if (!mkdtemp(tmpdir)) { perror("mkdtemp"); return 1; }

    test_matcher();
    test_rules();
    test_scanning();
    test_feeds();
    test_response();
    test_validation();

    printf("\n%d passed, %d failed\n", pass, fail);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
    if (system(cmd) != 0) fprintf(stderr, "note: could not clean %s\n", tmpdir);

    return fail ? 1 : 0;
}
