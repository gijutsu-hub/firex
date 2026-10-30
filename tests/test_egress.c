/*
 * Egress-gate tests: does the appliance's OWN outbound traffic actually
 * pass the air gap?
 *
 * This suite exists because of a specific failure. airgap_network_permitted()
 * was written, documented, and covered by five passing assertions in
 * test_phase9.c -- and nothing in the product ever called it. The README
 * printed a table promising that `isolated` and `manual` stop the appliance
 * fetching signature feeds, and the appliance went on fetching them. Every
 * test was green, because every test called the function directly.
 *
 * So these tests never call the gate. They bind a counting predicate, then
 * drive the four subsystems the way the daemon drives them, and assert that
 * each one ASKED. A test that calls the gate itself proves the gate works;
 * only a test that calls feed_fetch() proves feeds.c knows the gate exists.
 *
 *   make test-egress
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "egress.h"
#include "airgap.h"
#include "feeds.h"
#include "ha.h"
#include "gwmon.h"
#include "telemetry.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-58s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-58s %s\n", what, detail ? detail : ""); fail++; }
}

/* ── a predicate that records who asked ──────────────────────────────── */

static int  g_asked[EGRESS_KIND_MAX];
static bool g_answer = false;

static bool spy(void *arg, egress_kind_t kind, char *why, size_t whylen) {
    (void)arg;
    if (kind >= 0 && kind < EGRESS_KIND_MAX) g_asked[kind]++;
    if (!g_answer && why && whylen) snprintf(why, whylen, "shut for the test");
    return g_answer;
}

static void arm(bool answer) {
    memset(g_asked, 0, sizeof(g_asked));
    g_answer = answer;
    egress_reset_counters();
    egress_bind(spy, NULL);
}

/* ═══ 1. the gate itself ══════════════════════════════════════════════ */

static void test_gate(void) {
    printf("\n[ the gate ]\n");

    egress_bind(NULL, NULL);
    ok("unbound permits",
       egress_permitted(EGRESS_FEEDS, NULL, 0), "a build without an air gap");

    arm(false);
    char why[128] = "";
    ok("a bound refusal is reported",
       !egress_permitted(EGRESS_FEEDS, why, sizeof(why)), why);
    ok("  and carries a reason", why[0] != 0, why);
    ok("  and is counted", egress_refusals(EGRESS_FEEDS) == 1, NULL);

    arm(true);
    ok("a bound permit is not counted",
       egress_permitted(EGRESS_FEEDS, NULL, 0) &&
       egress_refusals(EGRESS_FEEDS) == 0, NULL);

    arm(false);
    ok("an out-of-range kind is refused",
       !egress_permitted((egress_kind_t)EGRESS_KIND_MAX, NULL, 0), NULL);

    ok("kinds are named",
       !strcmp(egress_kind_name(EGRESS_FEEDS), "feeds") &&
       !strcmp(egress_kind_name(EGRESS_GWMON), "gwmon"), NULL);
}

/* ═══ 2. the wiring -- the part that was missing ══════════════════════ */

static void test_feeds_asks(void) {
    printf("\n[ feeds.c ]\n");

    /*
     * A URL that must never be reached. If feeds.c has lost its gate this
     * resolves and connects for real, which is the loudest possible way for
     * the test to tell us -- but we assert on g_asked, not on the result,
     * so a machine with no DNS cannot make a broken build look fixed.
     */
    arm(false);
    char *body = NULL, why[256] = "";
    long n = feed_fetch("https://example.invalid/list.txt", &body, why, sizeof(why));

    ok("feed_fetch asks before reaching the network", g_asked[EGRESS_FEEDS] == 1, NULL);
    ok("  and refuses when the gap is shut", n < 0 && !body, why);
    free(body);

    /*
     * file:// is the way a signature list reaches an isolated appliance:
     * carried in by hand. Gating it would make `manual` mode useless
     * rather than strict, so the gate sits after that branch.
     */
    char path[] = "/tmp/firex_egress_XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) {
        const char *txt = "203.0.113.0/24\n";
        ssize_t w = write(fd, txt, strlen(txt));
        close(fd);
        (void)w;

        char url[320];
        snprintf(url, sizeof(url), "file://%s", path);

        arm(false);
        body = NULL;
        n = feed_fetch(url, &body, why, sizeof(why));
        ok("a file:// list still loads while the gap is shut", n > 0 && body, NULL);
        ok("  and never consults the gate", g_asked[EGRESS_FEEDS] == 0, NULL);
        free(body);
        unlink(path);
    }

    arm(true);
    body = NULL;
    feed_fetch("https://example.invalid/list.txt", &body, why, sizeof(why));
    ok("an open gap lets feeds through to the resolver",
       g_asked[EGRESS_FEEDS] == 1, NULL);
    free(body);
}

static void test_gwmon_asks(void) {
    printf("\n[ gwmon.c ]\n");

    arm(false);
    double rtt = gwmon_ping("203.0.113.1", NULL, 50);
    ok("gwmon_ping asks before probing", g_asked[EGRESS_GWMON] == 1, NULL);
    ok("  and sends nothing when refused", rtt < 0, NULL);
}

static void test_ha_asks(void) {
    printf("\n[ ha.c ]\n");

    ha_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled     = true;
    cfg.config_sync = true;
    cfg.role        = HA_ROLE_PRIMARY;
    cfg.config_sync_port = 8444;
    snprintf(cfg.peer_address, sizeof(cfg.peer_address), "203.0.113.2");
    snprintf(cfg.sync_secret,  sizeof(cfg.sync_secret),  "not-a-real-secret");

    ha_ctx_t h;
    ha_init(&h, &cfg);

    arm(false);
    char why[256] = "";
    int rc = ha_push_config(&h, "/etc/hostname", why, sizeof(why));
    ok("ha_push_config asks before contacting the peer",
       g_asked[EGRESS_HA] == 1, NULL);
    ok("  and refuses with a reason", rc < 0 && why[0], why);

    ha_shutdown(&h);
}

static void test_telemetry_asks(void) {
    printf("\n[ telemetry.c ]\n");

    telemetry_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.syslog_host, sizeof(cfg.syslog_host), "203.0.113.3");
    cfg.syslog_port = 514;
    cfg.syslog_min_severity = SYSLOG_INFO;

    /*
     * Refused at init, so the collector socket is never even opened. This
     * is the case that a connect-time-only gate would have got right and a
     * send-time-only gate would have missed.
     */
    arm(false);
    telemetry_ctx_t t;
    telemetry_init(&t, &cfg);
    ok("telemetry_init asks before connecting", g_asked[EGRESS_TELEMETRY] >= 1, NULL);
    ok("  and opens no collector socket", t.syslog_fd < 0, NULL);

    int before = g_asked[EGRESS_TELEMETRY];
    telemetry_log(&t, SYSLOG_WARNING, "TEST", "a message that must not leave");
    ok("every syslog write asks too",
       g_asked[EGRESS_TELEMETRY] == before + 1, NULL);
    ok("  and the message counts as dropped", t.syslog_dropped >= 1, NULL);

    telemetry_shutdown(&t);
}

/* ═══ 3. the air gap is what answers ══════════════════════════════════ */

static void test_airgap_is_bound(void) {
    printf("\n[ airgap_bind_egress ]\n");

    ag_ctx_t a;
    airgap_init(&a);
    airgap_bind_egress(&a);

    airgap_set_mode(&a, AG_CONNECTED, "test");
    ok("connected: the appliance may fetch",
       egress_permitted(EGRESS_FEEDS, NULL, 0), NULL);

    char why[160] = "";
    airgap_set_mode(&a, AG_ISOLATED, "test");
    ok("isolated: it may not",
       !egress_permitted(EGRESS_FEEDS, why, sizeof(why)), why);
    ok("  and the reason names the mode and the subsystem",
       strstr(why, "isolated") && strstr(why, "feeds"), why);

    airgap_set_mode(&a, AG_MANUAL, "test");
    ok("manual: it may not",
       !egress_permitted(EGRESS_TELEMETRY, NULL, 0), NULL);

    airgap_set_mode(&a, AG_INBOUND_ONLY, "test");
    ok("inbound-only: fetching means talking out, so no",
       !egress_permitted(EGRESS_FEEDS, NULL, 0), NULL);

    airgap_set_mode(&a, AG_OUTBOUND_ONLY, "test");
    ok("outbound-only: yes",
       egress_permitted(EGRESS_FEEDS, NULL, 0), NULL);

    /*
     * The counter the console shows. It stayed at zero for the entire life
     * of the un-wired version, which is precisely why a dashboard tile is
     * not evidence that a control is running.
     */
    ok("refusals reach the air gap's own counter",
       a.blocked_fetches > 0, NULL);

    airgap_bind_egress(NULL);
    ok("unbinding restores plain behaviour",
       egress_permitted(EGRESS_FEEDS, NULL, 0), NULL);

    airgap_shutdown(&a);
}

int main(void) {
    printf("=== FireX egress gate ===\n");

    test_gate();
    test_feeds_asks();
    test_gwmon_asks();
    test_ha_asks();
    test_telemetry_asks();
    test_airgap_is_bound();

    egress_bind(NULL, NULL);
    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
