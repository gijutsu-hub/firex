/*
 * End-to-end test for the XDP backend.
 * Expects a veth pair: fwtest0 in the root namespace (where the program is
 * attached) and fwtest1 inside netns "fwtest", which generates the traffic.
 * Must run as root.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "firewall.h"
#include "xdp_filter.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail)
{
    if (cond) { printf("  PASS  %-44s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-44s %s\n", what, detail ? detail : ""); fail++; }
}

static void nap(double sec)
{
    struct timespec ts = { (time_t)sec, (long)((sec - (long)sec) * 1e9) };
    nanosleep(&ts, NULL);
}

/* Returns 0 when the ping got replies. */
static int do_ping(void)
{
    return system("ip netns exec fwtest ping -c 3 -i 0.3 -W 1 10.77.0.1 "
                  ">/dev/null 2>&1");
}

int main(void)
{
    firewall_ctx_t *ctx = fw_create();
    if (!ctx) { puts("fw_create failed"); return 1; }

    snprintf(ctx->interface, MAX_IFACE_NAME, "fwtest0");
    ctx->default_policy = ACTION_ALLOW;

    /* Block ICMP */
    fw_rule_t r;
    memset(&r, 0, sizeof(r));
    r.type = RULE_PROTOCOL;
    r.action = ACTION_BLOCK;
    r.protocol = IPPROTO_ICMP;
    r.priority = 10;
    r.enabled = true;
    snprintf(r.description, MAX_DESC_LEN, "Block ICMP (xdp test)");
    int icmp_rule = fw_add_rule(ctx, &r);

    /* A DPI rule the kernel cannot take, to check it is reported */
    memset(&r, 0, sizeof(r));
    r.type = RULE_DPI_REGEX;
    r.action = ACTION_BLOCK;
    r.priority = 50;
    r.enabled = true;
    snprintf(r.regex_pattern, MAX_REGEX_LEN, "%s", "SELECT.*FROM");
    snprintf(r.description, MAX_DESC_LEN, "SQLi (not offloadable)");
    fw_add_rule(ctx, &r);

    printf("Starting XDP engine on fwtest0...\n");
    if (xdp_engine_start(ctx) != 0) {
        printf("  START FAILED: %s\n", xdp_engine_status());
        fw_destroy(ctx);
        return 1;
    }
    printf("  status: %s\n\n", xdp_engine_status());

    ok("engine reports running", ctx->running, NULL);
    ok("status mentions the DPI rule was not offloaded",
       strstr(xdp_engine_status(), "DPI") != NULL, NULL);

    /* ---- ICMP should be dropped ---- */
    int rc = do_ping();
    nap(2.0);   /* let the poll thread sync stats */
    fw_stats_t s1 = fw_get_stats(ctx);

    char buf[128];
    snprintf(buf, sizeof(buf), "(ping rc=%d)", rc);
    ok("ping is blocked while the ICMP rule is on", rc != 0, buf);

    snprintf(buf, sizeof(buf), "(%lu packets, %lu blocked)",
             s1.total_packets, s1.blocked);
    ok("BPF stats map reports traffic", s1.total_packets > 0, buf);
    ok("BPF stats map reports drops", s1.blocked > 0, buf);
    ok("ICMP counter moved", s1.icmp_count > 0, NULL);

    int logs = 0;
    fw_get_logs(ctx, &logs);
    snprintf(buf, sizeof(buf), "(%d entries)", logs);
    ok("ring buffer events reached the log", logs > 0, buf);

    /* ---- disable the rule: traffic should flow, live ---- */
    fw_toggle_rule(ctx, icmp_rule, false);
    nap(2.0);   /* the loader re-syncs on the generation counter */

    rc = do_ping();
    snprintf(buf, sizeof(buf), "(ping rc=%d)", rc);
    ok("ping succeeds after disabling the rule live", rc == 0, buf);

    nap(1.5);
    fw_stats_t s2 = fw_get_stats(ctx);
    snprintf(buf, sizeof(buf), "(%lu -> %lu allowed)", s1.allowed, s2.allowed);
    ok("allowed counter advanced", s2.allowed > s1.allowed, buf);

    /* ---- re-enable: blocked again ---- */
    fw_toggle_rule(ctx, icmp_rule, true);
    nap(2.0);
    rc = do_ping();
    snprintf(buf, sizeof(buf), "(ping rc=%d)", rc);
    ok("ping blocked again after re-enabling", rc != 0, buf);

    printf("\nStopping engine...\n");
    xdp_engine_stop(ctx);
    ok("engine stopped", !ctx->running, NULL);

    /* The program must be gone from the interface */
    int still = system("ip link show fwtest0 2>/dev/null | grep -q xdp");
    ok("XDP program detached from the interface", still != 0, NULL);

    rc = do_ping();
    snprintf(buf, sizeof(buf), "(ping rc=%d)", rc);
    ok("traffic flows again after detach", rc == 0, buf);

    fw_destroy(ctx);
    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
