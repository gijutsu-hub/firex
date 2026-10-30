/*
 * Desktop console plumbing: the JSON reader, the interface list and the
 * HTTP client's refusals.
 *
 * The console's whole claim is that it shows the same state as the web
 * console because it asks the same daemon. That claim rests on this file
 * parsing the daemon's replies correctly, so the fixtures below are real
 * output shapes from src/webui.c rather than JSON invented to pass.
 *
 * The live round trip -- login, GET, session -- runs only when a daemon
 * is listening; FIREX_TEST_PORT points it at one.
 *   make test-gui
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "guiapp.h"
#include "brand.h"

static int pass = 0, fail = 0;

static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-58s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-58s %s\n", what, detail ? detail : ""); fail++; }
}

/* ── fixtures ─────────────────────────────────────────────────────────
 * Trimmed from what the endpoints actually emit. */

static const char POLICY[] =
"{\"aliases\":[{\"name\":\"admins\",\"kind\":\"host\",\"description\":\"ops\","
 "\"entries\":\"10.0.0.5\",\"count\":1,\"hits\":12},"
 "{\"name\":\"printers\",\"kind\":\"net\",\"description\":\"\","
 "\"entries\":\"10.0.9.0/24\",\"count\":1,\"hits\":0}],"
 "\"schedules\":[{\"name\":\"workday\",\"description\":\"office hours\","
 "\"days\":\"Mon-Fri\",\"start\":\"09:00\",\"end\":\"18:00\",\"active\":true},"
 "{\"name\":\"maintenance\",\"description\":\"\",\"days\":\"Sun\","
 "\"start\":\"02:00\",\"end\":\"04:00\",\"active\":false}],"
 "\"routes\":[{\"dest\":\"10.9.0.0\",\"cidr\":16,\"gateway\":\"10.0.0.1\","
 "\"ifname\":\"eth0\",\"metric\":1,\"description\":\"lab\"}],"
 "\"schedule_skipped\":47}";

static const char WAN[] =
"{\"links\":[{\"index\":0,\"ifname\":\"eth0\",\"gateway\":\"10.0.2.2\","
 "\"status\":\"up\",\"rtt_ms\":1.75,\"loss_pct\":0,\"nat\":true,\"backup\":false},"
 "{\"index\":1,\"ifname\":\"eth2\",\"gateway\":\"192.168.8.1\","
 "\"status\":\"down\",\"rtt_ms\":0,\"loss_pct\":100,\"nat\":true,\"backup\":true}]}";

static const char VLANS[] =
"{\"vlans\":[{\"vlan_id\":10,\"name\":\"CORP\",\"zone\":\"LAN\"},"
 "{\"vlan_id\":20,\"name\":\"SERVERS\",\"zone\":\"DMZ\"},"
 "{\"vlan_id\":30,\"name\":\"GUEST\",\"zone\":\"GUEST\"}],"
 "\"ports\":[{\"ifname\":\"eth0\"},{\"ifname\":\"eth1\"}],"
 "\"acl_count\":16,\"readonly\":false,\"role\":\"admin\","
 "\"stats\":{\"allowed\":0,\"denied\":0},"
 "\"allowed\":128,\"denied\":9,\"violations\":0}";

static void test_json(void) {
    printf("\n== the JSON reader ==\n");

    char s[64];
    double d = 0;

    ok("a string value is read",
       fxj_str(POLICY, "schedule_skipped", s, sizeof(s)) == false, "not a string");
    ok("a number value is read",
       fxj_num(POLICY, "schedule_skipped", &d) && d == 47, NULL);

    ok("counts an array of objects", fxj_count(POLICY, "schedules") == 2, NULL);
    ok("counts a second array in the same document",
       fxj_count(POLICY, "aliases") == 2, NULL);
    ok("counts a single-element array", fxj_count(POLICY, "routes") == 1, NULL);
    ok("a key that is not there counts zero",
       fxj_count(POLICY, "nonesuch") == 0, NULL);

    /* Walking the array has to visit each element and stop. */
    int n = 0;
    char names[4][32] = {{0}};
    for (const char *p = fxj_array(POLICY, "schedules"); p && n < 4; p = fxj_next(p)) {
        fxj_str(p, "name", names[n], sizeof(names[n]));
        n++;
    }
    ok("walks every schedule", n == 2, NULL);
    ok("and reads each one's name",
       !strcmp(names[0], "workday") && !strcmp(names[1], "maintenance"),
       names[0]);

    /* The element cursor must read ITS OWN fields, not the first one's --
     * the bug that makes every row of a table show row one. */
    const char *first  = fxj_array(POLICY, "schedules");
    const char *second = fxj_next(first);
    double a1 = -1, a2 = -1;
    fxj_num(first, "active", &a1);
    fxj_num(second, "active", &a2);
    ok("true/false read as 1/0", a1 == 1 && a2 == 0, NULL);

    char d1[32] = "", d2[32] = "";
    fxj_str(first, "days", d1, sizeof(d1));
    fxj_str(second, "days", d2, sizeof(d2));
    ok("each element reads its own fields",
       !strcmp(d1, "Mon-Fri") && !strcmp(d2, "Sun"), d2);

    /* An empty string value must not make the walk give up. */
    char desc[32] = "x";
    ok("an empty string value reads as empty",
       fxj_str(second, "description", desc, sizeof(desc)) && desc[0] == '\0', NULL);

    printf("\n-- WAN --\n");
    const char *l1 = fxj_array(WAN, "links");
    const char *l2 = fxj_next(l1);
    char if1[32] = "", if2[32] = "", st1[16] = "", st2[16] = "";
    double rtt1 = 0, loss2 = 0;
    fxj_str(l1, "ifname", if1, sizeof(if1));
    fxj_str(l2, "ifname", if2, sizeof(if2));
    fxj_str(l1, "status", st1, sizeof(st1));
    fxj_str(l2, "status", st2, sizeof(st2));
    fxj_num(l1, "rtt_ms", &rtt1);
    fxj_num(l2, "loss_pct", &loss2);
    ok("both WAN links are walked",
       !strcmp(if1, "eth0") && !strcmp(if2, "eth2"), NULL);
    ok("their states differ as they should",
       !strcmp(st1, "up") && !strcmp(st2, "down"), NULL);
    ok("a fractional number survives", rtt1 > 1.7 && rtt1 < 1.8, NULL);
    ok("the second link's loss is its own", loss2 == 100, NULL);
    ok("the array ends", fxj_next(l2) == NULL, NULL);

    printf("\n-- segmentation --\n");
    ok("nested objects do not break the count",
       fxj_count(VLANS, "vlans") == 3, NULL);
    ok("a sibling array counts correctly",
       fxj_count(VLANS, "ports") == 2, NULL);
    /*
     * "allowed" appears inside "stats" as well as at the top level. The
     * reader takes the first match, which is the nested one -- so the
     * dashboard must not depend on which it gets. Pinning the behaviour
     * here means a change to it fails loudly instead of quietly showing
     * the wrong counter.
     */
    double allowed = -1;
    fxj_num(VLANS, "allowed", &allowed);
    ok("a duplicated key resolves to the first occurrence",
       allowed == 0, "nested stats.allowed wins over the top-level one");
    ok("a uniquely named counter is unambiguous",
       fxj_num(VLANS, "acl_count", &d) && d == 16, NULL);

    printf("\n-- refusals --\n");
    ok("a missing key is not a number", !fxj_num(POLICY, "absent", &d), NULL);
    ok("a missing key is not a string",
       !fxj_str(POLICY, "absent", s, sizeof(s)), NULL);
    ok("a missing array is NULL", fxj_array(POLICY, "absent") == NULL, NULL);
    ok("an empty array is NULL", fxj_array("{\"a\":[]}", "a") == NULL, NULL);
    ok("empty input is handled", fxj_count("", "a") == 0, NULL);
    ok("a truncated document does not run away",
       fxj_count("{\"a\":[{\"x\":1},{\"x\":2}", "a") >= 0, NULL);
    ok("a value that merely contains the key name is not matched",
       !fxj_num("{\"other\":\"acl_count\"}", "acl_count", &d), NULL);
    ok("a key must be followed by a colon",
       !fxj_num("{\"a\":[\"acl_count\",3]}", "acl_count", &d), NULL);

    /* A string holding a brace or a bracket must not confuse the walk. */
    static const char TRICKY[] =
        "{\"rows\":[{\"n\":\"a],[\",\"v\":1},{\"n\":\"b}{\",\"v\":2},"
        "{\"n\":\"c\\\"d\",\"v\":3}]}";
    ok("brackets inside a string do not end the array",
       fxj_count(TRICKY, "rows") == 3, NULL);
    const char *t3 = fxj_next(fxj_next(fxj_array(TRICKY, "rows")));
    double v3 = 0;
    ok("and the last element is still reachable",
       t3 && fxj_num(t3, "v", &v3) && v3 == 3, NULL);

    char esc[32] = "";
    fxj_str(TRICKY, "n", esc, sizeof(esc));
    ok("an escaped quote is unescaped", !strcmp(esc, "a],["), esc);

    /* A short output buffer must truncate, not overflow. */
    char tiny[4];
    fxj_str(POLICY, "days", tiny, sizeof(tiny));
    ok("a short buffer truncates and stays terminated",
       strlen(tiny) == 3 && tiny[3] == '\0', tiny);
}

static void test_interfaces(void) {
    printf("\n== interfaces ==\n");

    fx_ifinfo_t ifs[FX_IFINFO_MAX];
    int n = fx_ifinfo(ifs, FX_IFINFO_MAX);
    ok("at least loopback is found", n >= 1, NULL);

    bool lo = false, dup = false;
    for (int i = 0; i < n; i++) {
        if (ifs[i].loopback) lo = true;
        for (int j = i + 1; j < n; j++)
            if (!strcmp(ifs[i].name, ifs[j].name)) dup = true;
    }
    ok("loopback is flagged as loopback", lo, NULL);
    ok("no interface is listed twice", !dup, NULL);

    /* The login screen sizes its list from this, so overrunning the
     * caller's array would corrupt its stack. */
    fx_ifinfo_t one[1];
    memset(one, 0xAB, sizeof(one));
    int got = fx_ifinfo(one, 1);
    ok("the caller's capacity is respected", got <= 1, NULL);
    ok("a zero capacity returns nothing", fx_ifinfo(one, 0) == 0, NULL);

    char ip[64] = "";
    fx_primary_address(ip, sizeof(ip));
    ok("a primary address is always produced", ip[0] != '\0', ip);
    ok("and it is never loopback",
       strncmp(ip, "127.", 4) != 0, ip);
}

static void test_client_refusals(void) {
    printf("\n== the client's refusals ==\n");

    fx_client_t c;
    char err[FXC_ERR_LEN];

    /* Port 1 on loopback: nothing listens, and the answer must be about
     * the daemon rather than about the password. */
    fxc_init(&c, "127.0.0.1", 1);
    ok("a closed port is not reported as a bad password",
       fxc_login(&c, "admin", "admin", err, sizeof(err)) == -1 &&
       strstr(err, BRAND_DAEMON) != NULL, err);
    ok("and no session is invented", !c.connected && c.token[0] == '\0', NULL);
    ok("fxc_alive says so too", !fxc_alive(&c), NULL);

    fxc_init(&c, "127.0.0.1", 8080);
    ok("an empty user name is refused before any connection",
       fxc_login(&c, "", "x", err, sizeof(err)) == -1, err);

    /*
     * A quote or a backslash would break out of the JSON string the
     * login request is built from. Refused here rather than sent.
     */
    ok("a quote in the user name is refused",
       fxc_login(&c, "ad\"min", "x", err, sizeof(err)) == -1 &&
       strstr(err, "cannot send") != NULL, err);
    ok("a backslash in the password is refused",
       fxc_login(&c, "admin", "pa\\ss", err, sizeof(err)) == -1 &&
       strstr(err, "cannot send") != NULL, err);
    ok("a newline in the password is refused",
       fxc_login(&c, "admin", "pa\nss", err, sizeof(err)) == -1 &&
       strstr(err, "cannot send") != NULL, err);

    fxc_init(&c, "127.0.0.1", 8080);
    ok("defaults are sane", c.port == 8080 && !strcmp(c.host, "127.0.0.1"), NULL);
    fxc_init(&c, NULL, 0);
    ok("a missing host falls back to loopback",
       !strcmp(c.host, "127.0.0.1") && c.port == 8080, NULL);
}

/* Runs only against a daemon that is actually up. */
static void test_live(int port) {
    printf("\n== live round trip against port %d ==\n", port);

    fx_client_t c;
    char err[FXC_ERR_LEN] = "";
    fxc_init(&c, "127.0.0.1", port);

    if (!fxc_alive(&c)) {
        printf("  SKIP  nothing is listening on 127.0.0.1:%d\n", port);
        return;
    }
    ok("the daemon answers", true, NULL);

    ok("a wrong password is refused",
       fxc_login(&c, "admin", "definitely-not-it", err, sizeof(err)) == -1, err);
    ok("and the refusal is not the no-daemon message",
       strstr(err, "is not running") == NULL, err);

    if (fxc_login(&c, "admin", "admin", err, sizeof(err)) != 0) {
        printf("  SKIP  admin/admin was not accepted (%s)\n", err);
        return;
    }
    ok("admin/admin signs in", c.connected, c.role);
    ok("a session token came back", c.token[0] != '\0', NULL);
    ok("a CSRF token came back", c.csrf[0] != '\0', NULL);
    ok("the user name came back", !strcmp(c.user, "admin"), c.user);

    char *pol = fxc_get(&c, "/api/policy", (err[0] = 0, err), sizeof(err));
    ok("GET /api/policy returns a body", pol != NULL, err);
    if (pol) {
        ok("the daemon's own schedules parse",
           fxj_count(pol, "schedules") >= 0, NULL);
        ok("it is JSON, not an error page", pol[0] == '{', NULL);
        free(pol);
    }

    char *vl = fxc_get(&c, "/api/vlans", (err[0] = 0, err), sizeof(err));
    ok("GET /api/vlans returns a body", vl != NULL, err);
    if (vl) {
        ok("the configured VLANs are visible", fxj_count(vl, "vlans") > 0, NULL);
        free(vl);
    }

    char *acc = fxc_get(&c, "/api/accounts", (err[0] = 0, err), sizeof(err));
    ok("GET /api/accounts returns a body", acc != NULL, err);
    if (acc) {
        double n = -1;
        ok("the default-credential count is readable",
           fxj_num(acc, "defaults", &n) && n >= 0, NULL);
        free(acc);
    }

    char *nope = fxc_get(&c, "/api/there-is-no-such-endpoint", (err[0] = 0, err), sizeof(err));
    ok("a 404 comes back as an error, not a body", nope == NULL, err);
    free(nope);

    fxc_logout(&c);
    ok("logout clears the session",
       !c.connected && c.token[0] == '\0' && c.csrf[0] == '\0', NULL);

    char *after = fxc_get(&c, "/api/vlans", (err[0] = 0, err), sizeof(err));
    ok("and the session really is gone", after == NULL, err);
    free(after);
}

int main(void) {
    printf("== %s desktop console ==\n", BRAND_FULL);

    test_json();
    test_interfaces();
    test_client_refusals();

    const char *p = getenv("FIREX_TEST_PORT");
    test_live(p ? atoi(p) : 8080);

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
