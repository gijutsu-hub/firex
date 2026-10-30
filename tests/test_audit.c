/*
 * Administrative audit trail tests.
 *
 * The interesting properties here are not "does it write a line" but the
 * two that an auditor actually relies on: that a field cannot be used to
 * forge a second record, and that removing or editing a record is
 * detectable afterwards. Both are tested by doing the thing -- planting an
 * injection in a VLAN name, deleting a line from the middle of the file --
 * rather than by asserting that the code which prevents it was called.
 *
 *   make test-audit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include "audit.h"

static int pass = 0, fail = 0;
static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-58s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-58s %s\n", what, detail ? detail : ""); fail++; }
}

static char g_dir[256], g_log[384];

static int line_count(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0, c;
    while ((c = fgetc(f)) != EOF) if (c == '\n') n++;
    fclose(f);
    return n;
}

static bool file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[4096];
    bool found = false;
    while (fgets(line, sizeof(line), f))
        if (strstr(line, needle)) { found = true; break; }
    fclose(f);
    return found;
}

/* ═══ 1. recording ════════════════════════════════════════════════════ */

static void test_recording(void) {
    printf("\n[ recording ]\n");

    audit_ctx_t a;
    ok("the trail opens", audit_open(&a, g_log) == 0, g_log);

    struct stat st;
    ok("  and is 0600",
       stat(g_log, &st) == 0 && (st.st_mode & 07777) == 0600,
       "it names every operator and where they worked from");

    audit_record(&a, "alice", 0x0100007f, AUDIT_OK, "airgap.mode", "isolated",
                 "boundary changed from connected to isolated");
    audit_record(&a, "bob", 0, AUDIT_DENIED, "authz.deny", "POST",
                 "bob is read-only and attempted a write");

    ok("records reach the file", line_count(g_log) == 2, NULL);
    ok("  the actor is recorded", file_has(g_log, "alice"), NULL);
    ok("  the action is recorded", file_has(g_log, "airgap.mode"), NULL);
    ok("  the source address is recorded", file_has(g_log, "127.0.0.1"), NULL);
    ok("  a refusal is recorded as denied", file_has(g_log, "denied"), NULL);

    audit_entry_t ev[8];
    int n = audit_recent(&a, ev, 8);
    ok("the ring returns both, newest first",
       n == 2 && !strcmp(ev[0].actor, "bob") && !strcmp(ev[1].actor, "alice"),
       NULL);
    ok("  sequence numbers increase", ev[1].seq == 1 && ev[0].seq == 2, NULL);

    audit_close(&a);

    /* A restart must continue the chain, not start a second one that
     * would verify on its own terms and hide everything before it. */
    audit_ctx_t b;
    audit_open(&b, g_log);
    audit_record(&b, "carol", 0, AUDIT_OK, "config.apply", "/etc/firex.conf", "x");
    audit_entry_t one[1];
    audit_recent(&b, one, 1);
    ok("a restart continues the sequence", one[0].seq == 3, NULL);
    audit_close(&b);

    char why[256];
    ok("  and the chain still verifies across the restart",
       audit_verify(g_log, why, sizeof(why)) == 0, why);
}

/* ═══ 2. log injection ═══════════════════════════════════════════════ */

static void test_injection(void) {
    printf("\n[ injection ]\n");

    char path[384];
    snprintf(path, sizeof(path), "%s/inject.log", g_dir);

    audit_ctx_t a;
    audit_open(&a, path);

    /*
     * A tab and a newline inside a value. Unescaped, this writes a second
     * record claiming that root disabled the air gap -- and it would
     * verify, because the forged text would be inside the hashed body of
     * a record the appliance wrote itself.
     */
    audit_record(&a, "mallory", 0, AUDIT_OK, "vlan.rename",
                 "guest\t9\t2020-01-01T00:00:00Z\troot\t-\tairgap.mode\t"
                 "connected\tok\tdisabled by root",
                 "renamed a segment");

    ok("one record in, one line out", line_count(path) == 1,
       "a newline in a field would have made two");
    ok("  the forged actor did not become a record",
       !file_has(path, "\troot\t-\t"), NULL);
    ok("  the tabs are escaped, not dropped", file_has(path, "\\t"), NULL);

    audit_record(&a, "mallory", 0, AUDIT_OK, "note",
                 "line one\nline two", "multi-line target");
    ok("a newline cannot split a record", line_count(path) == 2, NULL);
    ok("  and is escaped visibly", file_has(path, "\\n"), NULL);

    audit_close(&a);

    char why[256];
    ok("the trail still verifies after the attempt",
       audit_verify(path, why, sizeof(why)) == 0, why);
    unlink(path);
}

/* ═══ 3. tamper evidence ═════════════════════════════════════════════ */

static void rewrite_without(const char *path, int drop_line) {
    FILE *in = fopen(path, "r");
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *out = fopen(tmp, "w");
    char line[4096];
    int n = 0;
    while (fgets(line, sizeof(line), in))
        if (++n != drop_line) fputs(line, out);
    fclose(in); fclose(out);
    rename(tmp, path);
}

static void test_tamper(void) {
    printf("\n[ tamper evidence ]\n");

    char path[384];
    snprintf(path, sizeof(path), "%s/tamper.log", g_dir);

    audit_ctx_t a;
    audit_open(&a, path);
    for (int i = 0; i < 6; i++)
        audit_record(&a, "operator", 0, AUDIT_OK, "config.write",
                     "/api/config/save", "revision %d", i + 1);
    audit_close(&a);

    char why[256];
    ok("an untouched trail verifies", audit_verify(path, why, sizeof(why)) == 0, why);

    /* ── a deleted record ── */
    char cut[384];
    snprintf(cut, sizeof(cut), "%s/cut.log", g_dir);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", path, cut);
    if (system(cmd) != 0) { ok("could not copy for the delete case", 0, NULL); return; }

    rewrite_without(cut, 3);
    int bad = audit_verify(cut, why, sizeof(why));
    ok("a deleted record is detected", bad != 0, why);
    ok("  and the first broken record is named", bad == 3, why);
    unlink(cut);

    /* ── an edited field ── */
    char ed[384];
    snprintf(ed, sizeof(ed), "%s/edited.log", g_dir);
    snprintf(cmd, sizeof(cmd),
             "sed 's/revision 4/revision 9/' '%s' > '%s'", path, ed);
    if (system(cmd) == 0) {
        bad = audit_verify(ed, why, sizeof(why));
        ok("an edited record is detected", bad != 0, why);
        ok("  at the record that was edited", bad == 4, why);
        unlink(ed);
    }

    /* ── a record appended by hand, with no valid hash ── */
    char app[384];
    snprintf(app, sizeof(app), "%s/appended.log", g_dir);
    snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", path, app);
    if (system(cmd) == 0) {
        FILE *f = fopen(app, "a");
        fprintf(f, "7\t2020-01-01T00:00:00Z\troot\t-\tairgap.mode\t"
                   "connected\tok\tdisabled\t%s\n",
                "0000000000000000000000000000000000000000000000000000000000000000");
        fclose(f);
        bad = audit_verify(app, why, sizeof(why));
        ok("a hand-written record is detected", bad == 7, why);
        unlink(app);
    }

    /*
     * Reordering. Both records are genuine and both hashes were real when
     * written, so a per-record checksum would accept this -- only a chain
     * catches it.
     */
    char sw[384];
    snprintf(sw, sizeof(sw), "%s/swapped.log", g_dir);
    snprintf(cmd, sizeof(cmd),
             "awk 'NR==2{a=$0;next} NR==3{print $0; print a; next} {print}' "
             "'%s' > '%s'", path, sw);
    if (system(cmd) == 0) {
        bad = audit_verify(sw, why, sizeof(why));
        ok("two swapped records are detected", bad != 0, why);
        unlink(sw);
    }

    unlink(path);
}

int main(void) {
    printf("=== FireX audit trail ===\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/firex_audit_XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
    snprintf(g_log, sizeof(g_log), "%s/audit.log", g_dir);

    test_recording();
    test_injection();
    test_tamper();

    unlink(g_log);
    rmdir(g_dir);

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
