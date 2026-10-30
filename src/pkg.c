/*
 * Add-on packages: verify, inspect, extract, record, remove.
 *
 * The dangerous step is extraction, because a tar archive decides its own
 * member paths. Three rules keep it contained:
 *
 *   1. Every member name must pass pkg_path_safe() before anything is
 *      written. One bad name rejects the whole package.
 *   2. Archives containing symbolic or hard links are refused outright.
 *      A link name can be innocent while its target points at /etc, and
 *      checking targets means parsing tar's verbose output, which is not
 *      reliably parseable for names with spaces. Refusing links is a rule
 *      that can actually be enforced, so that is the rule.
 *   3. Member names are restricted to a character whitelist, which is
 *      also what makes it safe to put them in a shell command later.
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include "pkg.h"
#include "shellcmd.h"
#include "brand.h"

#define ERRF(e, n, ...) do { if (e && n) snprintf(e, n, __VA_ARGS__); } while (0)

void pkg_init(pkg_ctx_t *p, const char *root, const char *db) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
    snprintf(p->root, sizeof(p->root), "%s", root ? root : "/usr/local");
    snprintf(p->db,   sizeof(p->db),   "%s", db   ? db   : "/var/lib/firex/packages");
}

/* ── path safety ────────────────────────────────────────────── */

/*
 * A deliberately small alphabet. Everything a real package needs -- letters,
 * digits, dot, dash, underscore, plus, slash -- and nothing that means
 * anything to a shell. Keeping the set this tight is what lets the install
 * and remove plans embed these names in commands without quoting games.
 */
static bool path_char_ok(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '_' || c == '+' || c == '/';
}

bool pkg_path_safe(const char *path, char *why, size_t whylen) {
    if (!path || !*path) {
        ERRF(why, whylen, "empty member name");
        return false;
    }
    size_t len = strlen(path);
    if (len >= PKG_PATH_LEN) {
        ERRF(why, whylen, "member name is longer than %d bytes", PKG_PATH_LEN - 1);
        return false;
    }
    if (path[0] == '/') {
        ERRF(why, whylen, "absolute path '%s'", path);
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (!path_char_ok(path[i])) {
            ERRF(why, whylen,
                 "member '%s' contains a character that is not allowed in a "
                 "package path (0x%02x at offset %zu)",
                 path, (unsigned char)path[i], i);
            return false;
        }
    }

    /* Walk components so "a/../../etc" is caught wherever the .. sits. */
    const char *s = path;
    while (*s) {
        const char *slash = strchr(s, '/');
        size_t clen = slash ? (size_t)(slash - s) : strlen(s);
        if (clen == 2 && s[0] == '.' && s[1] == '.') {
            ERRF(why, whylen, "member '%s' escapes the package root with '..'", path);
            return false;
        }
        if (!slash) break;
        s = slash + 1;
    }
    return true;
}

int pkg_listing_check(char *const *paths, int n, char *why, size_t whylen) {
    for (int i = 0; i < n; i++)
        if (!pkg_path_safe(paths[i], why, whylen)) return i;
    return -1;
}

/* ── install records ────────────────────────────────────────── */

pkg_info_t *pkg_find(pkg_ctx_t *p, const char *name) {
    if (!p || !name) return NULL;
    for (int i = 0; i < p->count; i++)
        if (strcmp(p->pkg[i].name, name) == 0) return &p->pkg[i];
    return NULL;
}

int pkg_record_write(const pkg_ctx_t *p, const pkg_info_t *info,
                     char *const *files, int nfiles, char *err, size_t errlen) {
    char path[PKG_PATH_LEN * 2];

    snprintf(path, sizeof(path), "%s/%s.pkg", p->db, info->name);
    FILE *f = fopen(path, "w");
    if (!f) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    fprintf(f, "# %s package record\n", BRAND_PRODUCT);
    fprintf(f, "name = %s\n",        info->name);
    fprintf(f, "version = %s\n",     info->version);
    fprintf(f, "description = %s\n", info->description);
    fprintf(f, "sha256 = %s\n",      info->sha256);
    fprintf(f, "installed = %llu\n", (unsigned long long)info->installed);
    fprintf(f, "files = %d\n",       nfiles);
    if (fclose(f) != 0) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }

    snprintf(path, sizeof(path), "%s/%s.files", p->db, info->name);
    f = fopen(path, "w");
    if (!f) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    for (int i = 0; i < nfiles; i++) fprintf(f, "%s\n", files[i]);
    if (fclose(f) != 0) { ERRF(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    return 0;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' ||
                     e[-1] == ' '  || e[-1] == '\t')) *--e = '\0';
    return s;
}

int pkg_record_read(const pkg_ctx_t *p, const char *name, pkg_info_t *out,
                    char *err, size_t errlen) {
    char path[PKG_PATH_LEN * 2];
    snprintf(path, sizeof(path), "%s/%s.pkg", p->db, name);

    FILE *f = fopen(path, "r");
    if (!f) { ERRF(err, errlen, "%s is not installed", name); return -1; }

    memset(out, 0, sizeof(*out));
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = trim(s), *v = trim(eq + 1);
        if      (!strcmp(k, "name"))        snprintf(out->name, sizeof(out->name), "%s", v);
        else if (!strcmp(k, "version"))     snprintf(out->version, sizeof(out->version), "%s", v);
        else if (!strcmp(k, "description")) snprintf(out->description, sizeof(out->description), "%s", v);
        else if (!strcmp(k, "sha256"))      snprintf(out->sha256, sizeof(out->sha256), "%s", v);
        else if (!strcmp(k, "installed"))   out->installed  = strtoull(v, NULL, 10);
        else if (!strcmp(k, "files"))       out->file_count = atoi(v);
    }
    fclose(f);

    if (!out->name[0]) {
        ERRF(err, errlen, "%s: the install record has no name", path);
        return -1;
    }
    return 0;
}

int pkg_db_load(pkg_ctx_t *p, char *err, size_t errlen) {
    if (!p) return -1;
    p->count = 0;

    DIR *d = opendir(p->db);
    if (!d) {
        /* Nothing installed yet is the normal state of a fresh appliance. */
        ERRF(err, errlen, "%s: %s", p->db, strerror(errno));
        return 1;
    }

    struct dirent *e;
    while ((e = readdir(d)) && p->count < PKG_MAX_INSTALLED) {
        size_t n = strlen(e->d_name);
        if (n < 5 || strcmp(e->d_name + n - 4, ".pkg") != 0) continue;

        char name[64];
        if (n - 4 >= sizeof(name)) continue;
        memcpy(name, e->d_name, n - 4);
        name[n - 4] = '\0';

        if (pkg_record_read(p, name, &p->pkg[p->count], NULL, 0) == 0)
            p->count++;
    }
    closedir(d);
    return 0;
}

/* ── plans ──────────────────────────────────────────────────── */

static void plan_add(pkg_plan_t *pl, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void plan_add(pkg_plan_t *pl, const char *fmt, ...) {
    if (!pl || pl->count >= PKG_MAX_CMDS) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(pl->cmd[pl->count], PKG_CMD_LEN, fmt, ap);
    va_end(ap);
    pl->count++;
}

int pkg_plan_install(const pkg_ctx_t *p, const upd_meta_t *m,
                     const char *payload_path, pkg_plan_t *out) {
    if (!p || !m || !out) return -1;
    memset(out, 0, sizeof(*out));

    plan_add(out, "mkdir -p %s", p->root);
    plan_add(out, "mkdir -p %s", p->db);
    /*
     * --no-same-owner so a package cannot hand its files to another uid,
     * and --no-same-permissions so it cannot ship a setuid-root binary and
     * have the mode restored. Absolute names need no flag: tar strips the
     * leading slash by default, and pkg_path_safe() has already refused
     * the archive by the time this plan is built.
     */
    plan_add(out, "tar -xzf %s -C %s --no-same-owner --no-same-permissions "
             "--no-overwrite-dir", payload_path, p->root);
    plan_add(out, "# record %s %s in %s/%s.pkg", m->name, m->version, p->db, m->name);
    return out->count;
}

int pkg_plan_remove(const pkg_ctx_t *p, const pkg_info_t *info, pkg_plan_t *out) {
    if (!p || !info || !out) return -1;
    memset(out, 0, sizeof(*out));

    plan_add(out, "# remove %d file(s) listed in %s/%s.files",
             info->file_count, p->db, info->name);
    plan_add(out, "rm -f %s/%s.files %s/%s.pkg", p->db, info->name, p->db, info->name);
    return out->count;
}

/* ── archive listing ────────────────────────────────────────── */

/*
 * Returns a NULL-terminated vector of member names, or NULL on failure.
 * link_count receives how many symbolic or hard links the archive holds,
 * which the caller treats as fatal.
 */
static char **tar_list(const char *archive, int *n_out, int *link_count,
                       char *err, size_t errlen) {
    /* archive is a staging path this process built under p->db, which
     * is itself up to PKG_PATH_LEN; size for that, not for one name. */
    char cmd[PKG_PATH_LEN * 2 + 64];
    snprintf(cmd, sizeof(cmd), "tar -tvzf %s 2>/dev/null", archive);

    FILE *pp = popen(cmd, "r");
    if (!pp) { ERRF(err, errlen, "could not run tar: %s", strerror(errno)); return NULL; }

    char **v = calloc(PKG_MAX_FILES + 1, sizeof(char *));
    if (!v) { pclose(pp); return NULL; }

    int  n = 0, links = 0;
    char line[1024];
    while (fgets(line, sizeof(line), pp) && n < PKG_MAX_FILES) {
        char *s = trim(line);
        if (!*s) continue;
        if (s[0] == 'l' || s[0] == 'h') links++;

        /*
         * Verbose tar output is "mode owner size date time name". The name
         * is everything after the fifth run of whitespace. Directories end
         * in '/', which the safety check accepts.
         */
        char *f = s;
        for (int field = 0; field < 5 && f; field++) {
            f = strchr(f, ' ');
            while (f && *f == ' ') f++;
        }
        if (!f || !*f) continue;

        char *arrow = strstr(f, " -> ");
        if (arrow) *arrow = '\0';

        v[n] = strdup(f);
        if (!v[n]) break;
        n++;
    }

    int rc = pclose(pp);
    if (rc != 0) {
        ERRF(err, errlen, "tar could not read the archive (exit %d)", rc);
        for (int i = 0; i < n; i++) free(v[i]);
        free(v);
        return NULL;
    }
    if (n == 0) {
        ERRF(err, errlen, "the package archive is empty");
        free(v);
        return NULL;
    }

    *n_out = n;
    *link_count = links;
    return v;
}

static void free_list(char **v, int n) {
    for (int i = 0; i < n; i++) free(v[i]);
    free(v);
}

/* ── install / remove ───────────────────────────────────────── */

int pkg_install(pkg_ctx_t *p, const char *bundle, const upd_keyring_t *ring,
                bool dry_run, pkg_plan_t *plan, char *err, size_t errlen) {
    if (!p || !bundle) return -1;

    upd_meta_t m;
    if (upd_bundle_verify(bundle, ring, NULL, &m, err, errlen) != 0) return -1;

    if (m.kind != UPD_KIND_PACKAGE) {
        ERRF(err, errlen, "%s is a system image, not a package", bundle);
        return -1;
    }
    if (!m.name[0] || !pkg_path_safe(m.name, NULL, 0) || strchr(m.name, '/')) {
        ERRF(err, errlen, "'%s' is not a usable package name", m.name);
        return -1;
    }

    /* The staging copy lives beside the database, on the same filesystem
     * the files are going to, so a full disk fails here and not halfway
     * through extraction. */
    char staging[PKG_PATH_LEN * 2];
    snprintf(staging, sizeof(staging), "%s/.staging-%s.tar.gz", p->db, m.name);

    char mk[PKG_PATH_LEN + 16];
    snprintf(mk, sizeof(mk), "mkdir -p %s", p->db);
    if (fx_run(mk) != 0) {
        ERRF(err, errlen, "could not create %s", p->db);
        return -1;
    }

    if (upd_bundle_extract(bundle, ring, staging, err, errlen) != 0) return -1;

    int n = 0, links = 0;
    char why[256] = "";
    char **files = tar_list(staging, &n, &links, err, errlen);
    if (!files) { unlink(staging); return -1; }

    if (links > 0) {
        ERRF(err, errlen,
             "the archive contains %d symbolic or hard link(s); %s packages "
             "may not ship links", links, BRAND_PRODUCT);
        free_list(files, n);
        unlink(staging);
        return -1;
    }

    int bad = pkg_listing_check(files, n, why, sizeof(why));
    if (bad >= 0) {
        ERRF(err, errlen, "refusing %s: %s", m.name, why);
        free_list(files, n);
        unlink(staging);
        return -1;
    }

    pkg_plan_t local;
    if (!plan) plan = &local;
    pkg_plan_install(p, &m, staging, plan);

    if (dry_run) {
        unlink(staging);
        free_list(files, n);
        return 0;
    }

    int failures = 0;
    for (int i = 0; i < plan->count; i++) {
        if (plan->cmd[i][0] == '#') continue;
        if (fx_run(plan->cmd[i]) != 0) failures++;
    }
    if (failures) {
        ERRF(err, errlen, "%d install command(s) failed; %s may be incomplete",
             failures, m.name);
        free_list(files, n);
        unlink(staging);
        return -1;
    }

    pkg_info_t info;
    memset(&info, 0, sizeof(info));
    snprintf(info.name, sizeof(info.name), "%s", m.name);
    snprintf(info.version, sizeof(info.version), "%s", m.version);
    snprintf(info.description, sizeof(info.description), "%s", m.description);
    snprintf(info.sha256, sizeof(info.sha256), "%s", m.sha256);
    info.installed  = (uint64_t)time(NULL);
    info.file_count = n;

    int rc = pkg_record_write(p, &info, files, n, err, errlen);
    free_list(files, n);
    unlink(staging);
    if (rc != 0) return -1;

    pkg_db_load(p, NULL, 0);
    return 0;
}

int pkg_remove(pkg_ctx_t *p, const char *name, bool dry_run,
               pkg_plan_t *plan, char *err, size_t errlen) {
    if (!p || !name) return -1;

    pkg_info_t info;
    if (pkg_record_read(p, name, &info, err, errlen) != 0) return -1;

    pkg_plan_t local;
    if (!plan) plan = &local;
    pkg_plan_remove(p, &info, plan);
    if (dry_run) return 0;

    /*
     * Files are unlinked here rather than through the shell: the list is
     * read back from disk, and re-validating each entry before touching it
     * keeps a tampered .files record from reaching outside the root.
     */
    char path[PKG_PATH_LEN * 2];
    snprintf(path, sizeof(path), "%s/%s.files", p->db, name);

    int removed = 0, skipped = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        char line[PKG_PATH_LEN + 2];
        while (fgets(line, sizeof(line), f)) {
            char *s = trim(line);
            if (!*s) continue;
            if (!pkg_path_safe(s, NULL, 0)) { skipped++; continue; }

            size_t l = strlen(s);
            if (l && s[l - 1] == '/') continue;      /* directories below */

            char full[PKG_PATH_LEN * 2];
            snprintf(full, sizeof(full), "%s/%s", p->root, s);
            if (unlink(full) == 0) removed++;
        }
        fclose(f);
    }

    /* Then the directories, deepest last in the archive order, so walking
     * the list backwards removes children before their parents. Each rmdir
     * fails harmlessly when something else still lives there. */
    f = fopen(path, "r");
    if (f) {
        static char dirs[PKG_MAX_FILES][PKG_PATH_LEN];
        int nd = 0;
        char line[PKG_PATH_LEN + 2];
        while (fgets(line, sizeof(line), f) && nd < PKG_MAX_FILES) {
            char *s = trim(line);
            size_t l = strlen(s);
            if (l && s[l - 1] == '/' && pkg_path_safe(s, NULL, 0))
                snprintf(dirs[nd++], PKG_PATH_LEN, "%s", s);
        }
        fclose(f);
        for (int i = nd - 1; i >= 0; i--) {
            char full[PKG_PATH_LEN * 2];
            snprintf(full, sizeof(full), "%s/%s", p->root, dirs[i]);
            rmdir(full);
        }
    }

    if (skipped)
        ERRF(err, errlen, "%d entr(ies) in the file list were unsafe and left alone",
             skipped);

    snprintf(path, sizeof(path), "%s/%s.files", p->db, name);
    unlink(path);
    snprintf(path, sizeof(path), "%s/%s.pkg", p->db, name);
    unlink(path);

    pkg_db_load(p, NULL, 0);
    (void)removed;
    return 0;
}
