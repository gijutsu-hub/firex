/*
 * Versioned configuration store. See include/configstore.h for the layout.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "configstore.h"
#include "brand.h"

/* "00042.conf" -> 42, and anything else -> -1. The fixed width keeps a plain
 * directory listing in revision order. */
static int rev_from_name(const char *name) {
    int n = 0, digits = 0;
    const char *p = name;
    while (*p >= '0' && *p <= '9') { n = n * 10 + (*p - '0'); p++; digits++; }
    if (digits != 5 || strcmp(p, ".conf") != 0) return -1;
    return n;
}

static void rev_path(cfgstore_t *s, int rev, char *buf, size_t len) {
    snprintf(buf, len, "%s/%05d.conf", s->dir, rev);
}

static int mkdir_p(const char *path) {
    char buf[CFG_DIR_LEN];
    snprintf(buf, sizeof(buf), "%s", path);

    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0750) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(buf, 0750) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Copy with the same durability discipline as the serialiser: write a temp
 * file beside the destination, fsync, rename. */
static int copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "r");
    if (!in) return -1;

    char tmp[CFG_PATH_LEN + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", to);
    /* Revisions are copies of a file that holds secrets; same mode. */
    int ofd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (ofd < 0) { fclose(in); return -1; }
    FILE *out = fdopen(ofd, "w");
    if (!out) { close(ofd); fclose(in); unlink(tmp); return -1; }

    char buf[8192];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        if (fwrite(buf, 1, n, out) != n) { rc = -1; break; }
    if (ferror(in)) rc = -1;

    if (rc == 0 && fflush(out) != 0) rc = -1;
    int fd = fileno(out);
    if (rc == 0 && fd >= 0 && fsync(fd) != 0) rc = -1;
    if (fclose(out) != 0) rc = -1;
    fclose(in);

    if (rc != 0 || rename(tmp, to) != 0) { unlink(tmp); return -1; }
    return 0;
}

static void prune_locked(cfgstore_t *s) {
    if (s->keep <= 0) return;

    int revs[512];
    int count = 0;
    DIR *d = opendir(s->dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) && count < (int)(sizeof(revs)/sizeof(revs[0]))) {
        int r = rev_from_name(e->d_name);
        if (r >= 0) revs[count++] = r;
    }
    closedir(d);
    if (count <= s->keep) return;

    /* ascending, so the oldest go first */
    for (int i = 1; i < count; i++) {
        int k = revs[i], j = i - 1;
        while (j >= 0 && revs[j] > k) { revs[j+1] = revs[j]; j--; }
        revs[j+1] = k;
    }
    char p[CFG_PATH_LEN];
    for (int i = 0; i < count - s->keep; i++) {
        rev_path(s, revs[i], p, sizeof(p));
        unlink(p);
    }
}

int cfgstore_init(cfgstore_t *s, const char *active_path) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
    s->keep = CFG_KEEP_DEFAULT;

    snprintf(s->active, sizeof(s->active), "%s", active_path);

    char dirbuf[CFG_DIR_LEN - 16];
    if (snprintf(dirbuf, sizeof(dirbuf), "%s", active_path) >= (int)sizeof(dirbuf)) {
        fprintf(stderr, "[%s] config path too long: %s\n", BRAND_PRODUCT, active_path);
        return -1;
    }
    char *slash = strrchr(dirbuf, '/');
    if (slash) *slash = '\0';
    else        snprintf(dirbuf, sizeof(dirbuf), ".");

    snprintf(s->dir, sizeof(s->dir), "%s/config.d", dirbuf[0] ? dirbuf : "/");

    if (mkdir_p(s->dir) != 0) {
        fprintf(stderr, "[%s] config history unavailable: cannot create %s (%s)\n",
                BRAND_PRODUCT, s->dir, strerror(errno));
        s->ready = false;
        return -1;
    }
    s->ready = true;
    return 0;
}

int cfgstore_latest(cfgstore_t *s) {
    if (!s->ready) return 0;
    DIR *d = opendir(s->dir);
    if (!d) return 0;
    int max = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        int r = rev_from_name(e->d_name);
        if (r > max) max = r;
    }
    closedir(d);
    return max;
}

int cfgstore_commit(cfgstore_t *s,
                    vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *bp,
                    policy_ctx_t *pol, vpn_ctx_t *vpn,
                    const char *author, const char *note) {
    if (!s->ready) return -1;

    pthread_mutex_lock(&s->lock);

    cfg_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    meta.revision = cfgstore_latest(s) + 1;
    meta.when     = time(NULL);
    snprintf(meta.author, sizeof(meta.author), "%s", author ? author : "system");
    if (note) snprintf(meta.note, sizeof(meta.note), "%s", note);

    char path[CFG_PATH_LEN];
    rev_path(s, meta.revision, path, sizeof(path));

    if (firex_save_enterprise_config_ex(path, v, n, bp, pol, vpn, &meta) != 0) {
        pthread_mutex_unlock(&s->lock);
        return -1;
    }

    /* The revision is the record; the active file is a copy of it. Writing the
     * revision first means a crash in between leaves history intact and the
     * appliance still booting the previous config. */
    if (copy_file(path, s->active) != 0) {
        pthread_mutex_unlock(&s->lock);
        return -1;
    }

    prune_locked(s);
    pthread_mutex_unlock(&s->lock);
    return meta.revision;
}

int cfgstore_path_for(cfgstore_t *s, int rev, char *buf, size_t len) {
    if (!s->ready || rev <= 0) return -1;
    char p[CFG_PATH_LEN];
    rev_path(s, rev, p, sizeof(p));
    if (access(p, R_OK) != 0) return -1;
    snprintf(buf, len, "%s", p);
    return 0;
}

int cfgstore_list(cfgstore_t *s, cfg_revision_t *out, int max) {
    if (!s->ready || max <= 0) return 0;

    pthread_mutex_lock(&s->lock);

    int revs[512];
    int count = 0;
    DIR *d = opendir(s->dir);
    if (!d) { pthread_mutex_unlock(&s->lock); return 0; }
    struct dirent *e;
    while ((e = readdir(d)) && count < (int)(sizeof(revs)/sizeof(revs[0]))) {
        int r = rev_from_name(e->d_name);
        if (r >= 0) revs[count++] = r;
    }
    closedir(d);

    /* descending: newest first */
    for (int i = 1; i < count; i++) {
        int k = revs[i], j = i - 1;
        while (j >= 0 && revs[j] < k) { revs[j+1] = revs[j]; j--; }
        revs[j+1] = k;
    }

    int w = 0;
    for (int i = 0; i < count && w < max; i++) {
        cfg_revision_t *r = &out[w];
        memset(r, 0, sizeof(*r));
        r->revision = revs[i];
        rev_path(s, revs[i], r->path, sizeof(r->path));

        cfg_meta_t m;
        if (firex_read_config_meta(r->path, &m) == 0) {
            r->when = m.when;
            snprintf(r->author, sizeof(r->author), "%s", m.author);
            snprintf(r->note,   sizeof(r->note),   "%s", m.note);
        } else {
            struct stat st;
            if (stat(r->path, &st) == 0) r->when = st.st_mtime;
            snprintf(r->author, sizeof(r->author), "unknown");
        }
        w++;
    }
    pthread_mutex_unlock(&s->lock);
    return w;
}

int cfgstore_rollback(cfgstore_t *s, int rev) {
    char path[CFG_PATH_LEN];
    if (cfgstore_path_for(s, rev, path, sizeof(path)) != 0) return -1;

    pthread_mutex_lock(&s->lock);
    int rc = copy_file(path, s->active);
    pthread_mutex_unlock(&s->lock);
    return rc;
}

void cfgstore_shutdown(cfgstore_t *s) {
    if (!s) return;
    pthread_mutex_destroy(&s->lock);
    s->ready = false;
}
