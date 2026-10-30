#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "audit.h"
#include "malware.h"      /* mw_sha256 / mw_hex: one SHA-256, not two */

#define GENESIS "0000000000000000000000000000000000000000000000000000000000000000"

const char *audit_result_name(audit_result_t r) {
    switch (r) {
        case AUDIT_OK:     return "ok";
        case AUDIT_DENIED: return "denied";
        case AUDIT_FAILED: return "failed";
    }
    return "unknown";
}

/*
 * Fields are tab-separated and every value is escaped, so a field can
 * never contain a tab or a newline. Without that an operator could name a
 * VLAN "x\n9999\t2026..." and write a forged record into the trail through
 * a field the trail itself is reporting -- log injection, and the trail is
 * the one file where it matters most.
 */
static void esc(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    if (!outlen) return;
    for (const unsigned char *p = (const unsigned char *)(in ? in : ""); *p; p++) {
        const char *rep = NULL;
        char one[2] = { (char)*p, 0 };
        switch (*p) {
            case '\t': rep = "\\t";  break;
            case '\n': rep = "\\n";  break;
            case '\r': rep = "\\r";  break;
            case '\\': rep = "\\\\"; break;
            default:
                /* Control characters would let a terminal reading the file
                 * be driven by its contents. */
                if (*p < 0x20 || *p == 0x7f) rep = ".";
                else rep = one;
        }
        size_t rl = strlen(rep);
        if (o + rl >= outlen) break;
        memcpy(out + o, rep, rl);
        o += rl;
    }
    out[o] = 0;
}

/* The record's text, without its own hash. This is what the chain covers. */
static int format_body(char *out, size_t outlen, const audit_entry_t *e) {
    char when[32];
    struct tm tm;
    gmtime_r(&e->when, &tm);
    strftime(when, sizeof(when), "%Y-%m-%dT%H:%M:%SZ", &tm);

    char ip[INET_ADDRSTRLEN] = "-";
    if (e->peer) {
        struct in_addr a = { .s_addr = e->peer };
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
    }

    char actor[AUDIT_ACTOR_LEN * 2], action[AUDIT_ACTION_LEN * 2];
    char target[AUDIT_TARGET_LEN * 2], detail[AUDIT_DETAIL_LEN * 2];
    esc(e->actor,  actor,  sizeof(actor));
    esc(e->action, action, sizeof(action));
    esc(e->target, target, sizeof(target));
    esc(e->detail, detail, sizeof(detail));

    return snprintf(out, outlen, "%llu\t%s\t%s\t%s\t%s\t%s\t%s\t%s",
                    (unsigned long long)e->seq, when, actor, ip,
                    action, target, audit_result_name(e->result), detail);
}

static void chain(const char *prev_hex, const char *body, char *out_hex) {
    /* SHA-256(previous hash text || record text). Feeding the previous
     * HASH rather than the previous record is what makes one check of the
     * last line enough to vouch for everything before it. */
    size_t pl = strlen(prev_hex), bl = strlen(body);
    char *buf = malloc(pl + bl + 1);
    if (!buf) { snprintf(out_hex, AUDIT_HASH_HEX, "%s", GENESIS); return; }
    memcpy(buf, prev_hex, pl);
    memcpy(buf + pl, body, bl);

    uint8_t d[MW_DIGEST_LEN];
    mw_sha256(buf, pl + bl, d);
    free(buf);
    mw_hex(d, out_hex, AUDIT_HASH_HEX);
}

/* Reads the final record's hash so a restart continues one chain. */
static void load_tail(audit_ctx_t *a) {
    snprintf(a->prev_hash, sizeof(a->prev_hash), "%s", GENESIS);
    a->seq = 0;

    FILE *f = fopen(a->path, "r");
    if (!f) return;

    char line[2048], last[2048] = "";
    while (fgets(line, sizeof(line), f))
        if (line[0] != '#' && line[0] != '\n') snprintf(last, sizeof(last), "%s", line);
    fclose(f);
    if (!last[0]) return;

    /* seq is the first field, the hash the last. */
    unsigned long long seq = 0;
    if (sscanf(last, "%llu", &seq) == 1) a->seq = seq;

    char *nl = strpbrk(last, "\r\n");
    if (nl) *nl = 0;
    char *tab = strrchr(last, '\t');
    if (tab && strlen(tab + 1) == AUDIT_HASH_HEX - 1)
        snprintf(a->prev_hash, sizeof(a->prev_hash), "%s", tab + 1);
}

int audit_open(audit_ctx_t *a, const char *path) {
    if (!a || !path || !*path) return -1;
    memset(a, 0, sizeof(*a));
    pthread_mutex_init(&a->lock, NULL);
    snprintf(a->path, sizeof(a->path), "%s", path);

    load_tail(a);

    /*
     * O_APPEND, and 0600. Append is not a formality: without it a writer
     * that seeks can overwrite earlier records, and with it the kernel
     * places every write at the end even when two processes hold the file
     * open -- which is what keeps a reload from interleaving badly.
     */
    a->fd = open(path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (a->fd < 0) {
        fprintf(stderr, "[%s] audit: cannot write %s (%s); administrative "
                "actions will be recorded in memory only\n",
                BRAND_PRODUCT, path, strerror(errno));
    }
    a->ready = true;
    return a->fd >= 0 ? 0 : -1;
}

void audit_close(audit_ctx_t *a) {
    if (!a || !a->ready) return;
    pthread_mutex_lock(&a->lock);
    if (a->fd >= 0) { fsync(a->fd); close(a->fd); a->fd = -1; }
    a->ready = false;
    pthread_mutex_unlock(&a->lock);
    pthread_mutex_destroy(&a->lock);
}

void audit_record(audit_ctx_t *a, const char *actor, uint32_t peer,
                  audit_result_t result, const char *action,
                  const char *target, const char *fmt, ...) {
    if (!a || !a->ready) return;

    audit_entry_t e;
    memset(&e, 0, sizeof(e));
    e.when   = time(NULL);
    e.peer   = peer;
    e.result = result;
    snprintf(e.actor,  sizeof(e.actor),  "%s", actor  && *actor  ? actor  : "-");
    snprintf(e.action, sizeof(e.action), "%s", action && *action ? action : "-");
    snprintf(e.target, sizeof(e.target), "%s", target && *target ? target : "-");

    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e.detail, sizeof(e.detail), fmt, ap);
        va_end(ap);
    }

    pthread_mutex_lock(&a->lock);

    e.seq = ++a->seq;

    char body[2048];
    int bl = format_body(body, sizeof(body), &e);
    if (bl < 0) { pthread_mutex_unlock(&a->lock); return; }

    chain(a->prev_hash, body, e.hash);
    snprintf(a->prev_hash, sizeof(a->prev_hash), "%s", e.hash);

    /* The ring first: it must hold the record even when the disk does not,
     * because a full disk is one of the conditions during which somebody
     * most wants to know what was being done to the appliance. */
    a->ring[a->idx] = e;
    a->idx = (a->idx + 1) % AUDIT_RING;
    if (a->count < AUDIT_RING) a->count++;

    if (a->fd >= 0) {
        char line[2304];
        int n = snprintf(line, sizeof(line), "%s\t%s\n", body, e.hash);
        if (n > 0 && write(a->fd, line, (size_t)n) == n) {
            /*
             * fsync per record. An audit trail that is still in the page
             * cache when the appliance loses power has not recorded
             * anything, and these are rare events -- an operator changing
             * a setting, not a packet.
             */
            fsync(a->fd);
            a->written++;
        } else {
            a->write_errors++;
        }
    }

    pthread_mutex_unlock(&a->lock);
}

int audit_recent(audit_ctx_t *a, audit_entry_t *out, int max) {
    if (!a || !a->ready || !out || max <= 0) return 0;
    pthread_mutex_lock(&a->lock);
    int n = 0;
    for (int i = 0; i < a->count && n < max; i++) {
        int k = (a->idx - 1 - i + AUDIT_RING * 2) % AUDIT_RING;
        out[n++] = a->ring[k];
    }
    pthread_mutex_unlock(&a->lock);
    return n;
}

int audit_verify(const char *path, char *why, size_t whylen) {
    if (why && whylen) why[0] = 0;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (why) snprintf(why, whylen, "cannot read %s", path);
        return -1;
    }

    char prev[AUDIT_HASH_HEX];
    snprintf(prev, sizeof(prev), "%s", GENESIS);

    char line[2304];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = 0;
        if (!line[0]) continue;

        char *tab = strrchr(line, '\t');
        if (!tab || strlen(tab + 1) != AUDIT_HASH_HEX - 1) {
            fclose(f);
            if (why) snprintf(why, whylen, "record %d has no hash", lineno);
            return lineno;
        }
        *tab = 0;
        const char *claimed = tab + 1;

        char want[AUDIT_HASH_HEX];
        chain(prev, line, want);
        if (strcmp(want, claimed) != 0) {
            fclose(f);
            if (why)
                snprintf(why, whylen,
                         "record %d does not follow record %d -- it was "
                         "edited, or a record before it was removed",
                         lineno, lineno - 1);
            return lineno;
        }
        snprintf(prev, sizeof(prev), "%s", claimed);
    }
    fclose(f);

    if (why) snprintf(why, whylen, "%d record(s), chain intact", lineno);
    return 0;
}
