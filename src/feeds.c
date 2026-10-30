/*
 * Blocklist feeds. See include/feeds.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include "feeds.h"
#include "egress.h"
#include "brand.h"

const char *feed_kind_name(feed_kind_t k) {
    return k == FEED_DOMAIN ? "domain" : "ip";
}

feed_kind_t feed_kind_from(const char *s) {
    return (s && (!strcasecmp(s, "domain") || !strcasecmp(s, "dns")))
        ? FEED_DOMAIN : FEED_IP;
}

int feeds_init(feeds_ctx_t *f) {
    memset(f, 0, sizeof(*f));
    pthread_mutex_init(&f->lock, NULL);
    return 0;
}

void feeds_shutdown(feeds_ctx_t *f) {
    if (!f) return;
    feeds_stop(f);
    free(f->ranges);
    for (int i = 0; i < f->domain_count; i++) free(f->domains[i]);
    free(f->domains);
    f->ranges = NULL;
    f->domains = NULL;
    pthread_mutex_destroy(&f->lock);
}

int feeds_add(feeds_ctx_t *f, const feed_t *feed) {
    if (!feed->name[0] || !feed->url[0]) return -1;

    pthread_mutex_lock(&f->lock);
    if (f->feed_count >= FEED_MAX_FEEDS) {
        pthread_mutex_unlock(&f->lock);
        return -1;
    }
    for (int i = 0; i < f->feed_count; i++)
        if (!strcmp(f->feeds[i].name, feed->name)) {
            pthread_mutex_unlock(&f->lock);
            return -1;
        }

    feed_t *d = &f->feeds[f->feed_count];
    *d = *feed;
    if (d->refresh_minutes <= 0) d->refresh_minutes = 1440;
    f->feed_count++;
    pthread_mutex_unlock(&f->lock);
    return 0;
}

/* ═══════════════════ ranges ═══════════════════ */

bool feed_parse_cidr(const char *s, uint32_t *lo, uint32_t *hi) {
    if (!s || !*s) return false;

    char buf[64];
    if (snprintf(buf, sizeof(buf), "%s", s) >= (int)sizeof(buf)) return false;

    /* Trim trailing whitespace and anything after a comment marker. */
    char *c = strpbrk(buf, "#;");
    if (c) *c = '\0';
    for (char *p = buf + strlen(buf); p > buf && isspace((unsigned char)p[-1]); )
        *--p = '\0';
    char *start = buf;
    while (*start && isspace((unsigned char)*start)) start++;
    if (!*start) return false;

    int bits = 32;
    char *slash = strchr(start, '/');
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long b = strtol(slash + 1, &end, 10);
        if (end == slash + 1 || *end || b < 0 || b > 32) return false;
        bits = (int)b;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, start, &a) != 1) return false;

    uint32_t host = ntohl(a.s_addr);
    uint32_t mask = bits ? (0xffffffffu << (32 - bits)) : 0;
    *lo = host & mask;
    *hi = *lo | ~mask;
    return true;
}

static int cmp_range(const void *a, const void *b) {
    const feed_range_t *x = a, *y = b;
    if (x->lo < y->lo) return -1;
    if (x->lo > y->lo) return 1;
    return 0;
}

int feed_merge_ranges(feed_range_t *r, int n) {
    if (n <= 1) return n;
    qsort(r, (size_t)n, sizeof(*r), cmp_range);

    int w = 0;
    for (int i = 1; i < n; i++) {
        /*
         * Merge when the next range overlaps or merely touches: [1-5] and
         * [6-9] are one range, and leaving them apart doubles the table for
         * no benefit. The hi+1 guard keeps 255.255.255.255 from wrapping.
         */
        if (r[i].lo <= r[w].hi ||
            (r[w].hi != 0xffffffffu && r[i].lo == r[w].hi + 1)) {
            if (r[i].hi > r[w].hi) r[w].hi = r[i].hi;
        } else {
            r[++w] = r[i];
        }
    }
    return w + 1;
}

/* ═══════════════════ domains ═══════════════════ */

static int cmp_domain(const void *a, const void *b) {
    return strcmp(*(char * const *)a, *(char * const *)b);
}

static bool domain_present(feeds_ctx_t *f, const char *name) {
    int lo = 0, hi = f->domain_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int c = strcmp(f->domains[mid], name);
        if (c == 0) return true;
        if (c < 0) lo = mid + 1;
        else       hi = mid - 1;
    }
    return false;
}

/* ═══════════════════ parsing a list body ═══════════════════ */

int feeds_load_body(feeds_ctx_t *f, int index, const char *body, size_t len) {
    if (index < 0 || index >= f->feed_count || !body) return -1;
    feed_t *fd = &f->feeds[index];

    if (fd->kind == FEED_IP) {
        feed_range_t *tmp = malloc(sizeof(feed_range_t) * FEED_MAX_RANGES);
        if (!tmp) return -1;
        int n = 0;

        const char *p = body, *end = body + len;
        while (p < end && n < FEED_MAX_RANGES) {
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            size_t linelen = nl ? (size_t)(nl - p) : (size_t)(end - p);

            char line[80];
            if (linelen && linelen < sizeof(line)) {
                memcpy(line, p, linelen);
                line[linelen] = '\0';

                /*
                 * Many feeds are "address<space>comment" or plain CIDR.
                 * Take the first token and let the parser reject the rest.
                 */
                char *sp = strpbrk(line, " \t\r");
                if (sp) *sp = '\0';

                uint32_t lo, hi;
                if (line[0] && line[0] != '#' && feed_parse_cidr(line, &lo, &hi)) {
                    tmp[n].lo = lo;
                    tmp[n].hi = hi;
                    n++;
                }
            }
            if (!nl) break;
            p = nl + 1;
        }

        if (n == 0) {
            free(tmp);
            snprintf(fd->last_error, sizeof(fd->last_error),
                     "no usable addresses in the list");
            return 0;
        }

        /*
         * Feeds are merged together rather than kept apart: the datapath
         * asks one question, not one per feed. The cost is that a feed's
         * contribution cannot be withdrawn without rebuilding, which is what
         * a refresh does anyway.
         */
        pthread_mutex_lock(&f->lock);
        int total = f->range_count + n;
        feed_range_t *merged = malloc(sizeof(feed_range_t) * (size_t)total);
        if (!merged) {
            pthread_mutex_unlock(&f->lock);
            free(tmp);
            return -1;
        }
        if (f->range_count)
            memcpy(merged, f->ranges, sizeof(feed_range_t) * (size_t)f->range_count);
        memcpy(merged + f->range_count, tmp, sizeof(feed_range_t) * (size_t)n);

        int final = feed_merge_ranges(merged, total);
        free(f->ranges);
        f->ranges = merged;
        f->range_count = final;
        f->range_cap = total;
        pthread_mutex_unlock(&f->lock);

        free(tmp);
        fd->entries = n;
        return n;
    }

    /* ── domains ── */
    pthread_mutex_lock(&f->lock);
    int added = 0;
    const char *p = body, *end = body + len;

    while (p < end && f->domain_count < FEED_MAX_DOMAINS) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = nl ? (size_t)(nl - p) : (size_t)(end - p);

        char line[FEED_DOMAIN_LEN];
        if (linelen && linelen < sizeof(line)) {
            memcpy(line, p, linelen);
            line[linelen] = '\0';

            char *c = strpbrk(line, "#\r");
            if (c) *c = '\0';

            char *tok = line;
            while (*tok && isspace((unsigned char)*tok)) tok++;

            /*
             * A hosts-file feed is "0.0.0.0 evil.com". Take the second token
             * when the first parses as an address, so both shapes work.
             */
            char *sp = strpbrk(tok, " \t");
            if (sp) {
                struct in_addr probe;
                *sp = '\0';
                if (inet_pton(AF_INET, tok, &probe) == 1) {
                    tok = sp + 1;
                    while (*tok && isspace((unsigned char)*tok)) tok++;
                    char *sp2 = strpbrk(tok, " \t");
                    if (sp2) *sp2 = '\0';
                }
            }

            for (char *q = tok; *q; q++) *q = (char)tolower((unsigned char)*q);

            if (*tok && *tok != '#' && strchr(tok, '.') &&
                !domain_present(f, tok)) {
                if (f->domain_count >= f->domain_cap) {
                    int ncap = f->domain_cap ? f->domain_cap * 2 : 1024;
                    char **d = realloc(f->domains, (size_t)ncap * sizeof(char *));
                    if (!d) break;
                    f->domains = d;
                    f->domain_cap = ncap;
                }
                f->domains[f->domain_count] = strdup(tok);
                if (!f->domains[f->domain_count]) break;
                f->domain_count++;
                added++;
                /* Keep sorted so domain_present() stays a binary search. */
                qsort(f->domains, (size_t)f->domain_count, sizeof(char *),
                      cmp_domain);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    pthread_mutex_unlock(&f->lock);

    fd->entries = added;
    return added;
}

/* ═══════════════════ fetching ═══════════════════ */

static long read_all(BIO *bio, char **out, char *why, size_t whylen) {
    size_t cap = 1 << 20, len = 0;
    char *buf = malloc(cap);
    if (!buf) { snprintf(why, whylen, "out of memory"); return -1; }

    for (;;) {
        if (len + 65536 > cap) {
            if (cap > (64u << 20)) {       /* 64 MB is plenty for a blocklist */
                snprintf(why, whylen, "the list is larger than 64 MB");
                free(buf);
                return -1;
            }
            char *n = realloc(buf, cap * 2);
            if (!n) { free(buf); snprintf(why, whylen, "out of memory"); return -1; }
            buf = n;
            cap *= 2;
        }
        int r = BIO_read(bio, buf + len, 65536);
        if (r > 0) { len += (size_t)r; continue; }
        if (BIO_should_retry(bio)) continue;
        break;
    }
    buf[len] = '\0';
    *out = buf;
    return (long)len;
}

/* Strips the HTTP response headers and checks the status. */
static long http_body(char *raw, long len, char **body, char *why, size_t whylen) {
    if (len < 12 || strncmp(raw, "HTTP/", 5) != 0) {
        snprintf(why, whylen, "the reply is not HTTP");
        return -1;
    }
    int status = atoi(raw + 9);
    if (status < 200 || status >= 300) {
        char line[80] = "";
        char *nl = strpbrk(raw, "\r\n");
        if (nl) snprintf(line, sizeof(line), "%.*s", (int)(nl - raw), raw);
        snprintf(why, whylen, "the server answered: %s", line[0] ? line : "?");
        return -1;
    }
    char *sep = strstr(raw, "\r\n\r\n");
    if (!sep) {
        snprintf(why, whylen, "the reply has no body");
        return -1;
    }
    *body = sep + 4;
    return len - (long)(*body - raw);
}

long feed_fetch(const char *url, char **out, char *why, size_t whylen) {
    if (why && whylen) why[0] = '\0';
    if (!url || !out) return -1;
    *out = NULL;

    /* ── a local file, for an air-gapped appliance or a test ── */
    if (!strncmp(url, "file://", 7)) {
        FILE *f = fopen(url + 7, "rb");
        if (!f) {
            snprintf(why, whylen, "cannot open %s (%s)", url + 7, strerror(errno));
            return -1;
        }
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        rewind(f);
        if (n < 0 || n > (64L << 20)) {
            fclose(f);
            snprintf(why, whylen, "the file is empty or larger than 64 MB");
            return -1;
        }
        char *buf = malloc((size_t)n + 1);
        if (!buf) { fclose(f); snprintf(why, whylen, "out of memory"); return -1; }
        size_t got = fread(buf, 1, (size_t)n, f);
        fclose(f);
        buf[got] = '\0';
        *out = buf;
        return (long)got;
    }

    /*
     * Everything past here opens a socket on the appliance's own behalf,
     * so the air gap gets asked first -- after the file:// branch above
     * and not before it, because a list carried in by hand is exactly how
     * an isolated appliance is meant to receive signatures, and refusing
     * that would make the gap useless rather than strict.
     */
    if (!egress_permitted(EGRESS_FEEDS, why, whylen)) {
        if (why && whylen && !why[0])
            snprintf(why, whylen, "the air gap is shut; use a file:// list");
        return -1;
    }

    bool tls;
    const char *rest;
    if      (!strncmp(url, "https://", 8)) { tls = true;  rest = url + 8; }
    else if (!strncmp(url, "http://",  7)) { tls = false; rest = url + 7; }
    else {
        snprintf(why, whylen, "only http://, https:// and file:// are supported");
        return -1;
    }

    char host[256];
    const char *slash = strchr(rest, '/');
    size_t hlen = slash ? (size_t)(slash - rest) : strlen(rest);
    if (hlen == 0 || hlen >= sizeof(host)) {
        snprintf(why, whylen, "the URL has no host");
        return -1;
    }
    memcpy(host, rest, hlen);
    host[hlen] = '\0';
    const char *path = slash ? slash : "/";

    char hostonly[256];
    snprintf(hostonly, sizeof(hostonly), "%s", host);
    char *colon = strrchr(hostonly, ':');
    if (colon) *colon = '\0';

    char target[320];
    snprintf(target, sizeof(target), "%s%s", host,
             strchr(host, ':') ? "" : (tls ? ":443" : ":80"));

    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;
    long rc = -1;
    char *raw = NULL;

    if (tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { snprintf(why, whylen, "no TLS context"); return -1; }

        /*
         * Verify the certificate. A blocklist fetched over an unverified
         * channel is a list an attacker can choose, which is worse than no
         * list at all.
         */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            snprintf(why, whylen, "no trusted CA store on this system");
            SSL_CTX_free(ctx);
            return -1;
        }

        bio = BIO_new_ssl_connect(ctx);
        if (!bio) { SSL_CTX_free(ctx); snprintf(why, whylen, "no BIO"); return -1; }

        SSL *ssl = NULL;
        BIO_get_ssl(bio, &ssl);
        if (!ssl) {
            BIO_free_all(bio); SSL_CTX_free(ctx);
            snprintf(why, whylen, "no SSL handle");
            return -1;
        }
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        SSL_set_tlsext_host_name(ssl, hostonly);      /* SNI */
        SSL_set1_host(ssl, hostonly);                 /* and check the name */
        BIO_set_conn_hostname(bio, target);
    } else {
        bio = BIO_new_connect(target);
        if (!bio) { snprintf(why, whylen, "no BIO"); return -1; }
    }

    if (BIO_do_connect(bio) <= 0) {
        snprintf(why, whylen, "cannot connect to %s", target);
        goto out;
    }
    if (tls && BIO_do_handshake(bio) <= 0) {
        snprintf(why, whylen,
                 "the TLS handshake with %s failed; the certificate did not "
                 "verify", hostonly);
        goto out;
    }

    char req[640];
    int rl = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s/%s\r\n"
        "Accept: text/plain\r\nConnection: close\r\n\r\n",
        path, hostonly, BRAND_PRODUCT, BRAND_VERSION);
    if (rl <= 0 || BIO_write(bio, req, rl) != rl) {
        snprintf(why, whylen, "could not send the request");
        goto out;
    }

    long n = read_all(bio, &raw, why, whylen);
    if (n < 0) goto out;

    char *body = NULL;
    long blen = http_body(raw, n, &body, why, whylen);
    if (blen < 0) { free(raw); raw = NULL; goto out; }

    /* Hand back just the body, in its own allocation. */
    char *copy = malloc((size_t)blen + 1);
    if (!copy) { free(raw); raw = NULL; snprintf(why, whylen, "out of memory"); goto out; }
    memcpy(copy, body, (size_t)blen);
    copy[blen] = '\0';
    free(raw);
    raw = NULL;

    *out = copy;
    rc = blen;

out:
    if (bio) BIO_free_all(bio);
    if (ctx) SSL_CTX_free(ctx);
    free(raw);
    return rc;
}

int feeds_refresh_one(feeds_ctx_t *f, int index) {
    if (index < 0 || index >= f->feed_count) return -1;
    feed_t *fd = &f->feeds[index];
    if (!fd->enabled) return 0;

    char *body = NULL;
    char why[192] = "";
    long n = feed_fetch(fd->url, &body, why, sizeof(why));

    fd->last_fetch = time(NULL);

    if (n < 0) {
        /* Keep whatever we had: a list that empties itself because a server
         * blipped would quietly stop protecting anything. */
        snprintf(fd->last_error, sizeof(fd->last_error), "%s", why);
        fprintf(stderr, "[%s] feed '%s': %s (keeping %d existing entries)\n",
                BRAND_PRODUCT, fd->name, why, fd->entries);
        free(body);
        return -1;
    }

    fd->last_error[0] = '\0';
    int loaded = feeds_load_body(f, index, body, (size_t)n);
    free(body);

    if (loaded > 0) {
        fd->last_change = time(NULL);
        printf("[%s] feed '%s': %d %s entries\n", BRAND_PRODUCT, fd->name,
               loaded, feed_kind_name(fd->kind));
    }
    return loaded;
}

int feeds_refresh_due(feeds_ctx_t *f, time_t now) {
    int done = 0;
    for (int i = 0; i < f->feed_count; i++) {
        feed_t *fd = &f->feeds[i];
        if (!fd->enabled) continue;
        if (fd->last_fetch &&
            now - fd->last_fetch < (time_t)fd->refresh_minutes * 60) continue;
        if (feeds_refresh_one(f, i) >= 0) done++;
    }
    return done;
}

static void *feeds_thread(void *arg) {
    feeds_ctx_t *f = arg;
    while (f->running) {
        feeds_refresh_due(f, time(NULL));
        /* A minute of granularity is plenty for lists refreshed hourly. */
        for (int i = 0; i < 600 && f->running; i++) {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int feeds_start(feeds_ctx_t *f) {
    if (!f->enabled || !f->feed_count) return 0;

    f->running = true;
    if (pthread_create(&f->thread, NULL, feeds_thread, f) != 0) {
        f->running = false;
        fprintf(stderr, "[%s] could not start the feed refresher\n", BRAND_PRODUCT);
        return -1;
    }
    printf("[%s] Blocklists: %d feed(s)\n", BRAND_PRODUCT, f->feed_count);
    return 0;
}

void feeds_stop(feeds_ctx_t *f) {
    if (!f->running) return;
    f->running = false;
    pthread_join(f->thread, NULL);
}

/* ═══════════════════ lookups ═══════════════════ */

bool feeds_match_ip(feeds_ctx_t *f, uint32_t ip_net_order) {
    if (!f->enabled || !f->range_count) return false;

    uint32_t ip = ntohl(ip_net_order);

    pthread_mutex_lock(&f->lock);
    f->lookups++;

    int lo = 0, hi = f->range_count - 1;
    bool hit = false;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (ip < f->ranges[mid].lo)      hi = mid - 1;
        else if (ip > f->ranges[mid].hi) lo = mid + 1;
        else { hit = true; break; }
    }
    if (hit) f->ip_hits++;
    pthread_mutex_unlock(&f->lock);
    return hit;
}

bool feeds_match_domain(feeds_ctx_t *f, const char *host) {
    if (!f->enabled || !f->domain_count || !host || !*host) return false;

    char name[FEED_DOMAIN_LEN];
    size_t n = 0;
    for (const char *p = host; *p && n + 1 < sizeof(name); p++) {
        if (*p == ':') break;                 /* strip any :port */
        name[n++] = (char)tolower((unsigned char)*p);
    }
    name[n] = '\0';
    while (n && name[n-1] == '.') name[--n] = '\0';   /* trailing root dot */
    if (!n) return false;

    pthread_mutex_lock(&f->lock);
    f->lookups++;

    /*
     * Walk the parent labels so one entry covers a subtree: a list holding
     * "evil.com" should catch "tracker.ads.evil.com".
     */
    bool hit = false;
    for (const char *probe = name; probe && *probe; ) {
        if (domain_present(f, probe)) { hit = true; break; }
        const char *dot = strchr(probe, '.');
        probe = dot ? dot + 1 : NULL;
    }
    if (hit) f->domain_hits++;
    pthread_mutex_unlock(&f->lock);
    return hit;
}
