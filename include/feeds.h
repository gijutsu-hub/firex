#ifndef FIREX_FEEDS_H
#define FIREX_FEEDS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

/*
 * Blocklist feeds: lists of addresses and domains, fetched on a schedule and
 * merged into one structure the datapath can ask cheaply.
 *
 * Addresses are kept as merged, sorted ranges rather than a list of CIDRs.
 * A feed of 200,000 prefixes is common, overlaps between feeds are normal,
 * and a binary search over merged ranges answers in a dozen comparisons
 * regardless. Domains are a sorted table, and a lookup walks the parent
 * labels so one entry covers a whole subtree.
 *
 * A fetch that fails leaves the previous list in place. A blocklist that
 * empties itself because a server was briefly unreachable would quietly stop
 * protecting anything, which is worse than being stale.
 */

#define FEED_MAX_FEEDS     16
#define FEED_MAX_RANGES    262144
#define FEED_MAX_DOMAINS   131072
#define FEED_NAME_LEN      48
#define FEED_URL_LEN       256
#define FEED_DOMAIN_LEN    256

typedef enum { FEED_IP = 0, FEED_DOMAIN } feed_kind_t;

typedef struct { uint32_t lo, hi; } feed_range_t;   /* host order, inclusive */

typedef struct {
    char        name[FEED_NAME_LEN];
    char        url[FEED_URL_LEN];      /* http://, https:// or file:// */
    feed_kind_t kind;
    int         refresh_minutes;
    bool        enabled;

    time_t      last_fetch, last_change;
    int         entries;
    unsigned long hits;
    char        last_error[192];
} feed_t;

typedef struct {
    feed_t          feeds[FEED_MAX_FEEDS];
    int             feed_count;

    feed_range_t   *ranges;             /* sorted, merged */
    int             range_count, range_cap;

    char          **domains;            /* sorted, lowercased */
    int             domain_count, domain_cap;

    bool            enabled;
    unsigned long   lookups, ip_hits, domain_hits;

    bool            running;
    pthread_t       thread;
    pthread_mutex_t lock;
} feeds_ctx_t;

int  feeds_init(feeds_ctx_t *f);
void feeds_shutdown(feeds_ctx_t *f);

int  feeds_add(feeds_ctx_t *f, const feed_t *feed);

/* Fetches one feed and merges it in. Returns entries loaded, or -1 with the
 * reason recorded on the feed. */
int  feeds_refresh_one(feeds_ctx_t *f, int index);

/* Fetches every feed that is due. Returns how many were refreshed. */
int  feeds_refresh_due(feeds_ctx_t *f, time_t now);

int  feeds_start(feeds_ctx_t *f);
void feeds_stop(feeds_ctx_t *f);

/* ── lookups, on the datapath ── */
bool feeds_match_ip(feeds_ctx_t *f, uint32_t ip_net_order);

/* Matches the name and every parent label, so "evil.com" covers
 * "a.b.evil.com". The input is not required to be lowercase. */
bool feeds_match_domain(feeds_ctx_t *f, const char *host);

/* ── building, exposed for tests ── */

/* Parses a list body into ranges or domains and installs it, replacing
 * whatever that feed contributed before. Returns entries parsed. */
int  feeds_load_body(feeds_ctx_t *f, int index, const char *body, size_t len);

/* CIDR or plain address to an inclusive range. False when unparseable. */
bool feed_parse_cidr(const char *s, uint32_t *lo, uint32_t *hi);

/* Sorts and merges overlapping or adjacent ranges in place; returns the new
 * count. Exposed because merging is where a range table gets this wrong. */
int  feed_merge_ranges(feed_range_t *r, int n);

/* Fetches a URL into a freshly allocated buffer the caller frees. Supports
 * http://, https:// and file://. Returns the length, or -1 with `why`. */
long feed_fetch(const char *url, char **out, char *why, size_t whylen);

const char *feed_kind_name(feed_kind_t k);
feed_kind_t feed_kind_from(const char *s);

#endif
