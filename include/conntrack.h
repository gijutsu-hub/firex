#ifndef FIREX_CONNTRACK_H
#define FIREX_CONNTRACK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Connection state table.
 *
 * FireX does not keep its own state table -- the kernel's conntrack already
 * does, and duplicating it would mean two views that can disagree. This reads
 * the kernel's, from whichever source the running kernel offers:
 *
 *   1. /proc/net/nf_conntrack      needs CONFIG_NF_CONNTRACK_PROCFS and root
 *   2. `conntrack -L`              the conntrack-tools package
 *   3. neither                     the table size is still readable from
 *                                  sysctl, so the capacity gauge works even
 *                                  when individual flows cannot be listed
 *
 * Which one was used is reported, so "no connections" is never confused with
 * "cannot see connections".
 */

#define CT_MAX_ENTRIES 4096
#define CT_PROTO_LEN   8
#define CT_STATE_LEN   16

typedef enum {
    CT_SRC_NONE = 0,
    CT_SRC_PROCFS,
    CT_SRC_TOOL
} ct_source_t;

typedef struct {
    char     proto[CT_PROTO_LEN];
    uint32_t src, dst;             /* network order */
    uint16_t sport, dport;
    char     state[CT_STATE_LEN];  /* ESTABLISHED, TIME_WAIT, ... */
    uint64_t packets, bytes;       /* original direction */
    uint64_t rx_packets, rx_bytes; /* reply direction */
    int      ttl;                  /* seconds before the entry expires */
    bool     assured;
} ct_entry_t;

typedef struct {
    ct_source_t source;
    char        source_detail[256];  /* why, when source is CT_SRC_NONE */
    uint32_t    count;               /* kernel's own total, from sysctl */
    uint32_t    max;
    int         listed;              /* how many entries were readable */
} ct_stats_t;

/*
 * Fills `out` with up to `max` entries and always fills `st`. Returns the
 * number written, or -1 only when `out`/`st` are unusable -- an unreadable
 * table is reported through `st`, not as an error, because the capacity
 * figures are still meaningful.
 */
int  ct_read(ct_entry_t *out, int max, ct_stats_t *st);

/* Table occupancy alone; cheap enough for the per-interval sampler. */
uint32_t ct_count(void);

const char *ct_source_str(ct_source_t s);

/* Parses one /proc/net/nf_conntrack line. Exposed so the format handling can
 * be tested without the kernel providing the file. Returns true on success. */
bool ct_parse_line(const char *line, ct_entry_t *e);

#endif
