#ifndef FIREX_AUDIT_H
#define FIREX_AUDIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "brand.h"

/*
 * The administrative audit trail: who did what to this appliance.
 *
 * This is NOT the packet log. logger.c records traffic; this records the
 * operators. They answer different questions and they have different
 * readers -- after an incident nobody asks which packets were dropped on
 * Tuesday, they ask who turned the air gap off on Tuesday, from where, and
 * whether it was supposed to be them.
 *
 * Before this existed those answers were five fprintf(stderr) calls. They
 * reached journald, which rotates on its own schedule, is not queryable
 * from the console, and is writable by anyone who reaches root on the box
 * -- which is exactly the person whose actions an audit trail exists to
 * record.
 *
 * TAMPER EVIDENCE. Each record carries a SHA-256 over the previous
 * record's hash and its own text, so the file is a chain. Removing a line,
 * reordering two, or editing a field breaks every hash after it, and
 * audit_verify() names the first record that does not follow. This does
 * not make the log unalterable -- nothing on a box the attacker owns can
 * be -- but it turns a silent deletion into a visible gap, which is the
 * property an auditor is actually asking for.
 */

#define AUDIT_ACTOR_LEN    40
#define AUDIT_ACTION_LEN   48
#define AUDIT_TARGET_LEN   96
#define AUDIT_DETAIL_LEN  192
#define AUDIT_HASH_HEX     65          /* 32 bytes, hex, NUL */
#define AUDIT_RING        512          /* what /api/audit can show */

typedef enum {
    AUDIT_OK,          /* the action was carried out            */
    AUDIT_DENIED,      /* refused: role, CSRF, validation        */
    AUDIT_FAILED       /* attempted and failed: I/O, kernel      */
} audit_result_t;

typedef struct {
    uint64_t       seq;
    time_t         when;
    char           actor[AUDIT_ACTOR_LEN];
    uint32_t       peer;               /* network order; 0 = local */
    char           action[AUDIT_ACTION_LEN];
    char           target[AUDIT_TARGET_LEN];
    audit_result_t result;
    char           detail[AUDIT_DETAIL_LEN];
    char           hash[AUDIT_HASH_HEX];
} audit_entry_t;

typedef struct {
    bool            ready;
    char            path[256];
    int             fd;                /* append-only, O_APPEND */
    uint64_t        seq;
    char            prev_hash[AUDIT_HASH_HEX];

    audit_entry_t   ring[AUDIT_RING];
    int             count, idx;

    unsigned long   written;
    unsigned long   write_errors;

    pthread_mutex_t lock;
} audit_ctx_t;

/*
 * Opens (and creates) the trail, reading back the last record's hash so a
 * restart continues the chain rather than starting a second one. A
 * directory that cannot be written is reported but not fatal: an appliance
 * that refuses to boot because it cannot log is an appliance that an
 * attacker takes offline by filling a disk.
 */
int  audit_open(audit_ctx_t *a, const char *path);
void audit_close(audit_ctx_t *a);

/*
 * Record one action. `detail` is printf-style and may be NULL. Never
 * blocks on anything but the file write, and never fails the caller --
 * the action has already happened, and refusing to return would not
 * un-happen it.
 */
void audit_record(audit_ctx_t *a, const char *actor, uint32_t peer,
                  audit_result_t result, const char *action,
                  const char *target, const char *fmt, ...)
     __attribute__((format(printf, 7, 8)));

/* Most recent first, into `out`. Returns how many were written. */
int  audit_recent(audit_ctx_t *a, audit_entry_t *out, int max);

/*
 * Walks the file and recomputes the chain. Returns 0 when every record
 * follows from the one before it. On a break, returns the 1-based line
 * number and describes it in (why, whylen) -- "record 412 does not follow
 * record 411" is a sentence an auditor can act on; "corrupt" is not.
 */
int  audit_verify(const char *path, char *why, size_t whylen);

const char *audit_result_name(audit_result_t r);

#endif /* FIREX_AUDIT_H */
