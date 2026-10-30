#ifndef FIREX_RESPONSE_H
#define FIREX_RESPONSE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "zone.h"

/*
 * Automatic response.
 *
 * A detection on its own is not grounds for blocking a host: a single
 * signature hit can be a false positive, and a firewall that blackholes a
 * workstation over one packet will be turned off by the people who run it.
 * So detections accumulate a score, blocking happens at a threshold, repeat
 * offenders are held longer, and a quiet host decays back to zero.
 *
 * Quarantine rather than drop is the default, and it is what makes
 * ZONE_QUARANTINE mean something: a quarantined source is evaluated against
 * that row of the forwarding matrix instead of its own. What quarantine
 * permits is then the operator's policy, not a hardcoded rule here.
 */

#define RESP_MAX_OFFENDERS   4096
#define RESP_SET             "firex_quarantine"
#define RESP_REASON_LEN      160

typedef struct {
    bool enabled;
    int  threshold;           /* score at which a host is acted on */
    int  block_minutes;       /* how long the first block lasts */
    bool escalate;            /* double the duration on each repeat */
    int  max_block_minutes;   /* ceiling for the escalation */
    int  decay_minutes;       /* score halves after this long with no hits */
    bool quarantine;          /* true: reclassify; false: drop outright */
    bool notify;              /* log every action */
} response_cfg_t;

typedef struct {
    uint32_t ip;
    int      score;
    int      detections;
    time_t   first_seen, last_seen, last_decay;
    time_t   blocked_until;   /* 0 while not blocked */
    int      block_count;
    char     last_reason[RESP_REASON_LEN];
    bool     used;
} offender_t;

typedef struct {
    response_cfg_t  cfg;
    offender_t      offenders[RESP_MAX_OFFENDERS];

    unsigned long   recorded, blocks, releases, escalations, evicted;
    bool            apply_net;

    bool            running;
    pthread_t       reaper;
    pthread_mutex_t lock;
} response_ctx_t;

int  response_init(response_ctx_t *r, const response_cfg_t *cfg, bool apply_net);
int  response_start(response_ctx_t *r);
void response_stop(response_ctx_t *r);
void response_shutdown(response_ctx_t *r);

/*
 * Records one detection against a source. Returns true when this detection
 * is what tipped the host over the threshold -- so the caller logs a new
 * block once, not on every packet after it.
 */
bool response_record(response_ctx_t *r, uint32_t ip, int severity,
                     const char *reason);

/* True while the host is inside its block window. Safe on the datapath. */
bool response_is_blocked(response_ctx_t *r, uint32_t ip);

/* Clears a host entirely: score, history and block. */
int  response_release(response_ctx_t *r, uint32_t ip);

/* Expires finished blocks and decays idle scores. Returns how many hosts
 * were released. Exposed so a test can drive the clock. */
int  response_reap(response_ctx_t *r, time_t now);

int  response_snapshot(response_ctx_t *r, offender_t *out, int max);

/* The score one detection of this severity is worth. */
int  response_score_for(int severity);

/* The zone a blocked source should be evaluated as, or ZONE_MAX when the
 * host is not blocked or quarantine is off. */
zone_t response_zone_for(response_ctx_t *r, uint32_t ip);

int  response_install_rules(response_ctx_t *r);
int  response_teardown_rules(response_ctx_t *r);

#endif
