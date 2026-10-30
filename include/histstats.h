#ifndef FIREX_HISTSTATS_H
#define FIREX_HISTSTATS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "firewall.h"

/*
 * Historical counters.
 *
 * pfSense keeps these in RRD files. A ring in memory is simpler, costs about
 * 60 KB, and loses its history on restart -- an acceptable trade for a box
 * whose job is to be up. Counters that only ever climb are stored as the
 * delta over each interval, so a graph shows a rate without the reader having
 * to differentiate; the rest are point-in-time gauges.
 */

#define HIST_SAMPLES       1440   /* 12 hours at the default 30s interval */
#define HIST_MIN_INTERVAL  5
#define HIST_MAX_INTERVAL  3600
#define HIST_DEFAULT_INTERVAL 30

typedef struct {
    time_t   when;

    /* deltas over the interval */
    uint32_t packets, allowed, blocked;
    uint32_t ivr_allowed, ivr_denied;
    uint32_t pages_served, sched_skipped;
    uint32_t tag_violations;

    /* gauges */
    uint32_t ct_count;
    uint16_t wan_rtt_x10[2];    /* tenths of a millisecond */
    uint8_t  wan_loss[2];       /* percent */
    int8_t   active_wan;        /* -1 when nothing is up */
} hist_sample_t;

typedef struct {
    hist_sample_t   ring[HIST_SAMPLES];
    int             idx;        /* next slot to write */
    int             len;        /* how many are valid */
    int             interval_sec;

    /* previous cumulative readings, for the deltas above */
    bool            primed;
    unsigned long   p_packets, p_allowed, p_blocked;
    unsigned long   p_ivr_allowed, p_ivr_denied;
    unsigned long   p_pages, p_sched_skipped, p_tagvio;

    bool            running;
    pthread_t       thread;
    pthread_mutex_t lock;

    firewall_ctx_t *fw;         /* may be NULL; those series then read zero */
} hist_ctx_t;

int  hist_init(hist_ctx_t *h, firewall_ctx_t *fw, int interval_sec);
int  hist_start(hist_ctx_t *h);
void hist_stop(hist_ctx_t *h);
void hist_shutdown(hist_ctx_t *h);

/* Copies up to `max` samples, oldest first, and returns how many. */
int  hist_snapshot(hist_ctx_t *h, hist_sample_t *out, int max);

/* Builds one sample from the live counters and files it. Called by the
 * thread; exposed so a test can drive the clock itself. */
void hist_tick(hist_ctx_t *h);

/* Files a prepared sample. Deltas are taken as given -- this is the seam the
 * tests push through. */
void hist_push(hist_ctx_t *h, const hist_sample_t *s);

#endif
