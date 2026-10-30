/*
 * Historical counters. See include/histstats.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "histstats.h"
#include "inspect.h"
#include "conntrack.h"
#include "gwmon.h"
#include "brand.h"

int hist_init(hist_ctx_t *h, firewall_ctx_t *fw, int interval_sec) {
    memset(h, 0, sizeof(*h));
    pthread_mutex_init(&h->lock, NULL);
    h->fw = fw;

    h->interval_sec = interval_sec > 0 ? interval_sec : HIST_DEFAULT_INTERVAL;
    if (h->interval_sec < HIST_MIN_INTERVAL) h->interval_sec = HIST_MIN_INTERVAL;
    if (h->interval_sec > HIST_MAX_INTERVAL) h->interval_sec = HIST_MAX_INTERVAL;
    return 0;
}

void hist_push(hist_ctx_t *h, const hist_sample_t *s) {
    pthread_mutex_lock(&h->lock);
    h->ring[h->idx] = *s;
    h->idx = (h->idx + 1) % HIST_SAMPLES;
    if (h->len < HIST_SAMPLES) h->len++;
    pthread_mutex_unlock(&h->lock);
}

/* Counters only ever climb, but a reload or a reset can send one backwards.
 * Report zero for that interval rather than a vast bogus spike. */
static uint32_t delta(unsigned long now, unsigned long *prev) {
    unsigned long d = (now >= *prev) ? now - *prev : 0;
    *prev = now;
    return (d > 0xffffffffUL) ? 0xffffffffU : (uint32_t)d;
}

void hist_tick(hist_ctx_t *h) {
    hist_sample_t s;
    memset(&s, 0, sizeof(s));
    s.when = time(NULL);
    s.active_wan = -1;

    unsigned long packets = 0, allowed = 0, blocked = 0;
    if (h->fw) {
        fw_stats_t st = fw_get_stats(h->fw);
        packets = st.total_packets;
        allowed = st.allowed;
        blocked = st.blocked;
    }

    pthread_mutex_lock(&g_vlan.lock);
    unsigned long ivr_a = g_vlan.inter_vlan_allowed;
    unsigned long ivr_d = g_vlan.inter_vlan_denied;
    unsigned long skips = g_vlan.schedule_skipped;
    unsigned long tagv  = g_vlan.vlan_violations;
    pthread_mutex_unlock(&g_vlan.lock);

    pthread_mutex_lock(&g_blockpage.lock);
    unsigned long pages = g_blockpage.pages_served;
    pthread_mutex_unlock(&g_blockpage.lock);

    pthread_mutex_lock(&h->lock);
    if (!h->primed) {
        /* The first tick establishes the baseline; recording it as a delta
         * would attribute everything since boot to one interval. */
        h->p_packets = packets; h->p_allowed = allowed; h->p_blocked = blocked;
        h->p_ivr_allowed = ivr_a; h->p_ivr_denied = ivr_d;
        h->p_pages = pages; h->p_sched_skipped = skips; h->p_tagvio = tagv;
        h->primed = true;
        pthread_mutex_unlock(&h->lock);
        return;
    }
    s.packets        = delta(packets, &h->p_packets);
    s.allowed        = delta(allowed, &h->p_allowed);
    s.blocked        = delta(blocked, &h->p_blocked);
    s.ivr_allowed    = delta(ivr_a,   &h->p_ivr_allowed);
    s.ivr_denied     = delta(ivr_d,   &h->p_ivr_denied);
    s.pages_served   = delta(pages,   &h->p_pages);
    s.sched_skipped  = delta(skips,   &h->p_sched_skipped);
    s.tag_violations = delta(tagv,    &h->p_tagvio);
    pthread_mutex_unlock(&h->lock);

    s.ct_count = ct_count();

    gw_state_t gs[2];
    int active = -1;
    int gn = gwmon_snapshot(&g_gwmon, gs, 2, &active);
    s.active_wan = (int8_t)active;
    for (int i = 0; i < gn && i < 2; i++) {
        double r = gs[i].avg_rtt_ms;
        if (r < 0) r = 0;
        if (r > 6553.0) r = 6553.0;
        s.wan_rtt_x10[i] = (uint16_t)(r * 10.0);
        s.wan_loss[i]    = (uint8_t)(gs[i].loss_pct > 100 ? 100 : gs[i].loss_pct);
    }

    hist_push(h, &s);
}

static void *hist_thread(void *arg) {
    hist_ctx_t *h = arg;
    while (h->running) {
        hist_tick(h);
        for (int t = 0; t < h->interval_sec * 10 && h->running; t++) {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int hist_start(hist_ctx_t *h) {
    h->running = true;
    if (pthread_create(&h->thread, NULL, hist_thread, h) != 0) {
        h->running = false;
        fprintf(stderr, "[%s] could not start the history sampler\n",
                BRAND_PRODUCT);
        return -1;
    }
    printf("[%s] History: sampling every %ds, %d slots (%d hours)\n",
           BRAND_PRODUCT, h->interval_sec, HIST_SAMPLES,
           (h->interval_sec * HIST_SAMPLES) / 3600);
    return 0;
}

void hist_stop(hist_ctx_t *h) {
    if (!h->running) return;
    h->running = false;
    pthread_join(h->thread, NULL);
}

void hist_shutdown(hist_ctx_t *h) {
    if (!h) return;
    hist_stop(h);
    pthread_mutex_destroy(&h->lock);
}

int hist_snapshot(hist_ctx_t *h, hist_sample_t *out, int max) {
    if (!out || max <= 0) return 0;

    pthread_mutex_lock(&h->lock);
    int n = h->len < max ? h->len : max;

    /* Walk back n from the write cursor so the newest n are returned, then
     * emit them oldest first -- which is the order a chart wants. */
    int start = (h->idx - n + HIST_SAMPLES) % HIST_SAMPLES;
    for (int i = 0; i < n; i++)
        out[i] = h->ring[(start + i) % HIST_SAMPLES];

    pthread_mutex_unlock(&h->lock);
    return n;
}
