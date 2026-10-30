/*
 * Automatic response. See include/response.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "response.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

int response_init(response_ctx_t *r, const response_cfg_t *cfg, bool apply_net) {
    memset(r, 0, sizeof(*r));
    pthread_mutex_init(&r->lock, NULL);
    r->apply_net = apply_net;
    if (cfg) r->cfg = *cfg;

    if (!r->cfg.threshold)         r->cfg.threshold = 10;
    if (!r->cfg.block_minutes)     r->cfg.block_minutes = 15;
    if (!r->cfg.max_block_minutes) r->cfg.max_block_minutes = 1440;
    if (!r->cfg.decay_minutes)     r->cfg.decay_minutes = 60;
    return 0;
}

/*
 * A serious detection should not need ten repeats to act, and a noisy
 * low-severity rule should not block a host on its own. The curve is steep
 * enough that one severity-4 hit reaches the default threshold alone.
 */
int response_score_for(int severity) {
    switch (severity) {
        case 4:  return 10;
        case 3:  return 5;
        case 2:  return 2;
        default: return 1;
    }
}

static offender_t *find_locked(response_ctx_t *r, uint32_t ip) {
    for (int i = 0; i < RESP_MAX_OFFENDERS; i++)
        if (r->offenders[i].used && r->offenders[i].ip == ip)
            return &r->offenders[i];
    return NULL;
}

/* A free slot, or the least interesting one: never evict a blocked host. */
static offender_t *slot_locked(response_ctx_t *r) {
    offender_t *oldest = NULL;
    for (int i = 0; i < RESP_MAX_OFFENDERS; i++) {
        offender_t *o = &r->offenders[i];
        if (!o->used) return o;
        if (o->blocked_until) continue;
        if (!oldest || o->last_seen < oldest->last_seen) oldest = o;
    }
    if (oldest) r->evicted++;
    return oldest;
}

static void set_block(response_ctx_t *r, uint32_t ip, int seconds) {
    if (!r->apply_net) return;
    char cmd[256], abuf[INET_ADDRSTRLEN];
    snprintf(cmd, sizeof(cmd), "ipset add %s %s timeout %d -exist 2>/dev/null",
             RESP_SET, fx_ip_str(ip, abuf, sizeof(abuf)), seconds);
    fx_try(cmd);
}

static void clear_block(response_ctx_t *r, uint32_t ip) {
    if (!r->apply_net) return;
    char cmd[256], abuf[INET_ADDRSTRLEN];
    snprintf(cmd, sizeof(cmd), "ipset del %s %s 2>/dev/null",
             RESP_SET, fx_ip_str(ip, abuf, sizeof(abuf)));
    fx_try(cmd);
}

bool response_record(response_ctx_t *r, uint32_t ip, int severity,
                     const char *reason) {
    if (!r->cfg.enabled || !ip) return false;

    time_t now = time(NULL);
    bool newly_blocked = false;
    int  block_secs = 0;

    pthread_mutex_lock(&r->lock);
    r->recorded++;

    offender_t *o = find_locked(r, ip);
    if (!o) {
        o = slot_locked(r);
        if (!o) { pthread_mutex_unlock(&r->lock); return false; }
        memset(o, 0, sizeof(*o));
        o->ip = ip;
        o->used = true;
        o->first_seen = now;
        o->last_decay = now;
    }

    o->score += response_score_for(severity);
    o->detections++;
    o->last_seen = now;
    if (reason) snprintf(o->last_reason, RESP_REASON_LEN, "%s", reason);

    if (!o->blocked_until && o->score >= r->cfg.threshold) {
        int mins = r->cfg.block_minutes;
        if (r->cfg.escalate && o->block_count > 0) {
            /* Double per previous block, capped. A host that keeps coming
             * back is held longer each time without ever being permanent. */
            for (int i = 0; i < o->block_count && mins < r->cfg.max_block_minutes; i++)
                mins *= 2;
            if (mins > r->cfg.max_block_minutes) mins = r->cfg.max_block_minutes;
            r->escalations++;
        }
        o->blocked_until = now + (time_t)mins * 60;
        o->block_count++;
        block_secs = mins * 60;
        r->blocks++;
        newly_blocked = true;
    }
    pthread_mutex_unlock(&r->lock);

    if (newly_blocked) {
        set_block(r, ip, block_secs);
        if (r->cfg.notify) {
            char abuf[INET_ADDRSTRLEN];
            printf("[%s] response: %s %s for %d minute(s) -- %s\n",
                   BRAND_PRODUCT, fx_ip_str(ip, abuf, sizeof(abuf)),
                   r->cfg.quarantine ? "quarantined" : "blocked",
                   block_secs / 60, reason ? reason : "threshold reached");
        }
    }
    return newly_blocked;
}

bool response_is_blocked(response_ctx_t *r, uint32_t ip) {
    if (!r->cfg.enabled) return false;

    time_t now = time(NULL);
    pthread_mutex_lock(&r->lock);
    offender_t *o = find_locked(r, ip);
    bool blocked = o && o->blocked_until && now < o->blocked_until;
    pthread_mutex_unlock(&r->lock);
    return blocked;
}

zone_t response_zone_for(response_ctx_t *r, uint32_t ip) {
    if (!r->cfg.enabled || !r->cfg.quarantine) return ZONE_MAX;
    return response_is_blocked(r, ip) ? ZONE_QUARANTINE : ZONE_MAX;
}

int response_release(response_ctx_t *r, uint32_t ip) {
    pthread_mutex_lock(&r->lock);
    offender_t *o = find_locked(r, ip);
    if (!o) { pthread_mutex_unlock(&r->lock); return -1; }
    bool was = o->blocked_until != 0;
    memset(o, 0, sizeof(*o));
    if (was) r->releases++;
    pthread_mutex_unlock(&r->lock);

    clear_block(r, ip);
    return 0;
}

int response_reap(response_ctx_t *r, time_t now) {
    uint32_t released[64];
    int nrel = 0, freed = 0;

    pthread_mutex_lock(&r->lock);
    for (int i = 0; i < RESP_MAX_OFFENDERS; i++) {
        offender_t *o = &r->offenders[i];
        if (!o->used) continue;

        if (o->blocked_until && now >= o->blocked_until) {
            o->blocked_until = 0;
            /* The score is cut rather than cleared: a host that earned a
             * block should not start from zero the moment it expires. */
            o->score /= 2;
            if (nrel < 64) released[nrel++] = o->ip;
            r->releases++;
            freed++;
        }

        if (r->cfg.decay_minutes > 0 && !o->blocked_until &&
            now - o->last_decay >= (time_t)r->cfg.decay_minutes * 60) {
            o->score /= 2;
            o->last_decay = now;
        }

        /* A quiet host with nothing left against it is forgotten. */
        if (!o->blocked_until && o->score <= 0 &&
            now - o->last_seen > (time_t)r->cfg.decay_minutes * 120)
            memset(o, 0, sizeof(*o));
    }
    pthread_mutex_unlock(&r->lock);

    for (int i = 0; i < nrel; i++) clear_block(r, released[i]);
    return freed;
}

int response_snapshot(response_ctx_t *r, offender_t *out, int max) {
    pthread_mutex_lock(&r->lock);
    int n = 0;
    for (int i = 0; i < RESP_MAX_OFFENDERS && n < max; i++)
        if (r->offenders[i].used) out[n++] = r->offenders[i];
    pthread_mutex_unlock(&r->lock);
    return n;
}

static void *reaper_thread(void *arg) {
    response_ctx_t *r = arg;
    while (r->running) {
        response_reap(r, time(NULL));
        for (int i = 0; i < 300 && r->running; i++) {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int response_start(response_ctx_t *r) {
    if (!r->cfg.enabled) return 0;

    r->running = true;
    if (pthread_create(&r->reaper, NULL, reaper_thread, r) != 0) {
        r->running = false;
        fprintf(stderr, "[%s] could not start the response reaper\n",
                BRAND_PRODUCT);
        return -1;
    }
    printf("[%s] Auto-response: %s at score %d, %d min%s, decay %d min\n",
           BRAND_PRODUCT, r->cfg.quarantine ? "quarantine" : "block",
           r->cfg.threshold, r->cfg.block_minutes,
           r->cfg.escalate ? " escalating" : "", r->cfg.decay_minutes);
    return 0;
}

void response_stop(response_ctx_t *r) {
    if (!r->running) return;
    r->running = false;
    pthread_join(r->reaper, NULL);
}

void response_shutdown(response_ctx_t *r) {
    if (!r) return;
    response_stop(r);
    pthread_mutex_destroy(&r->lock);
}

int response_install_rules(response_ctx_t *r) {
    if (!r->cfg.enabled || !r->apply_net) return 0;

    char cmd[256];
    /*
     * The set carries its own timeout, so a crash cannot leave a host held
     * forever -- the kernel expires the entry even with nothing running.
     */
    snprintf(cmd, sizeof(cmd),
             "ipset create %s hash:ip timeout %d 2>/dev/null",
             RESP_SET, r->cfg.max_block_minutes * 60);
    fx_try(cmd);

    fx_try("iptables -N FIREX_RESPONSE 2>/dev/null");
    fx_run("iptables -F FIREX_RESPONSE");
    fx_try("iptables -D FORWARD -j FIREX_RESPONSE 2>/dev/null");
    fx_run("iptables -I FORWARD 1 -j FIREX_RESPONSE");
    fx_try("iptables -D INPUT -j FIREX_RESPONSE 2>/dev/null");
    fx_run("iptables -I INPUT 1 -j FIREX_RESPONSE");

    if (r->cfg.quarantine) {
        /*
         * In quarantine mode the inspection path reclassifies the source
         * into ZONE_QUARANTINE and the zone matrix decides what it may
         * still reach. Only the appliance itself is closed off here, so a
         * quarantined host cannot reach the console.
         */
        snprintf(cmd, sizeof(cmd),
                 "iptables -A FIREX_RESPONSE -m set --match-set %s src "
                 "-m conntrack --ctstate NEW -j DROP", RESP_SET);
        fx_run(cmd);
        printf("  [RESPONSE] quarantine set '%s' armed; the zone matrix "
               "decides what QUARANTINE may reach\n", RESP_SET);
    } else {
        snprintf(cmd, sizeof(cmd),
                 "iptables -A FIREX_RESPONSE -m set --match-set %s src -j DROP",
                 RESP_SET);
        fx_run(cmd);
        printf("  [RESPONSE] block set '%s' armed\n", RESP_SET);
    }
    return 0;
}

int response_teardown_rules(response_ctx_t *r) {
    if (!r->apply_net) return 0;
    fx_try("iptables -D FORWARD -j FIREX_RESPONSE 2>/dev/null");
    fx_try("iptables -D INPUT -j FIREX_RESPONSE 2>/dev/null");
    fx_try("iptables -F FIREX_RESPONSE 2>/dev/null");
    fx_try("iptables -X FIREX_RESPONSE 2>/dev/null");
    return 0;
}
