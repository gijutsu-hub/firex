/*
 * Air gap enforcement -- see include/airgap.h for the five modes and what
 * each one is for.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "airgap.h"
#include "egress.h"

/* ── names ───────────────────────────────────────────────────────────── */

static const struct {
    ag_mode_t   mode;
    const char *name;
    const char *label;
} MODES[] = {
    { AG_CONNECTED,    "connected",     "Connected"      },
    { AG_SCHEDULED,    "scheduled",     "Scheduled gap"  },
    { AG_INBOUND_ONLY, "inbound-only",  "Diode: inbound" },
    { AG_OUTBOUND_ONLY,"outbound-only", "Diode: outbound"},
    { AG_ISOLATED,     "isolated",      "Isolated"       },
    { AG_MANUAL,       "manual",        "Manual transfer"},
};

const char *airgap_mode_name(ag_mode_t m) {
    for (size_t i = 0; i < sizeof MODES / sizeof *MODES; i++)
        if (MODES[i].mode == m) return MODES[i].name;
    return "unknown";
}

const char *airgap_mode_label(ag_mode_t m) {
    for (size_t i = 0; i < sizeof MODES / sizeof *MODES; i++)
        if (MODES[i].mode == m) return MODES[i].label;
    return "Unknown";
}

bool airgap_mode_from_name(const char *s, ag_mode_t *out) {
    if (!s || !out) return false;
    for (size_t i = 0; i < sizeof MODES / sizeof *MODES; i++)
        if (strcasecmp(s, MODES[i].name) == 0) { *out = MODES[i].mode; return true; }
    return false;
}

void airgap_days_text(uint8_t days, char *out, size_t outlen) {
    static const char *D[7] = { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
    if (!out || outlen == 0) return;
    out[0] = 0;
    if ((days & 0x7F) == 0x7F) { snprintf(out, outlen, "Every day"); return; }
    if ((days & 0x7F) == 0x3E) { snprintf(out, outlen, "Mon-Fri");   return; }
    if ((days & 0x7F) == 0x41) { snprintf(out, outlen, "Weekends");  return; }

    size_t n = 0;
    for (int i = 0; i < 7; i++) {
        if (!(days & (1u << i))) continue;
        int w = snprintf(out + n, outlen - n, "%s%s", n ? " " : "", D[i]);
        if (w < 0 || (size_t)w >= outlen - n) break;
        n += (size_t)w;
    }
    if (!n) snprintf(out, outlen, "Never");
}

/* ── lifecycle ───────────────────────────────────────────────────────── */

int airgap_init(ag_ctx_t *a) {
    if (!a) return -1;
    memset(a, 0, sizeof(*a));
    if (pthread_mutex_init(&a->lock, NULL) != 0) return -1;

    a->mode              = AG_CONNECTED;
    a->log_denied        = true;
    a->require_time_sync = true;
    a->time_synced       = false;
    a->open_now          = true;
    a->last_change       = time(NULL);
    snprintf(a->state_reason, sizeof(a->state_reason),
             "Air gap is not in use");
    a->ready = true;
    return 0;
}

void airgap_shutdown(ag_ctx_t *a) {
    if (!a || !a->ready) return;
    a->ready = false;
    pthread_mutex_destroy(&a->lock);
}

/* Caller holds the lock. */
static void push_event(ag_ctx_t *a, bool opened, const char *reason) {
    ag_event_t e;
    memset(&e, 0, sizeof(e));
    e.when   = time(NULL);
    e.mode   = a->mode;
    e.opened = opened;
    snprintf(e.reason, sizeof(e.reason), "%s", reason ? reason : "");

    if (a->event_count < AG_MAX_EVENTS) {
        a->events[a->event_count++] = e;
    } else {
        memmove(&a->events[0], &a->events[1],
                sizeof(ag_event_t) * (AG_MAX_EVENTS - 1));
        a->events[AG_MAX_EVENTS - 1] = e;
    }
}

int airgap_set_mode(ag_ctx_t *a, ag_mode_t mode, const char *who) {
    if (!a || !a->ready || mode < 0 || mode >= AG_MODE_MAX) return -1;

    pthread_mutex_lock(&a->lock);
    ag_mode_t was = a->mode;
    a->mode = mode;

    char reason[AG_REASON_LEN];
    snprintf(reason, sizeof(reason), "Mode %s -> %s%s%s",
             airgap_mode_name(was), airgap_mode_name(mode),
             who && *who ? " by " : "", who && *who ? who : "");
    push_event(a, mode == AG_CONNECTED, reason);
    a->last_change = time(NULL);
    pthread_mutex_unlock(&a->lock);

    airgap_tick(a, time(NULL));
    return 0;
}

int airgap_add_window(ag_ctx_t *a, const char *name, uint8_t days,
                      uint16_t start_min, uint16_t end_min,
                      bool allow_in, bool allow_out) {
    if (!a || !a->ready) return -1;
    if (start_min >= 1440 || end_min > 1440) return -1;
    if (start_min == end_min) return -1;      /* a zero-length opening */

    pthread_mutex_lock(&a->lock);
    int idx = -1;
    for (int i = 0; i < AG_MAX_WINDOWS; i++) {
        if (a->windows[i].used) continue;
        ag_window_t *w = &a->windows[i];
        memset(w, 0, sizeof(*w));
        w->used      = true;
        w->days      = (uint8_t)(days & 0x7F);
        w->start_min = start_min;
        w->end_min   = end_min;
        w->allow_in  = allow_in;
        w->allow_out = allow_out;
        snprintf(w->name, sizeof(w->name), "%s", name && *name ? name : "window");
        if (i >= a->window_count) a->window_count = i + 1;
        idx = i;
        break;
    }
    pthread_mutex_unlock(&a->lock);
    return idx;
}

void airgap_clear_windows(ag_ctx_t *a) {
    if (!a || !a->ready) return;
    pthread_mutex_lock(&a->lock);
    memset(a->windows, 0, sizeof(a->windows));
    a->window_count = 0;
    pthread_mutex_unlock(&a->lock);
}

/* ── schedule ────────────────────────────────────────────────────────── */

/*
 * Is `w` open at local time `tm`? A window whose end is before its start
 * wraps midnight -- 22:00 to 04:00 is one opening, not two -- and the
 * day bit refers to the day it STARTS on, so the small hours of Saturday
 * belong to Friday's window. Getting that backwards is the classic way a
 * nightly sync window silently stops working at the weekend.
 */
static bool window_open_at(const ag_window_t *w, const struct tm *tm) {
    int minute = tm->tm_hour * 60 + tm->tm_min;

    if (w->start_min < w->end_min) {
        if (!(w->days & (1u << tm->tm_wday))) return false;
        return minute >= w->start_min && minute < w->end_min;
    }
    /* wraps midnight */
    if (minute >= w->start_min) {
        return (w->days & (1u << tm->tm_wday)) != 0;
    }
    if (minute < w->end_min) {
        int prev = (tm->tm_wday + 6) % 7;
        return (w->days & (1u << prev)) != 0;
    }
    return false;
}

/* Caller holds the lock. Picks the window covering `now`, or NULL. */
static const ag_window_t *active_window(const ag_ctx_t *a, const struct tm *tm) {
    for (int i = 0; i < a->window_count; i++) {
        const ag_window_t *w = &a->windows[i];
        if (w->used && window_open_at(w, tm)) return w;
    }
    return NULL;
}

/* Caller holds the lock. Minute-steps forward to the next change, up to a
 * week. A loop rather than arithmetic because windows may overlap, wrap
 * midnight and disagree about days; a week of minutes is 10,080
 * iterations of a trivial test, run once a tick. */
static time_t next_transition(const ag_ctx_t *a, time_t now, bool open_now) {
    for (int i = 1; i <= 7 * 24 * 60; i++) {
        time_t t = now + (time_t)i * 60;
        struct tm tm;
        localtime_r(&t, &tm);
        bool open = active_window(a, &tm) != NULL;
        if (open != open_now) return t;
    }
    return 0;
}

bool airgap_tick(ag_ctx_t *a, time_t now) {
    if (!a || !a->ready) return false;

    pthread_mutex_lock(&a->lock);

    bool was = a->open_now;
    char reason[AG_REASON_LEN];

    switch (a->mode) {
        case AG_CONNECTED:
            a->open_now = true;
            snprintf(reason, sizeof(reason), "Air gap is not in use");
            a->next_change = 0;
            break;

        case AG_SCHEDULED: {
            if (a->require_time_sync && !a->time_synced) {
                a->open_now = false;
                snprintf(reason, sizeof(reason),
                         "Closed: the clock is not synchronised, so no window can be trusted");
                a->next_change = 0;
                break;
            }
            struct tm tm;
            localtime_r(&now, &tm);
            const ag_window_t *w = active_window(a, &tm);
            a->open_now = (w != NULL);
            if (w) snprintf(reason, sizeof(reason), "Open: window \"%s\"", w->name);
            else if (a->window_count == 0)
                snprintf(reason, sizeof(reason),
                         "Closed: no windows are defined, so the gap never opens");
            else
                snprintf(reason, sizeof(reason), "Closed: outside every window");
            a->next_change = next_transition(a, now, a->open_now);
            break;
        }

        case AG_INBOUND_ONLY:
            a->open_now = true;      /* one direction is still a crossing */
            snprintf(reason, sizeof(reason),
                     "Inbound only: nothing may leave the trusted side");
            a->next_change = 0;
            break;

        case AG_OUTBOUND_ONLY:
            a->open_now = true;
            snprintf(reason, sizeof(reason),
                     "Outbound only: no session may be opened from outside");
            a->next_change = 0;
            break;

        case AG_ISOLATED:
            a->open_now = false;
            snprintf(reason, sizeof(reason), "Isolated: nothing crosses in either direction");
            a->next_change = 0;
            break;

        case AG_MANUAL:
            a->open_now = false;
            snprintf(reason, sizeof(reason),
                     "Manual transfer: the appliance fetches nothing of its own");
            a->next_change = 0;
            break;

        default:
            a->open_now = true;
            snprintf(reason, sizeof(reason), "Unknown mode");
            a->next_change = 0;
            break;
    }

    bool changed = (was != a->open_now) ||
                   strcmp(a->state_reason, reason) != 0;
    if (changed) {
        snprintf(a->state_reason, sizeof(a->state_reason), "%s", reason);
        if (was != a->open_now) {
            a->last_change = now;
            push_event(a, a->open_now, reason);
        }
    }
    bool state_changed = (was != a->open_now);
    pthread_mutex_unlock(&a->lock);
    return state_changed;
}

/* ── per-packet ──────────────────────────────────────────────────────── */

ag_cross_t airgap_classify(zone_t src, zone_t dst) {
    if (src == dst) return AG_CROSS_NONE;
    if (dst == ZONE_WAN) return AG_CROSS_OUT;
    if (src == ZONE_WAN) return AG_CROSS_IN;
    return AG_CROSS_NONE;
}

ag_verdict_t airgap_verdict(ag_ctx_t *a, ag_cross_t cross, time_t now,
                            char *reason, size_t reasonlen) {
    if (reason && reasonlen) reason[0] = 0;
    if (!a || !a->ready || cross == AG_CROSS_NONE) return AG_PASS;
    if (a->mode == AG_CONNECTED) return AG_PASS;

    pthread_mutex_lock(&a->lock);

    bool deny = false;
    const char *why = "";

    switch (a->mode) {
        case AG_CONNECTED:
            break;

        case AG_SCHEDULED: {
            if (!a->open_now) { deny = true; why = "outside the transfer window"; break; }
            struct tm tm;
            localtime_r(&now, &tm);
            const ag_window_t *w = active_window(a, &tm);
            if (!w) { deny = true; why = "outside the transfer window"; break; }
            if (cross == AG_CROSS_IN  && !w->allow_in)  { deny = true; why = "the window does not permit inbound"; }
            if (cross == AG_CROSS_OUT && !w->allow_out) { deny = true; why = "the window does not permit outbound"; }
            break;
        }

        case AG_INBOUND_ONLY:
            if (cross == AG_CROSS_OUT) { deny = true; why = "the diode points inward"; }
            break;

        case AG_OUTBOUND_ONLY:
            if (cross == AG_CROSS_IN) { deny = true; why = "the diode points outward"; }
            break;

        case AG_ISOLATED:
        case AG_MANUAL:
            deny = true;
            why = a->mode == AG_MANUAL ? "manual transfer only" : "the appliance is isolated";
            break;

        default:
            break;
    }

    if (deny) {
        if (cross == AG_CROSS_IN) a->denied_in++; else a->denied_out++;
    } else {
        if (cross == AG_CROSS_IN) a->passed_in++; else a->passed_out++;
    }

    if (deny && reason && reasonlen)
        snprintf(reason, reasonlen, "Air gap (%s): %s",
                 airgap_mode_name(a->mode), why);

    pthread_mutex_unlock(&a->lock);
    return deny ? AG_DENY : AG_PASS;
}

bool airgap_network_permitted(ag_ctx_t *a, time_t now, bool count) {
    if (!a || !a->ready) return true;

    pthread_mutex_lock(&a->lock);
    bool ok;
    switch (a->mode) {
        case AG_MANUAL:
            /* The whole point of the mode. */
            ok = false;
            break;
        case AG_ISOLATED:
            ok = false;
            break;
        case AG_SCHEDULED:
            ok = a->open_now;
            break;
        case AG_INBOUND_ONLY:
            /* Fetching means opening a session outward, which is the
             * direction a diode pointing in exists to forbid. */
            ok = false;
            break;
        default:
            ok = true;
            break;
    }
    if (!ok && count) a->blocked_fetches++;
    pthread_mutex_unlock(&a->lock);
    (void)now;
    return ok;
}

void airgap_set_time_synced(ag_ctx_t *a, bool synced) {
    if (!a || !a->ready) return;
    pthread_mutex_lock(&a->lock);
    a->time_synced = synced;
    pthread_mutex_unlock(&a->lock);
}

ag_mode_t airgap_mode_now(ag_ctx_t *a) {
    if (!a || !a->ready) return AG_CONNECTED;
    pthread_mutex_lock(&a->lock);
    ag_mode_t m = a->mode;
    pthread_mutex_unlock(&a->lock);
    return m;
}

/* ── the appliance's own egress ──────────────────────────────────────── */

static bool egress_adapter(void *arg, egress_kind_t kind,
                           char *why, size_t whylen) {
    ag_ctx_t *a = (ag_ctx_t *)arg;

    /* `count` true: a refusal belongs in blocked_fetches, which is the
     * number the console shows to say the gap is doing something. */
    if (airgap_network_permitted(a, time(NULL), true)) return true;

    if (why && whylen)
        snprintf(why, whylen,
                 "air gap (%s): %s may not reach the network",
                 airgap_mode_name(airgap_mode_now(a)), egress_kind_name(kind));
    return false;
}

void airgap_bind_egress(ag_ctx_t *a) {
    egress_bind(a ? egress_adapter : NULL, a);
}

int airgap_recent(ag_ctx_t *a, ag_event_t *out, int max) {
    if (!a || !a->ready || !out || max <= 0) return 0;
    pthread_mutex_lock(&a->lock);
    int n = 0;
    for (int i = a->event_count - 1; i >= 0 && n < max; i--) out[n++] = a->events[i];
    pthread_mutex_unlock(&a->lock);
    return n;
}
