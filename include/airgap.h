#ifndef FIREX_AIRGAP_H
#define FIREX_AIRGAP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

#include "zone.h"

/*
 * Air gap.
 *
 * An air gap is usually described as "unplug the cable", which is a
 * policy, not a product: somebody has to unplug it, at the right time,
 * and plug it back for exactly as long as the work takes. On a network
 * that is operated by people, that holds for about a week.
 *
 * This enforces the same intent in the datapath, in six degrees, so the
 * right one can be chosen for the site instead of the only one:
 *
 *   CONNECTED      normal operation; nothing is enforced here
 *   SCHEDULED      the gap is closed except inside named windows -- for a
 *                  plant that syncs once a night and is isolated the
 *                  rest of the day
 *   INBOUND_ONLY   a data diode pointing in: traffic may arrive from the
 *                  untrusted side, nothing may leave. For collection
 *                  networks that must receive and must never talk back
 *   OUTBOUND_ONLY  the diode reversed: telemetry and alarms may leave, no
 *                  session may be opened from outside
 *   ISOLATED       nothing crosses the boundary in either direction
 *   MANUAL         ISOLATED, and the appliance will not fetch anything of
 *                  its own either: signature feeds and update bundles
 *                  have to be carried in and installed by hand
 *
 * What each mode does to each class of traffic. "Appliance" is the
 * daemon's own outbound traffic -- signature feeds, update bundles,
 * telemetry -- and it is the column that decides whether a mode is
 * really an air gap or just a strict firewall:
 *
 *   mode            user traffic        appliance fetches   time source
 *   --------------- ------------------- ------------------- -----------
 *   connected       both directions     yes                 NTP
 *   scheduled       inside windows      inside windows      NTP
 *   inbound-only    inbound only        no (would be out)   NTP inbound
 *   outbound-only   outbound only       yes                 NTP
 *   isolated        none                no                  RTC only
 *   manual          none                no                  RTC or operator
 *
 * Note the last column. MANUAL fetches nothing, and that includes NTP,
 * so its clock is whatever the RTC says or whatever an operator set. A
 * schedule cannot be trusted on an undisciplined clock, which is why
 * MANUAL plus windows plus require_time_sync is refused in config
 * validation rather than accepted and silently never opening.
 *
 * The distinction between ISOLATED and MANUAL is the one that matters in
 * practice. An appliance that blocks all user traffic but still reaches
 * out for its own updates is not air-gapped; it is a firewall with one
 * sanctioned tunnel through it, and that tunnel is the most valuable
 * target on the network. MANUAL closes it.
 *
 * WHAT THIS DOES NOT CLAIM. Enforcement here is at the packet layer, so
 * it is as good as the appliance is -- a true physical gap is a property
 * of the cable, not of software, and no setting in this file is a
 * substitute for one where the threat model demands it. What this gives
 * is an enforced, logged, scheduled approximation that cannot be
 * forgotten about, plus a record of every crossing that was refused.
 */

#define AG_MAX_WINDOWS   16
#define AG_MAX_EVENTS    128
#define AG_REASON_LEN    120
#define AG_NAME_LEN      48

typedef enum {
    AG_CONNECTED = 0,
    AG_SCHEDULED,
    AG_INBOUND_ONLY,
    AG_OUTBOUND_ONLY,
    AG_ISOLATED,
    AG_MANUAL,
    AG_MODE_MAX
} ag_mode_t;

/* Which way a packet is crossing the trust boundary. */
typedef enum {
    AG_CROSS_NONE = 0,   /* does not cross -- internal traffic   */
    AG_CROSS_OUT,        /* trusted side -> untrusted side       */
    AG_CROSS_IN          /* untrusted side -> trusted side       */
} ag_cross_t;

typedef enum { AG_PASS = 0, AG_DENY } ag_verdict_t;

/*
 * An opening in the gap. `days` is a bitmask with bit 0 = Sunday, to
 * match struct tm's tm_wday, so a window is checked without a lookup
 * table and an off-by-one cannot quietly shift every schedule by a day.
 */
typedef struct {
    bool     used;
    char     name[AG_NAME_LEN];
    uint8_t  days;           /* bit 0 Sun .. bit 6 Sat */
    uint16_t start_min;      /* minutes past local midnight */
    uint16_t end_min;        /* exclusive; < start means it wraps midnight */
    bool     allow_in;
    bool     allow_out;
} ag_window_t;

typedef struct {
    time_t    when;
    ag_mode_t mode;
    bool      opened;        /* true: the gap opened, false: it closed */
    char      reason[AG_REASON_LEN];
} ag_event_t;

/* Configuration, as read from the file. Windows arrive separately. */
typedef struct {
    ag_mode_t mode;
    bool      require_time_sync;
    bool      log_denied;
} ag_cfg_t;

typedef struct {
    ag_mode_t   mode;
    bool        log_denied;

    /*
     * Fail closed when the clock is not trustworthy. A scheduled gap is
     * decided entirely by the local clock, so an appliance that boots
     * with a bad clock would otherwise pick a window at random. With
     * this set, SCHEDULED denies until the time is known good.
     */
    bool        require_time_sync;
    bool        time_synced;

    ag_window_t windows[AG_MAX_WINDOWS];
    int         window_count;

    /* live */
    bool        open_now;
    char        state_reason[AG_REASON_LEN];
    time_t      last_change;
    time_t      next_change;     /* 0 when nothing is scheduled */

    unsigned long denied_in, denied_out;
    unsigned long passed_in, passed_out;
    unsigned long blocked_fetches;   /* the appliance's own traffic */

    ag_event_t  events[AG_MAX_EVENTS];
    int         event_count;

    pthread_mutex_t lock;
    bool        ready;
} ag_ctx_t;

/* ── lifecycle ───────────────────────────────────────────────────────── */

int  airgap_init(ag_ctx_t *a);
void airgap_shutdown(ag_ctx_t *a);

/* ── configuration ───────────────────────────────────────────────────── */

int  airgap_set_mode(ag_ctx_t *a, ag_mode_t mode, const char *who);

/* Returns the window index, or -1 when the table is full or the times
 * are not inside a day. */
int  airgap_add_window(ag_ctx_t *a, const char *name, uint8_t days,
                       uint16_t start_min, uint16_t end_min,
                       bool allow_in, bool allow_out);
void airgap_clear_windows(ag_ctx_t *a);

/* ── decisions ───────────────────────────────────────────────────────── */

/*
 * Re-evaluates the schedule and updates open_now / next_change. Call
 * periodically; returns true when the state changed, which is when the
 * caller should bring the WAN links up or down to match.
 */
bool airgap_tick(ag_ctx_t *a, time_t now);

/* The verdict for one packet. `cross` says which way it is going. */
ag_verdict_t airgap_verdict(ag_ctx_t *a, ag_cross_t cross, time_t now,
                            char *reason, size_t reasonlen);

/*
 * Works out which way a packet crosses, given the zones on each end.
 * Anything touching ZONE_WAN is a crossing; everything else is internal
 * and air gap has no opinion on it.
 */
ag_cross_t airgap_classify(zone_t src, zone_t dst);

/*
 * May the appliance itself reach the network right now -- signature
 * feeds, update bundles, telemetry? False in MANUAL always, and in
 * ISOLATED or a closed SCHEDULED window. Callers count a refusal in
 * blocked_fetches by passing `count` true.
 */
bool airgap_network_permitted(ag_ctx_t *a, time_t now, bool count);

/*
 * Reads the mode under the lock. The console and the egress adapter both
 * want to name the current mode in a message, and doing that by touching
 * a->mode directly is the small race this exists to remove.
 */
ag_mode_t airgap_mode_now(ag_ctx_t *a);

/* Record whether the clock is disciplined. Under the lock, because the
 * scheduler's tick reads it on another thread and a window that opens on a
 * half-written flag is the kind of fault that shows up once a month. */
void airgap_set_time_synced(ag_ctx_t *a, bool synced);

/*
 * Make this air gap the answer that egress_permitted() gives in egress.h,
 * so the appliance's own outbound traffic -- feeds, telemetry, HA pushes,
 * gateway probes -- is held back by the same decision that holds back
 * transit traffic.
 *
 * Without this call airgap_network_permitted() is a function nothing asks,
 * every mode is a strict firewall rather than an air gap, and the
 * difference is invisible because the refusal counters simply stay at
 * zero. Passing NULL unbinds.
 */
void airgap_bind_egress(ag_ctx_t *a);

/* ── reporting ───────────────────────────────────────────────────────── */

const char *airgap_mode_name(ag_mode_t m);
const char *airgap_mode_label(ag_mode_t m);
bool        airgap_mode_from_name(const char *s, ag_mode_t *out);

/* Copies up to `max` recent events, newest first. */
int  airgap_recent(ag_ctx_t *a, ag_event_t *out, int max);

/* Formats a window's days as "Mon-Fri" style text into `out`. */
void airgap_days_text(uint8_t days, char *out, size_t outlen);

#endif /* FIREX_AIRGAP_H */
