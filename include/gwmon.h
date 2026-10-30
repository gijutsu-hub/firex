#ifndef FIREX_GWMON_H
#define FIREX_GWMON_H

#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include "netconf.h"

/*
 * Gateway monitoring and multi-WAN failover.
 *
 * A background thread sends ICMP echoes out each WAN interface to that link's
 * monitor address. State changes are gated by consecutive-result thresholds,
 * so one lost packet on a busy link does not move the default route; a link
 * has to fail `fail_threshold` probes in a row to be declared down, and
 * succeed `ok_threshold` in a row to come back.
 *
 * When the set of usable links changes, the default route is rebuilt: the
 * lowest `failover_priority` among the links that are up wins, and the others
 * are parked at a high metric so the kernel ignores them without losing the
 * gateway address.
 *
 * A WAN with no monitor address configured is treated as permanently up --
 * there is no evidence to the contrary, and silently declaring it down would
 * be worse than leaving it alone.
 */

#define GW_DEFAULT_INTERVAL   5
#define GW_DEFAULT_TIMEOUT_MS 1000
#define GW_DEFAULT_FAIL       3
#define GW_DEFAULT_OK         2
#define GW_RTT_WINDOW         10   /* probes kept for the loss/latency figure */

typedef enum { GW_UNKNOWN = 0, GW_UP, GW_DOWN, GW_UNMONITORED } gw_status_t;

typedef struct {
    gw_status_t   status;
    int           consecutive_ok;
    int           consecutive_fail;

    double        last_rtt_ms;      /* < 0 when the last probe timed out */
    double        avg_rtt_ms;
    int           loss_pct;         /* over the last GW_RTT_WINDOW probes */

    time_t        last_probe;
    time_t        last_change;
    unsigned long probes, failures;

    bool          active;           /* currently carrying the default route */
    uint32_t      gateway;          /* learned for DHCP/PPPoE links */
    char          probing[INET_ADDRSTRLEN];  /* target these results describe */

    /* ring of recent results, 1 = lost */
    uint8_t       window[GW_RTT_WINDOW];
    int           window_idx, window_len;
} gw_state_t;

typedef struct {
    gw_state_t      state[2];
    int             wan_count;
    int             active_wan;     /* -1 when every link is down */

    int             interval_sec;
    int             timeout_ms;
    int             fail_threshold;
    int             ok_threshold;

    bool            running;
    bool            apply_net;      /* false: observe only, never touch routes */
    pthread_t       thread;
    pthread_mutex_t lock;

    netconf_ctx_t  *nc;
} gwmon_ctx_t;

int  gwmon_init(gwmon_ctx_t *g, netconf_ctx_t *n, bool apply_net);
int  gwmon_start(gwmon_ctx_t *g);
void gwmon_stop(gwmon_ctx_t *g);
void gwmon_shutdown(gwmon_ctx_t *g);

/* Copies the current state out under the lock. Returns how many were written;
 * `active` receives the index of the link carrying the default route. */
int  gwmon_snapshot(gwmon_ctx_t *g, gw_state_t *out, int max, int *active);

/*
 * One ICMP echo out `ifname` to `target`. Returns the round trip in
 * milliseconds, or -1 on timeout or error. Exposed so tests can probe
 * loopback without starting the thread.
 */
double gwmon_ping(const char *target, const char *ifname, int timeout_ms);

/*
 * Which link should carry the default route, given each one's state and
 * priority? Lower `failover_priority` wins; a link marked backup loses to a
 * non-backup at equal priority. Returns -1 when nothing is usable.
 *
 * Pure function, no I/O -- failover logic is tested through this.
 */
int  gwmon_select(const wan_config_t *wan, const gw_state_t *st, int count);

/* Applies one probe result to a link's state, returning true when the
 * up/down status changed. Pure apart from the clock; tests drive it directly. */
bool gwmon_record(gwmon_ctx_t *g, gw_state_t *s, bool ok, double rtt_ms);

const char *gwmon_status_str(gw_status_t s);

#endif
