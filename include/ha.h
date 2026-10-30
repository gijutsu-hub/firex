#ifndef FIREX_HA_H
#define FIREX_HA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "vlan.h"

/*
 * High availability: two appliances, one of which is carrying traffic.
 *
 * Three separate things have to be true for a failover to be invisible:
 *
 *   1. the gateway addresses move      -- VRRP, via keepalived
 *   2. established connections survive -- conntrackd, syncing the kernel's
 *                                         connection table over a dedicated link
 *   3. both nodes agree on the config  -- replication, below
 *
 * FireX owns the configuration for the first two and generates it; keepalived
 * and conntrackd do the work. The third is ours entirely.
 *
 * While HA is enabled the VLAN gateway addresses belong to VRRP, not to the
 * interface: the node must not assign them itself or both nodes would answer
 * for the same address. vlan_apply_to_system() is told to leave them alone.
 *
 * Replication is authenticated by an HMAC over the body and a timestamp, not
 * by a password in a header. The shared secret never travels, a captured push
 * cannot be replayed outside its window, and the receiving node needs no user
 * account for the sending one.
 */

#define HA_ADDR_LEN        64
#define HA_SECRET_LEN      128
#define HA_VRRP_PASS_LEN   32
#define HA_SIG_LEN         65     /* 64 hex characters + NUL */
#define HA_REPLAY_WINDOW   300    /* seconds a signed push stays valid */
#define HA_DEFAULT_VRID    51
#define HA_DEFAULT_CT_PORT 3780
#define HA_DEFAULT_SYNC_PORT 8080
#define HA_STATE_FILE      "/run/firex/ha-state"

typedef enum { HA_ROLE_PRIMARY = 0, HA_ROLE_SECONDARY } ha_role_t;

typedef enum {
    HA_STATE_UNKNOWN = 0,
    HA_STATE_MASTER,
    HA_STATE_BACKUP,
    HA_STATE_FAULT
} ha_state_t;

typedef struct {
    bool      enabled;
    ha_role_t role;

    char      peer_address[HA_ADDR_LEN];     /* the other node on the sync link */
    char      sync_interface[IFNAME_LEN];
    char      sync_address[HA_ADDR_LEN];     /* this node on that link */

    int       vrrp_id;                       /* 1-255, same on both nodes */
    char      vrrp_password[HA_VRRP_PASS_LEN];
    int       priority;                      /* 1-254; higher wins */
    int       advert_interval;               /* seconds */
    bool      preempt;                       /* reclaim when the primary returns */

    bool      conntrack_sync;
    int       conntrack_port;

    bool      config_sync;
    int       config_sync_port;              /* the peer's console port */
    char      sync_secret[HA_SECRET_LEN];    /* HMAC key; never transmitted */
} ha_cfg_t;

typedef struct {
    ha_cfg_t        cfg;

    ha_state_t      state;
    time_t          state_since;
    unsigned long   transitions;

    unsigned long   pushes_sent, pushes_received, pushes_rejected;
    char            last_error[192];
    bool            applied;
    int             vips;                    /* addresses VRRP is carrying */

    pthread_mutex_t lock;
} ha_ctx_t;

int  ha_init(ha_ctx_t *h, const ha_cfg_t *cfg);
void ha_shutdown(ha_ctx_t *h);

/*
 * Writes keepalived.conf. Every enabled VLAN with a gateway contributes that
 * gateway as a virtual address. Returns how many were written, or -1.
 */
int  ha_generate_keepalived(ha_ctx_t *h, vlan_ctx_t *v, const char *path,
                            const char *notify_script);

/* Writes the notify script keepalived runs on each transition. */
int  ha_generate_notify(ha_ctx_t *h, const char *path);

/* Writes conntrackd.conf. Returns 0, or -1. */
int  ha_generate_conntrackd(ha_ctx_t *h, const char *path);

int  ha_apply(ha_ctx_t *h, vlan_ctx_t *v);
int  ha_teardown(ha_ctx_t *h);

/* Reads the state keepalived's notify script last recorded. */
ha_state_t ha_read_state(ha_ctx_t *h);
void       ha_set_state(ha_ctx_t *h, ha_state_t s);

/* ── replication ──
 * The signature covers the timestamp and the body together, so neither can be
 * swapped for another. Both are pure and tested without a network.
 */
int  ha_sign(const char *secret, time_t ts, const void *body, size_t len,
             char *out, size_t outlen);

/*
 * Returns true when the signature is valid and the timestamp is inside
 * HA_REPLAY_WINDOW of `now`. `why` receives the reason on failure.
 */
bool ha_verify(const char *secret, const char *ts_header, const char *sig_header,
               const void *body, size_t len, time_t now,
               char *why, size_t whylen);

/* Pushes a configuration file to the peer. Returns 0 on success. */
int  ha_push_config(ha_ctx_t *h, const char *config_path,
                    char *why, size_t whylen);

const char *ha_state_name(ha_state_t s);
ha_state_t  ha_state_from(const char *s);
const char *ha_role_name(ha_role_t r);
ha_role_t   ha_role_from(const char *s);

#endif
