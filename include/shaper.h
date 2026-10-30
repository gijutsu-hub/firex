#ifndef FIREX_SHAPER_H
#define FIREX_SHAPER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include "vlan.h"

/* Only a pointer is needed here, and netconf.h includes this header for the
 * configuration struct below -- so forward-declare rather than include. */
typedef struct netconf_ctx netconf_ctx_t;

/*
 * Traffic shaping: HTB for the rate limits, FQ-CoDel underneath for the
 * latency.
 *
 * The rate limit is the part people ask for; the leaf qdisc is the part that
 * actually makes the link feel fast. A token bucket with one FIFO behind it
 * enforces a rate and leaves bufferbloat exactly where it was, which is what
 * this replaces.
 *
 * Shaping only works on egress, so:
 *   - upload is shaped on the WAN interface, classified by source subnet,
 *     which gives each VLAN its own class under one ceiling
 *   - download to a VLAN's clients is shaped on that VLAN's own interface,
 *     where it is egress from this box
 *   - total download from the internet can only be shaped by redirecting WAN
 *     ingress to an IFB device, which is opt-in because it costs a copy of
 *     every inbound packet
 *
 * The command sequence is built as data and run separately, so the whole
 * hierarchy can be inspected -- and tested -- without touching a NIC.
 */

#define SHAPER_MAX_CMDS   384
#define SHAPER_CMD_LEN    256
#define SHAPER_IFB_DEV    "ifb-firex"

#define SHAPER_ROOT_CLASS 1       /* 1:1   the ceiling                    */
#define SHAPER_BASE_CLASS 100     /* 1:100 upward, one per shaped VLAN    */
#define SHAPER_DEF_CLASS  999     /* 1:999 anything unclassified          */

typedef enum {
    QDISC_FQ_CODEL = 0,
    QDISC_CAKE,
    QDISC_SFQ,
    QDISC_PFIFO_FAST
} qdisc_t;

typedef struct {
    bool    enabled;
    int     wan_up_mbps;        /* 0 = do not shape upload       */
    int     wan_down_mbps;      /* 0 = do not shape download     */
    qdisc_t qdisc;
    int     codel_target_ms;    /* FQ-CoDel target,   default 5   */
    int     codel_interval_ms;  /* FQ-CoDel interval, default 100 */
    bool    ecn;                /* mark instead of drop           */
    bool    ingress_shaping;    /* redirect WAN ingress to an IFB */
} shaper_cfg_t;

typedef struct {
    char cmd[SHAPER_MAX_CMDS][SHAPER_CMD_LEN];
    int  count;
    int  overflow;              /* commands that did not fit */
} shaper_plan_t;

typedef struct {
    shaper_cfg_t    cfg;
    bool            applied;
    int             ifaces_shaped;
    int             classes;
    unsigned        failures;    /* tc commands that reported an error */
    char            last_error[160];
    pthread_mutex_t lock;
} shaper_ctx_t;

int  shaper_init(shaper_ctx_t *s, const shaper_cfg_t *cfg);
void shaper_shutdown(shaper_ctx_t *s);

/*
 * Builds the command sequence for this configuration. Pure: it reads the
 * tables and writes commands, and touches nothing. Returns the number of
 * commands, or -1.
 */
int  shaper_plan(const shaper_cfg_t *cfg, vlan_ctx_t *v, netconf_ctx_t *n,
                 shaper_plan_t *out);

/* Builds the teardown sequence: removes every qdisc this would have added. */
int  shaper_plan_teardown(const shaper_cfg_t *cfg, vlan_ctx_t *v,
                          netconf_ctx_t *n, shaper_plan_t *out);

/* Runs a plan. Returns how many commands reported failure. */
int  shaper_run(shaper_ctx_t *s, const shaper_plan_t *p);

int  shaper_apply(shaper_ctx_t *s, vlan_ctx_t *v, netconf_ctx_t *n);
int  shaper_teardown(shaper_ctx_t *s, vlan_ctx_t *v, netconf_ctx_t *n);

const char *qdisc_name(qdisc_t q);
qdisc_t     qdisc_from(const char *s);

/* Which class a VLAN is given, so the console can show the hierarchy. */
int  shaper_classid_for(vlan_ctx_t *v, uint16_t vlan_id);

#endif
