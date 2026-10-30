#ifndef FIREX_RELOAD_H
#define FIREX_RELOAD_H

#include <stdbool.h>
#include <stddef.h>
#include "vlan.h"
#include "netconf.h"
#include "blockpage.h"
#include "policy.h"
#include "vpn.h"

/*
 * Validate / stage / apply / rollback.
 *
 * A reload never edits the live configuration in place. The candidate is
 * parsed into throwaway contexts and validated there, so a config that cannot
 * be loaded is rejected while the appliance is still serving the old one. Only
 * after it passes is the live state swapped and re-applied to the system, and
 * if applying fails the previous configuration is put back and re-applied.
 */

#define CFG_ERR_LEN 256

typedef struct {
    int  vlans, ports, acls, wans, forwards;
    int  aliases, schedules, routes;
    int  wg_ifaces, wg_peers, ipsec_tunnels;
    int  warnings;
    char error[CFG_ERR_LEN];     /* empty when valid */
    char warning[CFG_ERR_LEN];   /* first warning, if any */
} cfg_validate_t;

/* Semantic checks over an already-parsed configuration. Returns 0 when the
 * configuration is usable. Safe to call on staging or live contexts; takes no
 * locks, so the caller holds them if the contexts are live. */
int firex_validate(vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *bp,
                   vpn_ctx_t *vpn, cfg_validate_t *out);

/* Parse `path` into throwaway contexts and validate. Touches neither the
 * globals nor the network -- this is what --check runs. */
int firex_validate_file(const char *path, cfg_validate_t *out);

/* Full cycle: validate `path`, swap it into the live contexts, re-apply to the
 * system. On any failure the previous configuration is restored and the
 * reason is written to `err`. Returns 0 on success. */
int firex_reload_file(const char *path, bool apply_net, char *err, size_t errlen);

/* True when the candidate changes something that only a restart can pick up
 * (currently just the portal's listening port). */
bool firex_needs_restart(const blockpage_ctx_t *live, const blockpage_ctx_t *cand);

#endif
