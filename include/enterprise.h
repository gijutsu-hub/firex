#ifndef FIREX_ENTERPRISE_H
#define FIREX_ENTERPRISE_H

#include "vlan.h"
#include "policy.h"
#include "vpn.h"
#include "netconf.h"
#include "blockpage.h"

/* Load the single enterprise config file that drives segmentation, the WAN
 * links, published services and the block-page portal. Returns 0 on success. */
int firex_load_enterprise_config(const char *path,
                                 vlan_ctx_t *v,
                                 netconf_ctx_t *n,
                                 blockpage_ctx_t *bp);

/*
 * As above, plus the alias / schedule table. Passing NULL for `pol` drops
 * [alias] and [schedule] blocks on the floor (with a warning) rather than
 * failing, which is what the plain form does.
 */
int firex_load_enterprise_config_ex(const char *path,
                                    vlan_ctx_t *v,
                                    netconf_ctx_t *n,
                                    blockpage_ctx_t *bp,
                                    policy_ctx_t *pol,
                                    vpn_ctx_t *vpn);

#endif
