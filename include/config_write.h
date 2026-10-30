#ifndef FIREX_CONFIG_WRITE_H
#define FIREX_CONFIG_WRITE_H

#include <time.h>
#include "vlan.h"
#include "netconf.h"
#include "blockpage.h"
#include "policy.h"
#include "vpn.h"

/*
 * Serialising half of the enterprise config. Exact inverse of
 * firex_load_enterprise_config() in enterprise_config.c -- anything this
 * writes must parse back to the same in-memory state, which tests/test_config.c
 * asserts by round-tripping the shipped configs.
 */

#define CFG_NOTE_LEN   128
#define CFG_AUTHOR_LEN 32

typedef struct {
    int    revision;              /* 0 = unversioned, no header emitted */
    time_t when;
    char   author[CFG_AUTHOR_LEN];
    char   note[CFG_NOTE_LEN];
} cfg_meta_t;

/*
 * Writes the complete running configuration to `path`. The write goes to
 * "<path>.tmp" and is fsync'd and renamed into place, so a crash or a full
 * disk can never leave a half-written config where the appliance will try to
 * boot from it. `meta` may be NULL.
 */
int firex_save_enterprise_config(const char *path,
                                 vlan_ctx_t *v,
                                 netconf_ctx_t *n,
                                 blockpage_ctx_t *bp,
                                 const cfg_meta_t *meta);

/* As above, including the alias and schedule table. Passing NULL for `pol`
 * writes no [alias] or [schedule] blocks. */
int firex_save_enterprise_config_ex(const char *path,
                                    vlan_ctx_t *v,
                                    netconf_ctx_t *n,
                                    blockpage_ctx_t *bp,
                                    policy_ctx_t *pol,
                                    vpn_ctx_t *vpn,
                                    const cfg_meta_t *meta);

/* Reads back the "# @rev / @time / @author / @note" header a saved config
 * carries. Returns 0 when a header was found. */
int firex_read_config_meta(const char *path, cfg_meta_t *out);

#endif
