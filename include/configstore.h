#ifndef FIREX_CONFIGSTORE_H
#define FIREX_CONFIGSTORE_H

#include <stdbool.h>
#include <pthread.h>
#include "config_write.h"

/*
 * Versioned configuration store.
 *
 *   /etc/firex/firex.conf           the active config the daemon loads
 *   /etc/firex/config.d/00001.conf  revision 1
 *   /etc/firex/config.d/00002.conf  revision 2  ...
 *
 * Every save writes a new numbered revision and then replaces the active file
 * with it. History is append-only: a rollback copies an old revision over the
 * active file and records that as a new revision, so the trail of who changed
 * what is never rewritten.
 */

#define CFG_PATH_LEN      512
#define CFG_KEEP_DEFAULT  32       /* revisions retained before pruning */

/* `dir` is kept shorter than a full path so that "<dir>/NNNNN.conf" always
 * fits in CFG_PATH_LEN without truncation. */
#define CFG_DIR_LEN (CFG_PATH_LEN - 32)

typedef struct {
    char            dir[CFG_DIR_LEN];      /* .../config.d           */
    char            active[CFG_PATH_LEN];  /* .../firex.conf         */
    int             keep;
    bool            ready;
    pthread_mutex_t lock;
} cfgstore_t;

typedef struct {
    int    revision;
    time_t when;
    char   author[CFG_AUTHOR_LEN];
    char   note[CFG_NOTE_LEN];
    char   path[CFG_PATH_LEN];
} cfg_revision_t;

/* Derives the store directory from the active config path and creates it.
 * Returns 0 on success, -1 if the directory cannot be made (a read-only
 * filesystem, say), in which case the daemon still runs -- it just cannot
 * version anything, and `ready` stays false. */
int  cfgstore_init(cfgstore_t *s, const char *active_path);

/* Serialises the live state into a new revision and makes it active.
 * Returns the new revision number, or -1. */
int  cfgstore_commit(cfgstore_t *s,
                     vlan_ctx_t *v, netconf_ctx_t *n, blockpage_ctx_t *bp,
                     policy_ctx_t *pol, vpn_ctx_t *vpn,
                     const char *author, const char *note);

/* Newest first. Returns how many were written to `out`. */
int  cfgstore_list(cfgstore_t *s, cfg_revision_t *out, int max);

/* Absolute path of one revision; -1 when it does not exist. */
int  cfgstore_path_for(cfgstore_t *s, int rev, char *buf, size_t len);

/* Copies an existing revision over the active config. The caller is expected
 * to reload afterwards and then commit the result as a new revision. */
int  cfgstore_rollback(cfgstore_t *s, int rev);

/* Highest revision number present, or 0 when the store is empty. */
int  cfgstore_latest(cfgstore_t *s);

void cfgstore_shutdown(cfgstore_t *s);

#endif
