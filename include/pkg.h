#ifndef FIREX_PKG_H
#define FIREX_PKG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "update.h"

/*
 * Add-on packages.
 *
 * A package is an ordinary signed bundle (kind: package) whose payload is
 * a gzipped tar. There is no separate package format and no second
 * signature scheme: whatever verifies a system image verifies a package,
 * which is the point -- one trust root, one verifier to get right.
 *
 * Installation never streams a tarball straight onto the filesystem. The
 * archive is listed first, every member path is checked, and extraction
 * only starts once all of them are safe. A tar member called
 * "../../etc/shadow" is a refusal of the whole package, not a skipped
 * file, because a package that tried it is not one to half-install.
 */

#define PKG_MAX_INSTALLED  64
#define PKG_MAX_FILES      4096
#define PKG_PATH_LEN       256
#define PKG_CMD_LEN        512
#define PKG_MAX_CMDS       16

typedef struct {
    char     name[64];
    char     version[32];
    char     description[160];
    char     sha256[UPD_SHA_HEX];
    uint64_t installed;
    int      file_count;
} pkg_info_t;

typedef struct {
    char       root[PKG_PATH_LEN];   /* where package files are unpacked */
    char       db[PKG_PATH_LEN];     /* where the install records live   */
    pkg_info_t pkg[PKG_MAX_INSTALLED];
    int        count;
} pkg_ctx_t;

/* Same plan-then-run shape as the shaper and HA: build the command list,
 * let a caller print it, and only then hand it to the shell. */
typedef struct {
    char cmd[PKG_MAX_CMDS][PKG_CMD_LEN];
    int  count;
} pkg_plan_t;

void pkg_init(pkg_ctx_t *p, const char *root, const char *db);

/* Reads every *.pkg record under db. A missing directory is not an error. */
int  pkg_db_load(pkg_ctx_t *p, char *err, size_t errlen);

pkg_info_t *pkg_find(pkg_ctx_t *p, const char *name);

/*
 * Is this tar member safe to extract under a package root?
 *
 * Rejects absolute paths, any ".." component, paths that start with "./.."
 * or contain a backslash, device-ish names, and anything over PKG_PATH_LEN.
 * why (optional) receives the reason. This is the function that decides
 * whether a hostile archive can escape the package root, so it is written
 * to reject anything it does not positively recognise.
 */
bool pkg_path_safe(const char *path, char *why, size_t whylen);

/* Applies pkg_path_safe to a whole listing. Returns the index of the
 * first bad entry, or -1 when all of them are safe. */
int  pkg_listing_check(char *const *paths, int n, char *why, size_t whylen);

/*
 * Builds the commands that would install an already-verified bundle.
 * Nothing runs and nothing is written; this is what --dry-run prints.
 */
int  pkg_plan_install(const pkg_ctx_t *p, const upd_meta_t *m,
                      const char *payload_path, pkg_plan_t *out);

int  pkg_plan_remove(const pkg_ctx_t *p, const pkg_info_t *info, pkg_plan_t *out);

/*
 * Verifies the bundle against the keyring, checks it is a package, lists
 * the archive, refuses any unsafe member, extracts, and records the
 * install. dry_run stops after the checks and fills plan instead.
 */
int  pkg_install(pkg_ctx_t *p, const char *bundle, const upd_keyring_t *ring,
                 bool dry_run, pkg_plan_t *plan, char *err, size_t errlen);

int  pkg_remove(pkg_ctx_t *p, const char *name, bool dry_run,
                pkg_plan_t *plan, char *err, size_t errlen);

/* Writes / reads one install record. Exposed for the tests. */
int  pkg_record_write(const pkg_ctx_t *p, const pkg_info_t *info,
                      char *const *files, int nfiles, char *err, size_t errlen);
int  pkg_record_read(const pkg_ctx_t *p, const char *name, pkg_info_t *out,
                     char *err, size_t errlen);

#endif /* FIREX_PKG_H */
