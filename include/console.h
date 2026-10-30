#ifndef FIREX_CONSOLE_H
#define FIREX_CONSOLE_H

#include <stdbool.h>
#include <stddef.h>
#include "update.h"
#include "pkg.h"
#include "vlan.h"
#include "netconf.h"

/*
 * The serial console menu.
 *
 * This is what an operator sees on ttyS0 when the web console is
 * unreachable, so it has to work when very little else does: no GTK, no
 * network, no name resolution. The menu itself is therefore split in two.
 * console_render() and console_lookup() are pure -- they turn state into
 * text and text into an action, and the tests drive them directly. Only
 * console_run() touches a terminal, and only the handlers touch the system.
 */

typedef enum {
    CON_NONE = 0,
    CON_STATUS,
    CON_IFACES,
    CON_SETIP,
    CON_PASSWD,
    CON_PING,
    CON_RELOAD,
    CON_UPDATE,
    CON_SLOTS,
    CON_ROLLBACK,
    CON_PACKAGES,
    CON_FACTORY,
    CON_SHELL,
    CON_DESKTOP,
    CON_REBOOT,
    CON_HALT,
    CON_LOGOUT,
    CON_INVALID
} console_action_t;

typedef struct {
    int              choice;
    console_action_t action;
    const char      *label;
    bool             destructive;  /* asks for confirmation before running */
    bool             needs_root;
} console_item_t;

/* The menu table, in display order. */
const console_item_t *console_items(int *count);
const console_item_t *console_item_for(console_action_t a);

/*
 * Turns a line of operator input into an action. Leading and trailing
 * whitespace is ignored, an empty line is CON_NONE (redraw), and anything
 * that is not exactly one of the listed numbers is CON_INVALID -- "5x"
 * and "5 6" are both refused rather than read as 5.
 */
console_action_t console_lookup(const char *input);

/* Renders the banner and menu into out. Returns the length, or -1. */
int console_render(char *out, size_t outlen,
                   const char *hostname, const char *version,
                   const slots_t *slots);

/* The one line that summarises A/B state at the top of the menu. */
int console_slot_line(const slots_t *s, char *out, size_t outlen);

typedef struct {
    vlan_ctx_t    *vlan;
    netconf_ctx_t *netconf;
    pkg_ctx_t     *pkg;
    slots_t       *slots;
    const char    *slots_path;
    const char    *keyring_path;
    const char    *config_path;
    const char    *users_path;     /* console user database; NULL disables */
    const char    *hostname;
} console_ctx_t;

/*
 * Asks for a console login when users_path names a database with at least
 * one user in it. An appliance with no users configured cannot be locked
 * out of its own console, so the menu opens with a warning instead -- but
 * that is a fallback for a half-built system, not a mode to ship in.
 * Returns 0 when the operator was let in, -1 when they were not.
 */
int console_login(console_ctx_t *ctx);

/* The interactive loop. Returns when the operator chooses to log out. */
int console_run(console_ctx_t *ctx);

#endif /* FIREX_CONSOLE_H */
