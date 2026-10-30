#ifndef FIREX_GUIAPP_H
#define FIREX_GUIAPP_H

#include <stdbool.h>
#include <stddef.h>

#include "auth.h"

/*
 * The desktop console.
 *
 * FireX has four ways in -- the web console, SSH, the serial menu and this
 * GUI -- and they only mean the same thing if they read the same state.
 * So this is a CLIENT of the running daemon over its own HTTP API, exactly
 * like the web console, rather than a second copy of the engine with its
 * own idea of what the appliance is doing.
 *
 * That also settles authentication: one user database, one session table,
 * one throttle. Signing in here is the same act as signing in at
 * http://<appliance>:8080/ui, and `root`/`root` or `admin`/`admin` work on
 * all four surfaces.
 */

#define FXC_HOST_LEN   64
#define FXC_ERR_LEN   256

typedef struct {
    char host[FXC_HOST_LEN];
    int  port;

    char token[AUTH_TOKEN_LEN];   /* session cookie value  */
    char csrf[AUTH_CSRF_LEN];     /* double-submit token   */
    char user[AUTH_USER_LEN];
    char role[16];
    bool connected;

    /*
     * How the last request actually travelled, and who answered.
     *
     * Discovered per connection rather than configured: the client tries
     * a TLS handshake and treats a failure as "this listener is plain
     * HTTP". The sign-in screen reads these so an operator can see
     * whether the password they are about to type crosses the network in
     * the clear, and can compare the fingerprint against the one the
     * daemon prints on the serial console.
     */
    bool tls;
    char fingerprint[96];         /* SHA-256, colon-separated hex */
} fx_client_t;

void fxc_init(fx_client_t *c, const char *host, int port);

/* True when something is listening. Used to tell "wrong password" apart
 * from "the daemon is not running", which look identical otherwise. */
bool fxc_alive(const fx_client_t *c);

/*
 * Signs in and keeps the session. 0 on success; -1 with `err` filled on
 * bad credentials, a throttle, or no daemon at all.
 */
int fxc_login(fx_client_t *c, const char *user, const char *pass,
              char *err, size_t errlen);

void fxc_logout(fx_client_t *c);

/* GETs `path` and returns the body, which the caller frees. NULL on
 * failure with `err` filled. */
char *fxc_get(fx_client_t *c, const char *path, char *err, size_t errlen);

/* POSTs `body` as JSON, carrying the CSRF token. Same ownership rules. */
char *fxc_post(fx_client_t *c, const char *path, const char *body,
               char *err, size_t errlen);

/* ── a small JSON reader ──────────────────────────────────────────────
 *
 * Enough to walk the console API's own replies and no more. It is not a
 * general parser: it assumes the well-formed output of src/webui.c, which
 * is the only thing it is ever pointed at.
 */

/* Looks up "key": within `json` and copies its string value. */
bool fxj_str(const char *json, const char *key, char *out, size_t outlen);

/* Same for a number; also accepts true/false as 1/0. */
bool fxj_num(const char *json, const char *key, double *out);

/* First element of the array at "key", or NULL. */
const char *fxj_array(const char *json, const char *key);

/* Walks to the next element of the array `p` points into, or NULL at the
 * closing bracket. Nested braces and quoted strings are skipped. */
const char *fxj_next(const char *p);

/* How many elements the array at "key" holds. */
int fxj_count(const char *json, const char *key);

/* ── interfaces ───────────────────────────────────────────────────────
 *
 * What `ip addr` would tell you, gathered here so the login screen can
 * say where the appliance actually is. An operator in front of a console
 * that will not let them in needs the address before anything else.
 */

#define FX_IFINFO_MAX 16

typedef struct {
    char name[32];
    char addr[46];      /* empty when the link carries no IPv4 */
    char mask[46];
    bool up;
    bool loopback;
} fx_ifinfo_t;

int fx_ifinfo(fx_ifinfo_t *out, int max);

/* The address an operator should actually type: the first routable IPv4,
 * skipping loopback and down links. Falls back to "<appliance>". */
void fx_primary_address(char *out, size_t outlen);

#endif /* FIREX_GUIAPP_H */
