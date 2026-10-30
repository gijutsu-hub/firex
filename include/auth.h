#ifndef FIREX_AUTH_H
#define FIREX_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

/*
 * Console authentication.
 *
 * Users live in a colon-separated file, one per line, mode 0600:
 *
 *     admin:$6$<salt>$<sha512-crypt>:admin
 *     ops:$6$<salt>$<sha512-crypt>:viewer
 *
 * Passwords are hashed with the system crypt(3) in SHA-512 mode; the plain
 * text is never stored and never logged. When the file is absent on first
 * start an `admin` account is created with a generated password that is
 * printed once -- the same pattern the image build uses for the root account.
 *
 * Sessions are held in memory only, so a restart logs everyone out. That is
 * deliberate: there is no session store to steal from disk.
 */

#define AUTH_USER_LEN     32
#define AUTH_HASH_LEN     128
#define AUTH_TOKEN_LEN    65     /* 64 hex characters + NUL */
#define AUTH_CSRF_LEN     33     /* 32 hex characters + NUL */
#define AUTH_MAX_USERS    16
#define AUTH_MAX_SESSIONS 32

/* Session lifetime. Idle expiry bounds an abandoned browser tab; the absolute
 * cap bounds a stolen cookie. */
#define AUTH_IDLE_SECONDS      (30 * 60)
#define AUTH_ABSOLUTE_SECONDS  (12 * 60 * 60)

/* Failed-login throttle, per source address. */
#define AUTH_FAIL_THRESHOLD    5
#define AUTH_FAIL_LOCKOUT      60

/*
 * Shipped defaults. The image build seeds `root` and `admin` with their own
 * names as passwords so a fresh appliance can always be reached -- root/root
 * and admin/admin, both for SSH and for the web console. That is a known
 * credential on a known port, so the console shows a banner until it is
 * changed and auth_list() reports which accounts are still at the default.
 *
 * The rule IS "the password equals the user name"; there is no table to keep
 * in step with the build script.
 */
#define AUTH_DEFAULT_FOR(name)  (name)

/* Minimum length for a password an operator chooses. The seeded defaults are
 * shorter on purpose and are written by the build, not through this path. */
#define AUTH_MIN_PASSWORD      8

#define AUTH_SHADOW_PATH       "/etc/shadow"
#define AUTH_CHPASSWD_CMD      "/usr/sbin/chpasswd 2>/dev/null"

typedef enum {
    ROLE_NONE = 0,
    ROLE_VIEWER,     /* may read every endpoint */
    ROLE_ADMIN       /* may also write and apply */
} fx_role_t;

/* One row of auth_list(): what the console may show about an account. */
typedef struct {
    char      name[AUTH_USER_LEN];
    fx_role_t role;
    bool      is_default;    /* the password is still the shipped default */
} auth_entry_t;

typedef struct {
    char      token[AUTH_TOKEN_LEN];
    char      csrf[AUTH_CSRF_LEN];
    char      user[AUTH_USER_LEN];
    fx_role_t role;
    uint32_t  peer;
    time_t    created;
    time_t    last_seen;
    bool      used;
} fx_session_t;

typedef struct {
    char      path[512];
    bool      ready;

    struct {
        char      name[AUTH_USER_LEN];
        char      hash[AUTH_HASH_LEN];
        fx_role_t role;
        bool      used;
    } users[AUTH_MAX_USERS];
    int user_count;

    fx_session_t sessions[AUTH_MAX_SESSIONS];

    struct {
        uint32_t ip;
        int      failures;
        time_t   last_fail;
    } throttle[AUTH_MAX_SESSIONS];

    pthread_mutex_t lock;
} auth_ctx_t;

/* Loads (or bootstraps) the user file. Returns 0 on success. */
int  auth_init(auth_ctx_t *a, const char *path);

/* Verifies credentials and opens a session. Returns 0 and fills `out` on
 * success; -1 on bad credentials, -2 when the source address is throttled,
 * -3 when the session table is full. */
int  auth_login(auth_ctx_t *a, const char *user, const char *pass,
                uint32_t peer, fx_session_t *out);

/* Looks up a live session by token and refreshes its idle timer. Returns NULL
 * when the token is unknown or expired. The returned pointer is a copy in
 * `out`, so callers never hold the table lock. */
bool auth_session(auth_ctx_t *a, const char *token, fx_session_t *out);

void auth_logout(auth_ctx_t *a, const char *token);

/* Constant-time comparison of a presented CSRF token against the session. */
bool auth_csrf_ok(const fx_session_t *s, const char *presented);

/* Replaces a user's password, rewriting the user file. */
int  auth_set_password(auth_ctx_t *a, const char *user, const char *pass);

/* Adds a user; -1 if the name is taken or the table is full. */
int  auth_add_user(auth_ctx_t *a, const char *user, const char *pass,
                   fx_role_t role);

const char *auth_role_name(fx_role_t r);

/* "admin" / "viewer" -> the enum; anything else is ROLE_NONE. */
fx_role_t   auth_role_from(const char *s);

/*
 * Loads the database without bootstrapping anything and without printing.
 * auth_init() creates an admin account when the file is missing, which is
 * right at daemon start and wrong for a tool that is about to set a
 * password itself. A missing file leaves an empty, usable context.
 */
int auth_load_quiet(auth_ctx_t *a, const char *path);

/* Copies up to `max` accounts into `out`; returns how many were written.
 * Hashes never leave the module -- is_default carries the only verdict a
 * caller needs. */
int  auth_list(auth_ctx_t *a, auth_entry_t *out, int max);

/* True when `user` exists and `pass` is its current password. */
bool auth_password_is(auth_ctx_t *a, const char *user, const char *pass);

/*
 * The Linux account of the same name, read from /etc/shadow:
 *   0  set to something of the operator's own
 *   1  still the shipped default (the password is the user name)
 *   2  locked, or no password at all
 *  -1  no such account
 *  -2  /etc/shadow could not be read at all
 */
int  auth_system_state(const char *user);

/* The same, against a shadow file of the caller's choosing. Only the
 * tests pass anything but AUTH_SHADOW_PATH -- a parser nobody can point
 * at a fixture is a parser nobody checks. */
int  auth_system_state_in(const char *shadow_path, const char *user);

/* Sets that Linux account's password through chpasswd. 0 on success. */
int  auth_system_set_password(const char *user, const char *pass);

void auth_shutdown(auth_ctx_t *a);

#endif
