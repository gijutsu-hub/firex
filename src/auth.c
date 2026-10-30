/*
 * Console authentication. See include/auth.h for the storage format.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <crypt.h>
#include <sys/stat.h>

#include "auth.h"
#include "netutil.h"
#include "brand.h"

static const char HEXDIG[] = "0123456789abcdef";

/* crypt(3) salt alphabet. */
static const char SALTCHARS[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static bool random_bytes(unsigned char *out, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) { close(fd); return false; }
        got += (size_t)r;
    }
    close(fd);
    return true;
}

/* Fills `out` with `hexchars` hex digits plus a NUL. */
static bool random_hex(char *out, size_t hexchars) {
    size_t nbytes = hexchars / 2;
    unsigned char buf[64];
    if (nbytes > sizeof(buf)) return false;
    if (!random_bytes(buf, nbytes)) return false;
    for (size_t i = 0; i < nbytes; i++) {
        out[i*2]     = HEXDIG[buf[i] >> 4];
        out[i*2 + 1] = HEXDIG[buf[i] & 0x0f];
    }
    out[hexchars] = '\0';
    return true;
}

/* Comparison whose timing does not depend on where the first difference is.
 * Used for every secret: session tokens, CSRF tokens, password hashes. */
static bool ct_eq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    unsigned char diff = (unsigned char)(la ^ lb);
    size_t n = la < lb ? la : lb;
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0 && la == lb;
}

static bool make_salt(char *out, size_t len) {
    /* "$6$" + 16 salt characters + "$" */
    if (len < 21) return false;
    unsigned char raw[16];
    if (!random_bytes(raw, sizeof(raw))) return false;
    memcpy(out, "$6$", 3);
    for (size_t i = 0; i < sizeof(raw); i++)
        out[3 + i] = SALTCHARS[raw[i] % (sizeof(SALTCHARS) - 1)];
    out[19] = '$';
    out[20] = '\0';
    return true;
}

static int hash_password(const char *pass, char *out, size_t len) {
    char salt[32];
    if (!make_salt(salt, sizeof(salt))) return -1;

    struct crypt_data data;
    memset(&data, 0, sizeof(data));
    char *h = crypt_r(pass, salt, &data);
    if (!h || h[0] != '$') return -1;
    if (snprintf(out, len, "%s", h) >= (int)len) return -1;
    return 0;
}

static bool verify_password(const char *pass, const char *stored) {
    if (!stored[0]) return false;
    struct crypt_data data;
    memset(&data, 0, sizeof(data));
    char *h = crypt_r(pass, stored, &data);
    if (!h) return false;
    return ct_eq(h, stored);
}

static fx_role_t role_from(const char *s);

fx_role_t auth_role_from(const char *s) { return role_from(s); }

static fx_role_t role_from(const char *s) {
    if (!strcasecmp(s, "admin"))  return ROLE_ADMIN;
    if (!strcasecmp(s, "viewer")) return ROLE_VIEWER;
    return ROLE_NONE;
}

const char *auth_role_name(fx_role_t r) {
    switch (r) {
        case ROLE_ADMIN:  return "admin";
        case ROLE_VIEWER: return "viewer";
        default:          return "none";
    }
}

/* ── user file ─────────────────────────────────────────────────────── */

static int write_users_locked(auth_ctx_t *a) {
    char tmp[600];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", a->path) >= (int)sizeof(tmp))
        return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }

    fprintf(f, "# %s console users -- username:crypt-hash:role\n", BRAND_PRODUCT);
    for (int i = 0; i < a->user_count; i++) {
        if (!a->users[i].used) continue;
        fprintf(f, "%s:%s:%s\n", a->users[i].name, a->users[i].hash,
                auth_role_name(a->users[i].role));
    }

    int rc = 0;
    if (fflush(f) != 0) rc = -1;
    if (rc == 0 && fsync(fileno(f)) != 0) rc = -1;
    if (fclose(f) != 0) rc = -1;

    if (rc != 0 || rename(tmp, a->path) != 0) { unlink(tmp); return -1; }
    return 0;
}

static int load_users_locked(auth_ctx_t *a) {
    FILE *f = fopen(a->path, "r");
    if (!f) return -1;

    a->user_count = 0;
    char line[512];
    while (fgets(line, sizeof(line), f) && a->user_count < AUTH_MAX_USERS) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        char *name = line;
        char *hash = strchr(name, ':');
        if (!hash) continue;
        *hash++ = '\0';
        char *role = strrchr(hash, ':');
        if (!role) continue;
        *role++ = '\0';

        if (!*name || !*hash) continue;
        /* Truncating here would let two distinct accounts collapse into one
         * name, so an over-long entry is skipped rather than shortened. */
        if (strlen(name) >= AUTH_USER_LEN || strlen(hash) >= AUTH_HASH_LEN) {
            fprintf(stderr, "[%s] console auth: skipping over-long entry\n",
                    BRAND_PRODUCT);
            continue;
        }
        int i = a->user_count;
        memcpy(a->users[i].name, name, strlen(name) + 1);
        memcpy(a->users[i].hash, hash, strlen(hash) + 1);
        a->users[i].role = role_from(role);
        a->users[i].used = true;
        a->user_count++;
    }
    fclose(f);
    return a->user_count > 0 ? 0 : -1;
}

/* A generated password, printed once. Avoids the ambiguous glyphs so it can be
 * read off a console screen without guessing. */
static bool generate_password(char *out, size_t len) {
    static const char ALPHA[] =
        "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    if (len < 17) return false;
    unsigned char raw[16];
    if (!random_bytes(raw, sizeof(raw))) return false;
    for (size_t i = 0; i < sizeof(raw); i++)
        out[i] = ALPHA[raw[i] % (sizeof(ALPHA) - 1)];
    out[16] = '\0';
    return true;
}

int auth_load_quiet(auth_ctx_t *a, const char *path) {
    memset(a, 0, sizeof(*a));
    pthread_mutex_init(&a->lock, NULL);
    snprintf(a->path, sizeof(a->path), "%s", path);
    /* A missing file is an empty database, not a failure: the caller is
     * about to create the first account in it. */
    load_users_locked(a);
    a->ready = true;
    return 0;
}

int auth_init(auth_ctx_t *a, const char *path) {
    memset(a, 0, sizeof(*a));
    pthread_mutex_init(&a->lock, NULL);
    snprintf(a->path, sizeof(a->path), "%s", path);

    if (load_users_locked(a) == 0) {
        a->ready = true;
        printf("[%s] console auth: %d user(s) from %s\n",
               BRAND_PRODUCT, a->user_count, a->path);
        return 0;
    }

    /* Bootstrap. */
    char pass[32];
    if (!generate_password(pass, sizeof(pass))) {
        fprintf(stderr, "[%s] console auth: no entropy for a password\n",
                BRAND_PRODUCT);
        return -1;
    }
    if (auth_add_user(a, "admin", pass, ROLE_ADMIN) != 0) {
        fprintf(stderr, "[%s] console auth: cannot create %s (%s)\n",
                BRAND_PRODUCT, a->path, strerror(errno));
        explicit_bzero(pass, sizeof(pass));
        return -1;
    }
    a->ready = true;

    printf("\n  ==================================================\n");
    printf("    %s console account created\n", BRAND_PRODUCT);
    printf("      username : admin\n");
    printf("      password : %s\n", pass);
    printf("    Shown once. Stored hashed in %s\n", a->path);
    printf("  ==================================================\n\n");
    explicit_bzero(pass, sizeof(pass));
    return 0;
}

int auth_add_user(auth_ctx_t *a, const char *user, const char *pass,
                  fx_role_t role) {
    if (!user || !*user || !pass || !*pass) return -1;

    pthread_mutex_lock(&a->lock);
    if (a->user_count >= AUTH_MAX_USERS) {
        pthread_mutex_unlock(&a->lock);
        return -1;
    }
    for (int i = 0; i < a->user_count; i++)
        if (a->users[i].used && !strcmp(a->users[i].name, user)) {
            pthread_mutex_unlock(&a->lock);
            return -1;
        }

    int i = a->user_count;
    char hash[AUTH_HASH_LEN];
    if (hash_password(pass, hash, sizeof(hash)) != 0) {
        pthread_mutex_unlock(&a->lock);
        return -1;
    }
    snprintf(a->users[i].name, AUTH_USER_LEN, "%s", user);
    snprintf(a->users[i].hash, AUTH_HASH_LEN, "%s", hash);
    a->users[i].role = role;
    a->users[i].used = true;
    a->user_count++;

    int rc = write_users_locked(a);
    if (rc != 0) { a->users[i].used = false; a->user_count--; }
    explicit_bzero(hash, sizeof(hash));
    pthread_mutex_unlock(&a->lock);
    return rc;
}

int auth_set_password(auth_ctx_t *a, const char *user, const char *pass) {
    if (!user || !pass || !*pass) return -1;

    pthread_mutex_lock(&a->lock);
    int found = -1;
    for (int i = 0; i < a->user_count; i++)
        if (a->users[i].used && !strcmp(a->users[i].name, user)) { found = i; break; }
    if (found < 0) { pthread_mutex_unlock(&a->lock); return -1; }

    char hash[AUTH_HASH_LEN];
    if (hash_password(pass, hash, sizeof(hash)) != 0) {
        pthread_mutex_unlock(&a->lock);
        return -1;
    }
    char old[AUTH_HASH_LEN];
    snprintf(old, sizeof(old), "%s", a->users[found].hash);
    snprintf(a->users[found].hash, AUTH_HASH_LEN, "%s", hash);

    int rc = write_users_locked(a);
    if (rc != 0) snprintf(a->users[found].hash, AUTH_HASH_LEN, "%s", old);

    explicit_bzero(hash, sizeof(hash));
    explicit_bzero(old,  sizeof(old));

    /* A password change invalidates every session that user holds. */
    if (rc == 0)
        for (int i = 0; i < AUTH_MAX_SESSIONS; i++)
            if (a->sessions[i].used && !strcmp(a->sessions[i].user, user))
                memset(&a->sessions[i], 0, sizeof(a->sessions[i]));

    pthread_mutex_unlock(&a->lock);
    return rc;
}

/* ── throttle ──────────────────────────────────────────────────────── */

static bool throttled_locked(auth_ctx_t *a, uint32_t ip, time_t now) {
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (a->throttle[i].ip != ip) continue;
        if (a->throttle[i].failures < AUTH_FAIL_THRESHOLD) return false;
        /* Lockout grows with the overshoot, capped so an attacker cannot lock
         * a legitimate address out indefinitely. */
        int over = a->throttle[i].failures - AUTH_FAIL_THRESHOLD;
        int wait = AUTH_FAIL_LOCKOUT * (over + 1);
        if (wait > 900) wait = 900;
        return (now - a->throttle[i].last_fail) < wait;
    }
    return false;
}

static void record_fail_locked(auth_ctx_t *a, uint32_t ip, time_t now) {
    int free_slot = -1, oldest = 0;
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        if (a->throttle[i].ip == ip) {
            a->throttle[i].failures++;
            a->throttle[i].last_fail = now;
            return;
        }
        if (!a->throttle[i].ip && free_slot < 0) free_slot = i;
        if (a->throttle[i].last_fail < a->throttle[oldest].last_fail) oldest = i;
    }
    int slot = free_slot >= 0 ? free_slot : oldest;
    a->throttle[slot].ip        = ip;
    a->throttle[slot].failures  = 1;
    a->throttle[slot].last_fail = now;
}

static void clear_fail_locked(auth_ctx_t *a, uint32_t ip) {
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++)
        if (a->throttle[i].ip == ip) memset(&a->throttle[i], 0, sizeof(a->throttle[i]));
}

/* ── sessions ──────────────────────────────────────────────────────── */

static bool session_expired(const fx_session_t *s, time_t now) {
    return (now - s->last_seen) > AUTH_IDLE_SECONDS ||
           (now - s->created)   > AUTH_ABSOLUTE_SECONDS;
}

static void reap_locked(auth_ctx_t *a, time_t now) {
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++)
        if (a->sessions[i].used && session_expired(&a->sessions[i], now))
            memset(&a->sessions[i], 0, sizeof(a->sessions[i]));
}

int auth_login(auth_ctx_t *a, const char *user, const char *pass,
               uint32_t peer, fx_session_t *out) {
    if (!a->ready || !user || !pass) return -1;

    time_t now = time(NULL);
    pthread_mutex_lock(&a->lock);
    reap_locked(a, now);

    if (throttled_locked(a, peer, now)) {
        pthread_mutex_unlock(&a->lock);
        return -2;
    }

    int found = -1;
    for (int i = 0; i < a->user_count; i++)
        if (a->users[i].used && !strcmp(a->users[i].name, user)) { found = i; break; }

    /* Hash even when the user does not exist, so a missing account and a wrong
     * password take the same time and cannot be told apart. */
    const char *stored = (found >= 0)
        ? a->users[found].hash
        : "$6$invalidinvalidi$invalid";
    bool ok = verify_password(pass, stored) && found >= 0 &&
              a->users[found].role != ROLE_NONE;

    if (!ok) {
        record_fail_locked(a, peer, now);
        pthread_mutex_unlock(&a->lock);
        return -1;
    }

    int slot = -1;
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++)
        if (!a->sessions[i].used) { slot = i; break; }
    if (slot < 0) {
        pthread_mutex_unlock(&a->lock);
        return -3;
    }

    fx_session_t *s = &a->sessions[slot];
    memset(s, 0, sizeof(*s));
    if (!random_hex(s->token, AUTH_TOKEN_LEN - 1) ||
        !random_hex(s->csrf,  AUTH_CSRF_LEN  - 1)) {
        memset(s, 0, sizeof(*s));
        pthread_mutex_unlock(&a->lock);
        return -3;
    }
    /* Distinct arrays inside the same struct; copy explicitly so the
     * compiler does not have to reason about aliasing. */
    memcpy(s->user, a->users[found].name, AUTH_USER_LEN);
    s->user[AUTH_USER_LEN - 1] = '\0';
    s->role      = a->users[found].role;
    s->peer      = peer;
    s->created   = now;
    s->last_seen = now;
    s->used      = true;

    clear_fail_locked(a, peer);
    *out = *s;
    pthread_mutex_unlock(&a->lock);

    char ab[INET_ADDRSTRLEN];
    printf("[%s] console login: %s (%s) from %s\n", BRAND_PRODUCT,
           s->user, auth_role_name(s->role), fx_ip_str(peer, ab, sizeof(ab)));
    return 0;
}

bool auth_session(auth_ctx_t *a, const char *token, fx_session_t *out) {
    if (!a->ready || !token || !*token) return false;

    time_t now = time(NULL);
    pthread_mutex_lock(&a->lock);
    reap_locked(a, now);

    for (int i = 0; i < AUTH_MAX_SESSIONS; i++) {
        fx_session_t *s = &a->sessions[i];
        if (!s->used || !ct_eq(s->token, token)) continue;
        s->last_seen = now;
        *out = *s;
        pthread_mutex_unlock(&a->lock);
        return true;
    }
    pthread_mutex_unlock(&a->lock);
    return false;
}

void auth_logout(auth_ctx_t *a, const char *token) {
    if (!a->ready || !token || !*token) return;
    pthread_mutex_lock(&a->lock);
    for (int i = 0; i < AUTH_MAX_SESSIONS; i++)
        if (a->sessions[i].used && ct_eq(a->sessions[i].token, token))
            memset(&a->sessions[i], 0, sizeof(a->sessions[i]));
    pthread_mutex_unlock(&a->lock);
}

bool auth_csrf_ok(const fx_session_t *s, const char *presented) {
    if (!s || !presented || !*presented) return false;
    return ct_eq(s->csrf, presented);
}

void auth_shutdown(auth_ctx_t *a) {
    if (!a) return;
    pthread_mutex_lock(&a->lock);
    explicit_bzero(a->sessions, sizeof(a->sessions));
    explicit_bzero(a->users,    sizeof(a->users));
    a->ready = false;
    pthread_mutex_unlock(&a->lock);
    pthread_mutex_destroy(&a->lock);
}

/* ── account inventory and default-credential detection ─────────── */

int auth_list(auth_ctx_t *a, auth_entry_t *out, int max) {
    if (!a || !out || max <= 0) return 0;
    pthread_mutex_lock(&a->lock);
    int n = 0;
    for (int i = 0; i < a->user_count && n < max; i++) {
        if (!a->users[i].used) continue;
        snprintf(out[n].name, sizeof(out[n].name), "%s", a->users[i].name);
        out[n].role = a->users[i].role;
        /*
         * Compared here, under the lock, rather than handing the hash out:
         * the caller gets a yes/no and never a string worth cracking.
         */
        out[n].is_default = verify_password(AUTH_DEFAULT_FOR(a->users[i].name),
                                            a->users[i].hash);
        n++;
    }
    pthread_mutex_unlock(&a->lock);
    return n;
}

bool auth_password_is(auth_ctx_t *a, const char *user, const char *pass) {
    if (!a || !user || !pass) return false;
    pthread_mutex_lock(&a->lock);
    bool hit = false;
    for (int i = 0; i < a->user_count; i++)
        if (a->users[i].used && !strcmp(a->users[i].name, user)) {
            hit = verify_password(pass, a->users[i].hash);
            break;
        }
    pthread_mutex_unlock(&a->lock);
    return hit;
}

/* ── the Linux account behind the console ───────────────────────── */

/*
 * /etc/shadow, second colon-field. Read directly rather than through
 * getspnam(): this runs inside the daemon, and a parser of twenty lines
 * is easier to reason about than NSS, which can be made to talk to the
 * network by a module the appliance did not choose.
 */
static int shadow_hash(const char *path, const char *user,
                       char *out, size_t len) {
    FILE *f = fopen(path, "r");
    /*
     * -2, not -1: "I could not look" and "there is no such account" are
     * different answers, and the console shows them differently. firexd
     * runs as root on the appliance, so an unreadable /etc/shadow means
     * something is wrong rather than that root has no password.
     */
    if (!f) return -2;

    size_t ulen = strlen(user);
    char line[1024];
    int rc = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, user, ulen) != 0 || line[ulen] != ':') continue;
        char *h = line + ulen + 1;
        char *end = strchr(h, ':');
        if (!end) break;
        *end = '\0';
        if (snprintf(out, len, "%s", h) < (int)len) rc = 0;
        break;
    }
    explicit_bzero(line, sizeof(line));
    fclose(f);
    return rc;
}

int auth_system_state_in(const char *shadow_path, const char *user) {
    if (!shadow_path || !user || !*user) return -1;
    char hash[AUTH_HASH_LEN];
    int rc = shadow_hash(shadow_path, user, hash, sizeof(hash));
    if (rc != 0) return (rc == -2) ? -2 : -1;

    int state;
    if (hash[0] != '$')                       state = 2;   /* locked or empty */
    else if (verify_password(user, hash))     state = 1;   /* name as password */
    else                                      state = 0;
    explicit_bzero(hash, sizeof(hash));
    return state;
}

int auth_system_state(const char *user) {
    return auth_system_state_in(AUTH_SHADOW_PATH, user);
}

int auth_system_set_password(const char *user, const char *pass) {
    if (!user || !*user || !pass || !*pass) return -1;
    /*
     * chpasswd takes "user:password" on stdin, so neither value ever
     * reaches a command line where ps(1) would show it. The name is
     * still checked here -- a colon or a newline in it would forge a
     * second record.
     */
    for (const char *p = user; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '-'))
            return -1;
    if (strchr(pass, '\n') || strchr(pass, '\r')) return -1;

    FILE *f = popen(AUTH_CHPASSWD_CMD, "w");
    if (!f) return -1;
    fprintf(f, "%s:%s\n", user, pass);
    int rc = pclose(f);
    return (rc == 0) ? 0 : -1;
}
