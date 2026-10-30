#ifndef FIREX_PORTAL_H
#define FIREX_PORTAL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "vlan.h"

/*
 * Captive portal.
 *
 * Until now FireX hinted at a portal -- DHCP option 114 and a DNAT redirect
 * into an ipset that nothing ever filled -- but there was no login behind it.
 * This is the rest: a session table, vouchers, a RADIUS client, and the
 * firewall state that actually lets an authenticated client out.
 *
 * The enforcement is deliberately inverted from the old intercept. Rather
 * than redirecting a set of "quarantined" clients, everything on a captive
 * VLAN is redirected *unless* its address is in the authenticated set. A bug
 * in the session code then fails closed.
 *
 * HTTPS cannot be intercepted without terminating TLS, which would mean
 * presenting a certificate no client should trust. Those flows are rejected
 * so the browser fails immediately and falls back to the plain-HTTP probe
 * every captive-portal detector makes.
 */

#define PORTAL_MAX_SESSIONS   512
#define PORTAL_MAX_VOUCHERS   512
#define PORTAL_CODE_LEN       16
#define PORTAL_USER_LEN       64
#define PORTAL_SECRET_LEN     64
#define PORTAL_HOST_LEN       128
#define PORTAL_TERMS_LEN      512

#define PORTAL_AUTH_SET       "firex_portal_auth"

/* RADIUS, RFC 2865 */
#define RADIUS_ACCESS_REQUEST  1
#define RADIUS_ACCESS_ACCEPT   2
#define RADIUS_ACCESS_REJECT   3
#define RADIUS_ACCESS_CHALLENGE 11
#define RADIUS_HDR_LEN         20
#define RADIUS_AUTH_LEN        16
#define RADIUS_MAX_PACKET      4096

typedef enum {
    PORTAL_AUTH_CLICK = 0,   /* accept the terms, no credentials */
    PORTAL_AUTH_VOUCHER,
    PORTAL_AUTH_RADIUS
} portal_auth_t;

typedef struct {
    uint32_t ip;
    char     user[PORTAL_USER_LEN];
    char     voucher[PORTAL_CODE_LEN];
    uint16_t vlan_id;
    time_t   started, last_seen, expires;
    bool     used;
} portal_session_t;

typedef struct {
    char   code[PORTAL_CODE_LEN];
    int    minutes;        /* how long it is good for once first redeemed */
    time_t created;
    time_t first_used;     /* 0 while unredeemed */
    char   note[64];
    bool   used;
    bool   enabled;
} portal_voucher_t;

typedef struct {
    bool          enabled;
    portal_auth_t auth;
    int           session_minutes;   /* hard cap on a session */
    int           idle_minutes;      /* expiry after no traffic */
    char          terms[PORTAL_TERMS_LEN];

    char     radius_host[PORTAL_HOST_LEN];
    uint16_t radius_port;
    char     radius_secret[PORTAL_SECRET_LEN];
    char     nas_id[PORTAL_USER_LEN];
    int      radius_timeout_ms;
    int      radius_retries;
} portal_cfg_t;

typedef struct {
    portal_cfg_t     cfg;

    portal_session_t sessions[PORTAL_MAX_SESSIONS];
    portal_voucher_t vouchers[PORTAL_MAX_VOUCHERS];
    int              voucher_count;

    unsigned long    logins_ok, logins_failed, expired;
    bool             apply_net;

    bool             running;
    pthread_t        reaper;
    pthread_mutex_t  lock;
} portal_ctx_t;

int  portal_init(portal_ctx_t *p, const portal_cfg_t *cfg, bool apply_net);
int  portal_start(portal_ctx_t *p);
void portal_stop(portal_ctx_t *p);
void portal_shutdown(portal_ctx_t *p);

/*
 * Authenticates a client and opens a session. `user`/`pass` are used by
 * RADIUS, `voucher` by voucher mode, and neither by click-through.
 * Returns 0 on success, -1 on rejection (with `why` filled), -2 when the
 * session table is full.
 */
int  portal_login(portal_ctx_t *p, uint32_t ip, uint16_t vlan_id,
                  const char *user, const char *pass, const char *voucher,
                  char *why, size_t whylen);

void portal_logout(portal_ctx_t *p, uint32_t ip);

/* The live session for an address, copied out, or false. Refreshes the idle
 * timer as a side effect -- a request through the portal is traffic. */
bool portal_session(portal_ctx_t *p, uint32_t ip, portal_session_t *out);

/* Expires idle and over-age sessions. Called by the reaper; exposed so a
 * test can drive the clock. */
int  portal_reap(portal_ctx_t *p, time_t now);

int  portal_snapshot(portal_ctx_t *p, portal_session_t *out, int max);

/* ── vouchers ── */
int  portal_generate_vouchers(portal_ctx_t *p, int count, int minutes,
                              const char *note);
int  portal_voucher_snapshot(portal_ctx_t *p, portal_voucher_t *out, int max);
int  portal_revoke_voucher(portal_ctx_t *p, const char *code);

/* ── firewall state ── */
int  portal_install_rules(portal_ctx_t *p, vlan_ctx_t *v, const char *portal_ip,
                          int portal_port);
int  portal_teardown_rules(portal_ctx_t *p);

/* ── RADIUS, split so the wire format is testable without a server ── */

/*
 * Builds an Access-Request. `authenticator` must be 16 random bytes supplied
 * by the caller and kept for verifying the reply. Returns the packet length.
 */
int  radius_build_request(uint8_t *out, size_t outlen, uint8_t id,
                          const uint8_t authenticator[RADIUS_AUTH_LEN],
                          const char *user, const char *pass,
                          const char *secret, uint32_t nas_ip,
                          const char *nas_id);

/*
 * Checks a reply's Response Authenticator against the request, then returns
 * its code. -1 when the packet is malformed or the signature does not match,
 * which is the case that matters: without this check anyone who can spoof a
 * UDP source address can grant themselves access.
 */
int  radius_verify_response(const uint8_t *resp, size_t resplen,
                            const uint8_t req_auth[RADIUS_AUTH_LEN],
                            const char *secret);

/* Full exchange. Returns RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT, or -1. */
int  radius_authenticate(const portal_cfg_t *cfg, const char *user,
                         const char *pass, uint32_t nas_ip,
                         char *why, size_t whylen);

const char *portal_auth_name(portal_auth_t a);
portal_auth_t portal_auth_from(const char *s);

/* Renders the login page. Returns the length written. */
int  portal_render_login(portal_ctx_t *p, char *out, size_t outlen,
                         const char *message, const char *redirect);

/* Renders the page a client sees once it is through. */
int  portal_render_success(portal_ctx_t *p, const portal_session_t *s,
                           char *out, size_t outlen);

#endif
