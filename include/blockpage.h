#ifndef FIREX_BLOCKPAGE_H
#define FIREX_BLOCKPAGE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include "brand.h"

#define BLOCKPAGE_PORT     8080

/*
 * The console's default port. Deliberately NOT the portal's: they are two
 * listeners with opposite exposure, and a shared number is how they end up
 * a shared socket again. 8443 is the conventional "admin over TLS" port,
 * and the console now terminates TLS on it -- see blockpage_set_tls().
 */
#define CONSOLE_PORT       8443
#define BLOCKPAGE_TLS_PORT 8443
#define MAX_BLOCK_EVENTS   2048

typedef enum {
    BLK_MALWARE,
    BLK_PHISHING,
    BLK_C2,
    BLK_INTRUSION,
    BLK_POLICY,
    BLK_CATEGORY,
    BLK_VLAN_ACL,
    BLK_ZONE,
    BLK_GEO,
    BLK_RATELIMIT,
    BLK_QUARANTINE,
    BLK_DLP,
    BLK_MAX
} block_reason_t;

typedef struct {
    char           request_id[17];
    time_t         timestamp;
    uint32_t       client_ip;
    uint16_t       vlan_id;
    char           vlan_name[32];
    char           zone[16];
    char           host[256];
    char           url[512];
    block_reason_t reason;
    char           policy_id[32];
    char           detail[256];
    int            severity;
} block_event_t;

/* Largest request the portal will buffer, headers and body together. */
#define BP_MAX_REQUEST     65536
#define BP_READ_TIMEOUT_SEC 10

/*
 * How many requests may be in flight at once, per listener.
 *
 * The server is thread-per-connection, which was unbounded: every accept
 * created a thread, and a thread reserves its stack. The portal listener
 * faces the segments the appliance is defending against, so any host on a
 * guest VLAN could open sockets until pthread_create failed or the box ran
 * out of memory -- and the appliance losing its management console is a
 * worse outcome than a few blocked users waiting a moment for theirs.
 *
 * 64 is far above what either listener sees in normal use (the console has
 * a handful of operators; the portal serves one short page per blocked
 * request) and far below what hurts. Over the limit the connection is
 * closed immediately rather than queued, because a queue under flood is
 * just the same exhaustion with extra latency.
 */
#define BP_MAX_CONNS       64

/*
 * `headers` is the whole raw request including the request line, so a handler
 * can look up Cookie or any other field with strcasestr(). `body` points into
 * that same buffer just past the header block and is NOT NUL-terminated at
 * body_len -- use body_len.
 */
typedef int (*bp_route_fn_fwd)(int fd, const char *method, const char *path,
                               uint32_t peer_ip, const char *headers,
                               const char *body, size_t body_len);

typedef struct {
    int             port;
    int             server_fd;
    bool            running;
    bool            enabled;

    /*
     * The admin console gets its OWN listener.
     *
     * Sharing one socket with the block page was a real exposure, not an
     * untidiness: the block page must face the untrusted segments -- that
     * is its whole job, it is what a quarantined host is redirected to --
     * while the console must never. One bind meant one exposure, and a
     * host on GUEST could reach the login page of the appliance that was
     * quarantining it.
     *
     * admin_bind is the address the console listens on, in network order.
     * 0 means every interface, which is only acceptable while there is no
     * management zone to bind to instead; the daemon says so loudly.
     */
    int             admin_port;
    uint32_t        admin_bind;
    int             admin_fd;
    bool            admin_enabled;

    /*
     * TLS on the console listener, and ONLY the console listener. The
     * portal is reached by clients that have just been intercepted mid
     * request; presenting them a self-signed certificate would replace a
     * branded explanation with a browser interstitial, which is the one
     * outcome the block page exists to avoid.
     *
     * tls_ctx is an SSL_CTX*, kept as void* so that every translation unit
     * including this header does not have to pull in openssl/ssl.h.
     */
    /* Live connection counts, one per listener. Reported on the System
     * page: a count that sits at the limit is the shape of a flood, and
     * the only place that is visible. */
    int             conns_portal;
    int             conns_admin;
    unsigned long   conns_refused;

    bool            tls_enabled;
    void           *tls_ctx;
    char            tls_cert[256];
    char            tls_key[256];
    char            tls_fingerprint[96];   /* SHA-256, colon-separated hex */
    unsigned long   tls_handshake_fail;

    char            org_name[64];
    char            admin_contact[128];
    bool            show_technical;
    bool            allow_override;
    bool            show_logo;

    block_event_t   events[MAX_BLOCK_EVENTS];
    int             event_count, event_idx;
    pthread_mutex_t lock;

    unsigned long   pages_served;
    unsigned long   override_requests;

    bp_route_fn_fwd router;      /* optional admin console routes */
} blockpage_ctx_t;

/* Extra route handler, consulted before the block page is rendered. Returning
 * non-zero means the handler answered the request and closed nothing (the
 * server still closes the socket). Used by the admin console so the HTTP
 * server is not duplicated. */
typedef bp_route_fn_fwd bp_route_fn;
void blockpage_set_router(blockpage_ctx_t *bp, bp_route_fn fn);

/*
 * Where the console listens. Returns -1 and changes nothing when the two
 * listeners would land on the same socket -- the daemon refuses to start
 * rather than silently collapsing back to one exposed port.
 */
int  blockpage_set_admin(blockpage_ctx_t *bp, int port, uint32_t bind_addr);

/*
 * Turn on TLS for the console. `cert` and `key` are PEM paths; when either
 * is missing a self-signed certificate is generated in place, because an
 * appliance whose management console will not start for want of a file is
 * worse than one presenting a certificate the operator has to accept once.
 *
 * NOTHING IS BAKED INTO THE IMAGE. A key shipped in the image is a key
 * every appliance shares, which is a key an attacker already has -- the
 * same reason /etc/ssh host keys are made on first boot rather than built.
 *
 * Returns 0 on success. On failure the console still starts, in the clear,
 * and says so loudly: losing management access to a box is the more
 * dangerous failure of the two.
 */
int  blockpage_set_tls(blockpage_ctx_t *bp, const char *cert, const char *key);

/* True once a TLS context is loaded and the console is serving over it.
 * The console asks before setting the Secure cookie attribute: sending
 * Secure over plain HTTP makes the cookie unusable and silently breaks
 * every login. */
bool blockpage_tls_active(const blockpage_ctx_t *bp);

/*
 * Transport for the connection THIS THREAD is serving. The server is
 * thread-per-connection, so the TLS association can live in thread-local
 * storage and every existing `int fd` signature stays as it is -- the
 * alternative was threading an SSL* through some two hundred call sites in
 * webui.c, which would have been a far larger change with far more places
 * to get it wrong.
 */
ssize_t bp_write(int fd, const void *buf, size_t len);
ssize_t bp_read(int fd, void *buf, size_t len);

/* Send a complete small response. Exposed for route handlers. */
void blockpage_send(int fd, const char *status, const char *ctype,
                    const char *body, size_t len);

/* As above, with extra response headers. `extra` must be a sequence of
 * complete "Name: value\r\n" lines (Set-Cookie, for instance). */
void blockpage_send_ex(int fd, const char *status, const char *ctype,
                       const char *extra, const char *body, size_t len);

int  blockpage_start(blockpage_ctx_t *bp);
void blockpage_stop(blockpage_ctx_t *bp);
const char *blockpage_reason_title(block_reason_t r);

/* Record a block and get back the request-id to surface to the user.
 * The returned pointer is into the ring buffer: copy it if you keep it. */
const char *blockpage_record(blockpage_ctx_t *bp, uint32_t client_ip,
                             uint16_t vlan_id, const char *vlan_name,
                             const char *zone, const char *host,
                             block_reason_t reason, const char *policy_id,
                             const char *detail, int severity);

/* Inject an HTTP 302 toward the portal, then close the flow. */
int  blockpage_inject_redirect(uint32_t client_ip, uint16_t client_port,
                               uint32_t server_ip, uint16_t server_port,
                               uint32_t seq, uint32_t ack,
                               const char *portal_ip, const char *request_id);

/* Install transparent interception rules for quarantined clients. */
int  blockpage_install_intercept(const char *portal_ip, int port);

#endif
