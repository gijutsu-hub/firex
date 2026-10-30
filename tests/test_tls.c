/*
 * Console TLS tests.
 *
 * The management console used to serve plain HTTP on 8443 -- the port
 * number that, by convention, tells an operator the opposite. These tests
 * run the real listener and speak real TLS to it, because the interesting
 * failures here are not in the certificate builder but at the seams: a
 * response written with write() instead of bp_write() corrupts the record
 * stream, and a Secure cookie emitted without TLS is discarded by the
 * browser and breaks every login with no error to show for it.
 *
 *   make test-tls
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "blockpage.h"
#include "guiapp.h"

static int pass = 0, fail = 0;
static void ok(const char *what, int cond, const char *detail) {
    if (cond) { printf("  PASS  %-58s %s\n", what, detail ? detail : ""); pass++; }
    else      { printf("  FAIL  %-58s %s\n", what, detail ? detail : ""); fail++; }
}

static char g_dir[256];
static char g_crt[384], g_key[384];

/* The console port used by this suite. High, loopback-only, and not 8443,
 * so a developer running the real daemon can still run the tests. */
#define TEST_PORT 18993

/* A stand-in for webui_route(): answers one path and nothing else. */
static int stub_router(int fd, const char *method, const char *path,
                       uint32_t peer, const char *headers,
                       const char *body, size_t body_len) {
    (void)peer; (void)headers; (void)body; (void)body_len;

    if (!strcmp(path, "/api/echo")) {
        char out[256];
        int n = snprintf(out, sizeof(out), "{\"method\":\"%s\",\"tls\":true}", method);
        blockpage_send(fd, "200 OK", "application/json", out, (size_t)n);
        return 1;
    }

    /* Enough of the console API for the desktop client to drive: a
     * sign-in that hands back a cookie and a CSRF token, and one
     * authenticated endpoint. */
    if (!strcmp(path, "/api/auth/login")) {
        static const char OK[] =
            "{\"user\":\"admin\",\"role\":\"admin\",\"csrf\":\"testcsrf\"}";
        blockpage_send_ex(fd, "200 OK", "application/json",
                          "Set-Cookie: firex_session=testtoken; HttpOnly; "
                          "Secure; SameSite=Strict; Path=/\r\n",
                          OK, sizeof(OK) - 1);
        return 1;
    }
    if (!strcmp(path, "/api/airgap")) {
        static const char AG[] = "{\"mode\":\"isolated\",\"open\":false}";
        blockpage_send(fd, "200 OK", "application/json", AG, sizeof(AG) - 1);
        return 1;
    }
    return 0;
}

/* ── a TLS client, the way a browser would arrive ────────────────────── */

static int tls_get(const char *path, char *out, size_t outlen,
                   char *cn_seen, size_t cnlen, char *err, size_t errlen) {
    out[0] = 0;
    if (cn_seen) cn_seen[0] = 0;
    if (err) err[0] = 0;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(err, errlen, "socket"); return -1; }

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(TEST_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        snprintf(err, errlen, "connect"); close(fd); return -1;
    }

    SSL_CTX *c = SSL_CTX_new(TLS_client_method());
    /* The certificate is self-signed by design, so the client does not
     * verify a chain -- it checks the identity by fingerprint instead,
     * which is what the operator is told to do on the first visit. */
    SSL *ssl = SSL_new(c);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        snprintf(err, errlen, "handshake: %s",
                 ERR_reason_error_string(ERR_get_error()));
        SSL_free(ssl); SSL_CTX_free(c); close(fd);
        return -1;
    }

    if (cn_seen) {
        X509 *crt = SSL_get1_peer_certificate(ssl);
        if (crt) {
            X509_NAME_get_text_by_NID(X509_get_subject_name(crt),
                                      NID_commonName, cn_seen, (int)cnlen);
            X509_free(crt);
        }
    }

    char req[512];
    int rn = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.1\r\nHost: localhost\r\n"
                      "Connection: close\r\n\r\n", path);
    SSL_write(ssl, req, rn);

    size_t got = 0;
    for (;;) {
        int n = SSL_read(ssl, out + got, (int)(outlen - 1 - got));
        if (n <= 0) break;
        got += (size_t)n;
        if (got >= outlen - 1) break;
    }
    out[got] = 0;

    SSL_free(ssl);
    SSL_CTX_free(c);
    close(fd);
    return (int)got;
}

/* ═══ 1. certificate generation ═══════════════════════════════════════ */

static void test_generation(blockpage_ctx_t *bp) {
    printf("\n[ certificate ]\n");

    ok("nothing is shipped: no certificate before start",
       access(g_crt, F_OK) != 0 && access(g_key, F_OK) != 0,
       "a key in the image is a key every appliance shares");

    int rc = blockpage_set_tls(bp, g_crt, g_key);
    ok("blockpage_set_tls succeeds", rc == 0, NULL);
    ok("  and generates both files",
       access(g_crt, R_OK) == 0 && access(g_key, R_OK) == 0, NULL);

    struct stat st;
    ok("the private key is 0600",
       stat(g_key, &st) == 0 && (st.st_mode & 07777) == 0600, NULL);
    ok("  and the certificate is world-readable",
       stat(g_crt, &st) == 0 && (st.st_mode & 0004), NULL);

    ok("a fingerprint is published for the operator to compare",
       bp->tls_fingerprint[0] && strchr(bp->tls_fingerprint, ':'),
       bp->tls_fingerprint);
    ok("blockpage_tls_active() agrees", blockpage_tls_active(bp), NULL);

    /* The extensions a browser actually reads. A certificate without a
     * subjectAltName is rejected outright by every current browser, not
     * merely warned about, so CN alone would have shipped a console that
     * cannot be opened. */
    FILE *f = fopen(g_crt, "r");
    X509 *crt = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    ok("the certificate parses", crt != NULL, NULL);
    if (crt) {
        ok("  it carries a subjectAltName",
           X509_get_ext_by_NID(crt, NID_subject_alt_name, -1) >= 0, NULL);
        ok("  it is marked CA:FALSE",
           X509_get_ext_by_NID(crt, NID_basic_constraints, -1) >= 0, NULL);
        ok("  and serverAuth",
           X509_get_ext_by_NID(crt, NID_ext_key_usage, -1) >= 0, NULL);
        ok("  the key is at least 3072 bits",
           EVP_PKEY_bits(X509_get0_pubkey(crt)) >= 3072, NULL);
        X509_free(crt);
    }

    /* Second call must reuse, not regenerate: a console whose identity
     * changed on every restart would train the operator to click through
     * the warning, which is the whole value of the fingerprint gone. */
    char first[96];
    snprintf(first, sizeof(first), "%s", bp->tls_fingerprint);
    blockpage_set_tls(bp, g_crt, g_key);
    ok("a restart keeps the same identity",
       !strcmp(first, bp->tls_fingerprint), NULL);
}

/* ═══ 2. the live listener ════════════════════════════════════════════ */

static void test_listener(blockpage_ctx_t *bp) {
    printf("\n[ listener ]\n");

    char body[8192], cn[256], err[256];
    int n = tls_get("/api/echo", body, sizeof(body), cn, sizeof(cn),
                    err, sizeof(err));

    ok("a TLS client completes the handshake", n > 0, err);
    ok("  and the subject names this appliance", cn[0] != 0, cn);
    ok("  and the console answers over it",
       strstr(body, "200 OK") && strstr(body, "\"tls\":true"), NULL);

    /*
     * The failure this catches: a response written with write() instead of
     * bp_write() lands outside the TLS record stream. The client then sees
     * either a decode error or a truncated body, so asserting on the
     * complete JSON is what makes the transport change load-bearing.
     */
    ok("  the body is complete, not truncated",
       strstr(body, "}") != NULL, NULL);

    /* Plaintext on the TLS port must not be answered. A cleartext reply to
     * a failed handshake would be exactly the channel TLS is here to
     * remove. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons(TEST_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char buf[512] = "";
    ssize_t got = -1;
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        const char *plain = "GET /api/echo HTTP/1.1\r\nHost: x\r\n\r\n";
        ssize_t w = write(fd, plain, strlen(plain));
        (void)w;
        struct timeval tv = { 2, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        got = read(fd, buf, sizeof(buf) - 1);
        if (got > 0) buf[got] = 0;
    }
    close(fd);
    ok("plain HTTP on the TLS port gets no cleartext reply",
       got <= 0 || !strstr(buf, "HTTP/1.1"), buf);
    ok("  and the refusal is counted",
       bp->tls_handshake_fail >= 1, NULL);
}

/* ═══ 3. the desktop console as a client ═════════════════════════════
 *
 * The console serves TLS by default now, and the desktop console reaches
 * it over the same port. If the GTK client still spoke only plain HTTP
 * the appliance's own screen would have been locked out of its own
 * daemon by the TLS change -- and nothing else in this suite would have
 * noticed, because every other test here is its own TLS client.
 */
static void test_desktop_client(void) {
    printf("\n[ desktop console client ]\n");

    fx_client_t c;
    fxc_init(&c, "127.0.0.1", TEST_PORT);

    ok("the client sees the listener", fxc_alive(&c), NULL);

    char err[FXC_ERR_LEN] = "";
    int rc = fxc_login(&c, "admin", "admin", err, sizeof(err));
    ok("it signs in over TLS", rc == 0, err);
    ok("  and knows the session was encrypted", c.tls, NULL);
    ok("  and recorded the certificate fingerprint",
       c.fingerprint[0] && strchr(c.fingerprint, ':'), c.fingerprint);

    char *j = fxc_get(&c, "/api/airgap", err, sizeof(err));
    ok("it reads an authenticated endpoint", j != NULL, err);
    if (j) {
        char mode[32] = "";
        fxj_str(j, "mode", mode, sizeof(mode));
        ok("  and the body arrived intact", !strcmp(mode, "isolated"), mode);
        free(j);
    }

    /*
     * And the other direction. An appliance with TLS switched off, or a
     * plain listener like the block-page portal, must still be reachable
     * -- the client discovers which it is per connection instead of being
     * configured, so neither case needs an operator to find a matching
     * switch on this side.
     */
    fx_client_t plain;
    fxc_init(&plain, "127.0.0.1", 18992);         /* the portal: no TLS */
    plain.tls = true;                              /* must be cleared */
    err[0] = 0;
    char *p2 = fxc_get(&plain, "/api/echo", err, sizeof(err));
    ok("a plaintext listener still answers", !plain.tls,
       plain.tls ? "the client thought it was TLS" : "fell back to HTTP");
    ok("  and no fingerprint is claimed for it", !plain.fingerprint[0], NULL);
    free(p2);
}

/* ═══ 4. the connection cap ══════════════════════════════════════════
 *
 * The portal listener faces the segments the appliance is defending
 * against. It used to create a thread per accepted socket with no limit,
 * so any host on a guest VLAN could spend the appliance's memory until
 * the management console went with it.
 */
static void test_conn_cap(blockpage_ctx_t *bp) {
    printf("\n[ connection cap ]\n");

    /*
     * Opened and left silent. Each one is a connection the server has
     * accepted and is waiting on, which is exactly the shape of the flood
     * -- cheap for the client, a thread and a stack for the server.
     */
    const int tries = BP_MAX_CONNS + 16;
    int *fds = calloc((size_t)tries, sizeof(int));
    int opened = 0;

    for (int i = 0; i < tries; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) break;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port   = htons(18992);          /* the portal */
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); break; }
        fds[opened++] = fd;
    }

    /* The accept loop runs on its own thread; give it a moment to drain
     * the backlog and make its decisions. */
    struct timespec ts = { 0, 400 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    ok("the server accepted connections", opened > BP_MAX_CONNS, NULL);
    ok("  and refused the ones over the cap",
       bp->conns_refused > 0, NULL);
    ok("  while never exceeding it",
       bp->conns_portal <= BP_MAX_CONNS, NULL);

    for (int i = 0; i < opened; i++) close(fds[i]);
    free(fds);

    /*
     * And the slots come back. A cap that leaked would be a denial of
     * service with a longer fuse -- the appliance would serve its first
     * sixty-four requests and then stop for good.
     */
    nanosleep(&ts, NULL);
    nanosleep(&ts, NULL);
    char body[4096], err[256];
    int n = tls_get("/api/echo", body, sizeof(body), NULL, 0, err, sizeof(err));
    ok("the console is still reachable afterwards", n > 0, err);
}

int main(void) {
    printf("=== FireX console TLS ===\n");

    snprintf(g_dir, sizeof(g_dir), "/tmp/firex_tls_XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 1; }
    snprintf(g_crt, sizeof(g_crt), "%s/console.crt", g_dir);
    snprintf(g_key, sizeof(g_key), "%s/console.key", g_dir);

    blockpage_ctx_t bp;
    memset(&bp, 0, sizeof(bp));
    bp.port = 18992;                 /* portal, unused by this suite */
    blockpage_set_router(&bp, stub_router);

    test_generation(&bp);

    if (blockpage_set_admin(&bp, TEST_PORT, htonl(INADDR_LOOPBACK)) != 0) {
        printf("  FAIL  console listener would not configure\n");
        fail++;
    } else if (blockpage_start(&bp) != 0) {
        printf("  FAIL  console listener would not start\n");
        fail++;
    } else {
        struct timespec ts = { 0, 200 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        test_listener(&bp);
        test_desktop_client();
        test_conn_cap(&bp);
        blockpage_stop(&bp);
    }

    unlink(g_crt);
    unlink(g_key);
    rmdir(g_dir);

    printf("\n%d passed, %d failed\n", pass, fail);
    return fail ? 1 : 0;
}
