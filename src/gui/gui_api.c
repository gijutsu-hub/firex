/*
 * Desktop console <-> daemon. See include/guiapp.h for why this is a
 * client rather than a second engine.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <sys/types.h>
#include <poll.h>

#include "guiapp.h"
#include "brand.h"

#define ERRF(e, n, ...) do { if (e) snprintf((e), (n), __VA_ARGS__); } while (0)

/* The console is on the appliance itself, so a round trip is microseconds.
 * Anything slower than this is a daemon that is wedged, and the GUI would
 * rather say so than freeze with it. */
#define FXC_TIMEOUT_MS 4000

void fxc_init(fx_client_t *c, const char *host, int port) {
    memset(c, 0, sizeof(*c));
    snprintf(c->host, sizeof(c->host), "%s", host && *host ? host : "127.0.0.1");
    c->port = port > 0 ? port : 8080;
}

/* ── transport ──────────────────────────────────────────────────────── */

static int dial(const fx_client_t *c, char *err, size_t errlen) {
    char port[16];
    snprintf(port, sizeof(port), "%d", c->port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(c->host, port, &hints, &res);
    if (gai != 0 || !res) {
        ERRF(err, errlen, "cannot resolve %s: %s", c->host, gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0) continue;

        /*
         * Non-blocking connect with a poll: a blocking one against a host
         * that is up but not listening can sit in SYN retries for a
         * minute, and this runs on the GTK main thread.
         */
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);

        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc == 0) { fcntl(fd, F_SETFL, fl); break; }

        if (errno == EINPROGRESS) {
            struct pollfd p = { .fd = fd, .events = POLLOUT };
            if (poll(&p, 1, FXC_TIMEOUT_MS) == 1) {
                int soerr = 0;
                socklen_t len = sizeof(soerr);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) == 0 &&
                    soerr == 0) {
                    fcntl(fd, F_SETFL, fl);
                    break;
                }
            }
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        ERRF(err, errlen, "%s is not answering on port %d", c->host, c->port);
    return fd;
}

/*
 * The console serves TLS by default, so this client has to speak it --
 * and has to keep working against an appliance configured without it,
 * and against the plain-HTTP block-page port.
 *
 * So: try the handshake, and treat a handshake failure as "this listener
 * is not TLS" rather than as an error. One probe, no configuration, and
 * an operator who switches TLS off does not then have to find a matching
 * switch here. Which way it went is recorded on the client so the sign-in
 * screen can say so, because "am I typing my password into a plaintext
 * socket" is a question the console should answer without being asked.
 */
typedef struct {
    int      fd;
    SSL     *ssl;
    SSL_CTX *ctx;
} fxc_conn_t;

static void conn_close(fxc_conn_t *k) {
    if (k->ssl) { SSL_shutdown(k->ssl); SSL_free(k->ssl); k->ssl = NULL; }
    if (k->ctx) { SSL_CTX_free(k->ctx); k->ctx = NULL; }
    if (k->fd >= 0) { close(k->fd); k->fd = -1; }
}

static bool conn_start_tls(fxc_conn_t *k, fx_client_t *c) {
    k->ctx = SSL_CTX_new(TLS_client_method());
    if (!k->ctx) return false;
    SSL_CTX_set_min_proto_version(k->ctx, TLS1_2_VERSION);

    /*
     * The appliance's certificate is self-signed on first boot by design
     * -- a certificate baked into the image would be one every appliance
     * shares. There is no chain to verify, so the identity is carried by
     * the fingerprint instead: it is recorded here and shown beside the
     * sign-in form, and the operator compares it once against the one the
     * daemon printed on the serial console.
     */
    k->ssl = SSL_new(k->ctx);
    if (!k->ssl) { SSL_CTX_free(k->ctx); k->ctx = NULL; return false; }
    SSL_set_fd(k->ssl, k->fd);
    SSL_set_tlsext_host_name(k->ssl, c->host);

    if (SSL_connect(k->ssl) != 1) {
        SSL_free(k->ssl);   k->ssl = NULL;
        SSL_CTX_free(k->ctx); k->ctx = NULL;
        return false;
    }

    X509 *crt = SSL_get1_peer_certificate(k->ssl);
    if (crt) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int n = 0;
        if (X509_digest(crt, EVP_sha256(), md, &n)) {
            size_t o = 0;
            for (unsigned int i = 0; i < n && o + 3 < sizeof(c->fingerprint); i++)
                o += (size_t)snprintf(c->fingerprint + o,
                                      sizeof(c->fingerprint) - o,
                                      "%s%02X", i ? ":" : "", md[i]);
        }
        X509_free(crt);
    }
    return true;
}

static bool conn_write(fxc_conn_t *k, const char *buf, size_t len) {
    if (!k->ssl) {
        size_t sent = 0;
        while (sent < len) {
            ssize_t w = write(k->fd, buf + sent, len - sent);
            if (w <= 0) { if (w < 0 && errno == EINTR) continue; return false; }
            sent += (size_t)w;
        }
        return true;
    }
    size_t sent = 0;
    while (sent < len) {
        int w = SSL_write(k->ssl, buf + sent, (int)(len - sent));
        if (w <= 0) return false;
        sent += (size_t)w;
    }
    return true;
}

/*
 * Reads to EOF. The daemon answers with Connection: close and a
 * Content-Length, so there is no keep-alive to unpick and no chunked
 * encoding to decode. The cap is a guard against a reply that never ends,
 * not a real limit -- the largest endpoint here is a few tens of KB.
 */
#define FXC_MAX_REPLY (4u * 1024 * 1024)

static char *read_all(fxc_conn_t *k, size_t *out_len, char *err, size_t errlen) {
    size_t cap = 16 * 1024, len = 0;
    char *buf = malloc(cap);
    if (!buf) { ERRF(err, errlen, "out of memory"); return NULL; }

    for (;;) {
        if (len + 4096 > cap) {
            if (cap >= FXC_MAX_REPLY) {
                ERRF(err, errlen, "the reply is implausibly large");
                free(buf);
                return NULL;
            }
            size_t ncap = cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) { ERRF(err, errlen, "out of memory"); free(buf); return NULL; }
            buf = nb;
            cap = ncap;
        }

        /*
         * Poll the socket, not the SSL object -- but only when OpenSSL
         * has nothing buffered already. A TLS record can carry more
         * application bytes than the last SSL_read returned, and those
         * bytes are inside OpenSSL, not in the kernel; polling for
         * readability then waits for traffic that has already arrived and
         * times out on a reply that is sitting complete in the buffer.
         */
        if (!k->ssl || !SSL_pending(k->ssl)) {
            struct pollfd p = { .fd = k->fd, .events = POLLIN };
            int pr = poll(&p, 1, FXC_TIMEOUT_MS);
            if (pr == 0) { ERRF(err, errlen, "the daemon stopped responding"); free(buf); return NULL; }
            if (pr < 0) { if (errno == EINTR) continue; ERRF(err, errlen, "poll: %s", strerror(errno)); free(buf); return NULL; }
        }

        ssize_t r;
        if (k->ssl) {
            int n = SSL_read(k->ssl, buf + len, (int)(cap - len - 1));
            if (n > 0) {
                r = n;
            } else {
                int e = SSL_get_error(k->ssl, n);
                /* A clean close and a peer that simply dropped the
                 * connection both mean "the body ended"; the daemon sends
                 * Connection: close, so this is the normal path. */
                if (e == SSL_ERROR_ZERO_RETURN || e == SSL_ERROR_SYSCALL) break;
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
                ERRF(err, errlen, "TLS read failed");
                free(buf);
                return NULL;
            }
        } else {
            r = read(k->fd, buf + len, cap - len - 1);
            if (r == 0) break;
            if (r < 0) {
                if (errno == EINTR) continue;
                ERRF(err, errlen, "read: %s", strerror(errno));
                free(buf);
                return NULL;
            }
        }
        len += (size_t)r;
    }

    buf[len] = '\0';
    if (out_len) *out_len = len;
    return buf;
}

/* Case-insensitive header lookup within the response head. */
static const char *header(const char *head, const char *name) {
    size_t n = strlen(name);
    for (const char *p = head; (p = strchr(p, '\n')); ) {
        p++;
        if (strncasecmp(p, name, n) == 0 && p[n] == ':') {
            p += n + 1;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
    }
    return NULL;
}

/*
 * One request, start to finish. `extra` carries per-request headers,
 * `body` is the JSON payload for a POST or NULL for a GET.
 */
static char *request(fx_client_t *c, const char *method, const char *path,
                     const char *body, char **out_head,
                     char *err, size_t errlen) {
    fxc_conn_t k = { .fd = dial(c, err, errlen), .ssl = NULL, .ctx = NULL };
    if (k.fd < 0) return NULL;

    /*
     * Probe for TLS on every request rather than remembering the answer.
     * The daemon can be restarted with TLS switched on or off underneath
     * a console that is already open, and a cached answer would then
     * either send cleartext into a TLS listener or a ClientHello into a
     * plain one -- both of which look like "the daemon stopped
     * responding" rather than like what they are.
     */
    c->tls = conn_start_tls(&k, c);
    if (!c->tls) {
        /*
         * The failed handshake left bytes in the socket and the peer's
         * idea of the connection is unusable, so the plaintext attempt
         * gets a new one.
         */
        close(k.fd);
        k.fd = dial(c, err, errlen);
        if (k.fd < 0) return NULL;
        c->fingerprint[0] = 0;
    }

    char req[2048];
    int n = snprintf(req, sizeof(req),
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s-console/%s\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n",
        method, path, c->host, c->port, BRAND_PRODUCT, BRAND_VERSION);

    if (c->token[0])
        n += snprintf(req + n, sizeof(req) - (size_t)n,
                      "Cookie: firex_session=%s\r\n", c->token);
    if (c->csrf[0] && strcmp(method, "GET") != 0)
        n += snprintf(req + n, sizeof(req) - (size_t)n,
                      "X-FireX-CSRF: %s\r\n", c->csrf);
    if (body)
        n += snprintf(req + n, sizeof(req) - (size_t)n,
                      "Content-Type: application/json\r\n"
                      "Content-Length: %zu\r\n", strlen(body));

    n += snprintf(req + n, sizeof(req) - (size_t)n, "\r\n");

    if (n <= 0 || (size_t)n >= sizeof(req)) {
        ERRF(err, errlen, "the request headers do not fit");
        conn_close(&k);
        return NULL;
    }

    if (!conn_write(&k, req, (size_t)n) ||
        (body && !conn_write(&k, body, strlen(body)))) {
        ERRF(err, errlen, "could not send the request");
        conn_close(&k);
        return NULL;
    }

    size_t len = 0;
    char *raw = read_all(&k, &len, err, errlen);
    conn_close(&k);
    if (!raw) return NULL;

    char *sep = strstr(raw, "\r\n\r\n");
    if (!sep) {
        ERRF(err, errlen, "the reply has no header separator");
        free(raw);
        return NULL;
    }
    *sep = '\0';
    char *payload = sep + 4;

    int status = 0;
    if (sscanf(raw, "HTTP/1.%*d %d", &status) != 1) status = 0;

    if (status != 200) {
        /* The API puts a sentence in {"error":"..."}; prefer it to a code. */
        char msg[256] = "";
        if (fxj_str(payload, "error", msg, sizeof(msg)) && msg[0])
            ERRF(err, errlen, "%s", msg);
        else
            ERRF(err, errlen, "the daemon answered %d", status);

        if (status == 401) c->connected = false;
        free(raw);
        return NULL;
    }

    char *copy = strdup(payload);
    if (out_head) *out_head = raw; else free(raw);
    if (!copy) ERRF(err, errlen, "out of memory");
    return copy;
}

bool fxc_alive(const fx_client_t *c) {
    int fd = dial(c, NULL, 0);
    if (fd < 0) return false;
    close(fd);
    return true;
}

int fxc_login(fx_client_t *c, const char *user, const char *pass,
              char *err, size_t errlen) {
    if (!user || !*user) { ERRF(err, errlen, "a user name is required"); return -1; }

    /*
     * The input is checked before anything is dialled. Neither field may
     * carry a quote or a backslash into the JSON this builds; the daemon
     * would reject the malformed request anyway, but a login box that
     * builds broken requests from ordinary input is its own bug.
     *
     * Order matters: doing the reachability check first meant these
     * refusals never fired on a machine with no daemon running, so what
     * the console said about a user name depended on whether something
     * happened to be listening.
     */
    for (const char *p = user; *p; p++)
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
            ERRF(err, errlen, "that user name has characters the console cannot send");
            return -1;
        }
    for (const char *p = pass; p && *p; p++)
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
            ERRF(err, errlen, "that password has characters the console cannot send");
            return -1;
        }

    /*
     * Asked before the attempt so the two failures read differently. "No
     * daemon" and "wrong password" are the same blank box otherwise, and
     * they want opposite things done about them.
     */
    if (!fxc_alive(c)) {
        ERRF(err, errlen,
             "%s is not running on %s:%d. Check: systemctl status %s",
             BRAND_DAEMON, c->host, c->port, BRAND_DAEMON);
        return -1;
    }

    char body[512];

    snprintf(body, sizeof(body),
             "{\"username\":\"%s\",\"password\":\"%s\"}", user, pass ? pass : "");

    char *head = NULL;
    char *reply = request(c, "POST", "/api/auth/login", body, &head, err, errlen);
    explicit_bzero(body, sizeof(body));

    if (!reply) { free(head); return -1; }

    /* The session itself is in the cookie, not the body. */
    const char *sc = head ? header(head, "Set-Cookie") : NULL;
    if (sc && strncmp(sc, "firex_session=", 14) == 0) {
        sc += 14;
        size_t i = 0;
        while (sc[i] && sc[i] != ';' && sc[i] != '\r' && sc[i] != '\n' &&
               i < sizeof(c->token) - 1) {
            c->token[i] = sc[i];
            i++;
        }
        c->token[i] = '\0';
    }

    fxj_str(reply, "csrf", c->csrf, sizeof(c->csrf));
    fxj_str(reply, "user", c->user, sizeof(c->user));
    fxj_str(reply, "role", c->role, sizeof(c->role));

    free(reply);
    free(head);

    if (!c->token[0] || !c->csrf[0]) {
        ERRF(err, errlen, "the daemon accepted the login but sent no session");
        return -1;
    }
    c->connected = true;
    return 0;
}

void fxc_logout(fx_client_t *c) {
    if (c->token[0]) {
        char e[FXC_ERR_LEN];
        char *r = request(c, "POST", "/api/auth/logout", "{}", NULL, e, sizeof(e));
        free(r);
    }
    explicit_bzero(c->token, sizeof(c->token));
    explicit_bzero(c->csrf, sizeof(c->csrf));
    c->connected = false;
}

char *fxc_get(fx_client_t *c, const char *path, char *err, size_t errlen) {
    return request(c, "GET", path, NULL, NULL, err, errlen);
}

char *fxc_post(fx_client_t *c, const char *path, const char *body,
               char *err, size_t errlen) {
    return request(c, "POST", path, body ? body : "{}", NULL, err, errlen);
}

/* ── the small JSON reader ──────────────────────────────────────────── */

/* Finds "key" used as a key -- i.e. followed by a colon -- and returns
 * the first character of its value. */
static const char *find_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    size_t klen = strlen(key);

    for (const char *p = json; (p = strchr(p, '"')); p++) {
        if (strncmp(p + 1, key, klen) != 0 || p[1 + klen] != '"') continue;
        const char *q = p + 2 + klen;
        while (*q == ' ' || *q == '\t' || *q == '\n') q++;
        if (*q != ':') continue;
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n') q++;
        return q;
    }
    return NULL;
}

bool fxj_str(const char *json, const char *key, char *out, size_t outlen) {
    if (!out || outlen == 0) return false;
    out[0] = '\0';

    const char *v = find_key(json, key);
    if (!v || *v != '"') return false;
    v++;

    size_t i = 0;
    while (*v && *v != '"' && i < outlen - 1) {
        if (*v == '\\' && v[1]) {
            v++;
            switch (*v) {
                case 'n': out[i++] = '\n'; break;
                case 't': out[i++] = '\t'; break;
                case 'r': out[i++] = '\r'; break;
                /* \uXXXX is passed through as the escape itself: the API
                 * only emits it for characters json_escape() would not
                 * pass, and mangling one is worse than showing it. */
                case 'u': out[i++] = '?';
                          if (v[1] && v[2] && v[3] && v[4]) v += 4;
                          break;
                default:  out[i++] = *v; break;
            }
            v++;
        } else {
            out[i++] = *v++;
        }
    }
    out[i] = '\0';
    return true;
}

bool fxj_num(const char *json, const char *key, double *out) {
    const char *v = find_key(json, key);
    if (!v) return false;

    if (!strncmp(v, "true", 4))  { if (out) *out = 1; return true; }
    if (!strncmp(v, "false", 5)) { if (out) *out = 0; return true; }
    if (!strncmp(v, "null", 4))  return false;

    char *end = NULL;
    double d = strtod(v, &end);
    if (end == v) return false;
    if (out) *out = d;
    return true;
}

const char *fxj_array(const char *json, const char *key) {
    const char *v = find_key(json, key);
    if (!v || *v != '[') return NULL;
    v++;
    while (*v == ' ' || *v == '\n' || *v == '\t') v++;
    return (*v == ']') ? NULL : v;
}

const char *fxj_next(const char *p) {
    if (!p) return NULL;

    int depth = 0;
    bool in_str = false;

    for (; *p; p++) {
        if (in_str) {
            if (*p == '\\' && p[1]) { p++; continue; }
            if (*p == '"') in_str = false;
            continue;
        }
        switch (*p) {
            case '"': in_str = true; break;
            case '{': case '[': depth++; break;
            case '}': depth--; break;
            case ']':
                if (depth == 0) return NULL;   /* end of our own array */
                depth--;
                break;
            case ',':
                if (depth == 0) {
                    p++;
                    while (*p == ' ' || *p == '\n' || *p == '\t') p++;
                    return *p ? p : NULL;
                }
                break;
            default: break;
        }
    }
    return NULL;
}

int fxj_count(const char *json, const char *key) {
    int n = 0;
    for (const char *p = fxj_array(json, key); p; p = fxj_next(p)) n++;
    return n;
}

/* ── interfaces ─────────────────────────────────────────────────────── */

int fx_ifinfo(fx_ifinfo_t *out, int max) {
    if (!out || max <= 0) return 0;

    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return 0;

    int n = 0;

    /*
     * Two passes. An interface with an address is the interesting case,
     * so those are listed first; a link that is up but unaddressed still
     * matters (it is usually the one somebody forgot to configure) and
     * goes after. Without the split, eth1 with no IP can push the LAN
     * address off a short list.
     */
    for (int pass = 0; pass < 2 && n < max; pass++) {
        for (struct ifaddrs *a = list; a && n < max; a = a->ifa_next) {
            if (!a->ifa_name) continue;

            bool has_v4 = a->ifa_addr && a->ifa_addr->sa_family == AF_INET;
            if (pass == 0 && !has_v4) continue;
            if (pass == 1 && has_v4)  continue;

            /* One row per interface, whichever pass claims it first. */
            bool seen = false;
            for (int i = 0; i < n; i++)
                if (!strcmp(out[i].name, a->ifa_name)) { seen = true; break; }
            if (seen) continue;

            fx_ifinfo_t *e = &out[n];
            memset(e, 0, sizeof(*e));
            snprintf(e->name, sizeof(e->name), "%s", a->ifa_name);
            e->up       = (a->ifa_flags & IFF_UP) && (a->ifa_flags & IFF_RUNNING);
            e->loopback = (a->ifa_flags & IFF_LOOPBACK) != 0;

            if (has_v4) {
                const struct sockaddr_in *s = (const struct sockaddr_in *)(void *)a->ifa_addr;
                inet_ntop(AF_INET, &s->sin_addr, e->addr, sizeof(e->addr));
                if (a->ifa_netmask) {
                    const struct sockaddr_in *m =
                        (const struct sockaddr_in *)(void *)a->ifa_netmask;
                    inet_ntop(AF_INET, &m->sin_addr, e->mask, sizeof(e->mask));
                }
            }
            n++;
        }
    }

    freeifaddrs(list);
    return n;
}

void fx_primary_address(char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    snprintf(out, outlen, "<appliance>");

    fx_ifinfo_t ifs[FX_IFINFO_MAX];
    int n = fx_ifinfo(ifs, FX_IFINFO_MAX);

    for (int i = 0; i < n; i++)
        if (!ifs[i].loopback && ifs[i].up && ifs[i].addr[0]) {
            snprintf(out, outlen, "%s", ifs[i].addr);
            return;
        }
    /* Nothing routable: an address that is merely configured still beats
     * telling the operator to browse to "<appliance>". */
    for (int i = 0; i < n; i++)
        if (!ifs[i].loopback && ifs[i].addr[0]) {
            snprintf(out, outlen, "%s", ifs[i].addr);
            return;
        }
}
