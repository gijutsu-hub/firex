/*
 * Captive portal: sessions, vouchers, RADIUS and the firewall state that
 * backs them. See include/portal.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/evp.h>

#include "portal.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

const char *portal_auth_name(portal_auth_t a) {
    switch (a) {
        case PORTAL_AUTH_VOUCHER: return "voucher";
        case PORTAL_AUTH_RADIUS:  return "radius";
        default:                  return "click";
    }
}

portal_auth_t portal_auth_from(const char *s) {
    if (!s) return PORTAL_AUTH_CLICK;
    if (!strcasecmp(s, "voucher")) return PORTAL_AUTH_VOUCHER;
    if (!strcasecmp(s, "radius"))  return PORTAL_AUTH_RADIUS;
    return PORTAL_AUTH_CLICK;
}

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

static void md5(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                uint8_t out[16]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int len = 16;
    EVP_DigestInit_ex(c, EVP_md5(), NULL);
    if (a && alen) EVP_DigestUpdate(c, a, alen);
    if (b && blen) EVP_DigestUpdate(c, b, blen);
    EVP_DigestFinal_ex(c, out, &len);
    EVP_MD_CTX_free(c);
}

/* Timing-independent comparison, used on the response authenticator. */
static bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* ═══════════════════ RADIUS ═══════════════════ */

static size_t put_attr(uint8_t *p, uint8_t type, const void *val, size_t len) {
    p[0] = type;
    p[1] = (uint8_t)(len + 2);
    memcpy(p + 2, val, len);
    return len + 2;
}

int radius_build_request(uint8_t *out, size_t outlen, uint8_t id,
                         const uint8_t authenticator[RADIUS_AUTH_LEN],
                         const char *user, const char *pass,
                         const char *secret, uint32_t nas_ip,
                         const char *nas_id) {
    if (!out || !authenticator || !user || !pass || !secret) return -1;

    size_t ulen = strlen(user), plen = strlen(pass), slen = strlen(secret);
    if (!ulen || ulen > 253 || plen > 128 || !slen) return -1;

    /* The password is padded to a multiple of 16 before encryption. */
    size_t padded = ((plen + 15) / 16) * 16;
    if (padded == 0) padded = 16;
    if (outlen < RADIUS_HDR_LEN + 2 + ulen + 2 + padded + 64) return -1;

    size_t off = RADIUS_HDR_LEN;
    off += put_attr(out + off, 1, user, ulen);          /* User-Name */

    /*
     * RFC 2865 section 5.2: the password is XORed with a chain of MD5
     * digests, each seeded by the previous ciphertext block. The shared
     * secret never goes on the wire.
     */
    uint8_t plain[128 + 16];
    memset(plain, 0, sizeof(plain));
    memcpy(plain, pass, plen);

    uint8_t cipher[128 + 16];
    uint8_t digest[16];
    const uint8_t *prev = authenticator;

    for (size_t blk = 0; blk < padded; blk += 16) {
        md5((const uint8_t *)secret, slen, prev, RADIUS_AUTH_LEN, digest);
        for (int i = 0; i < 16; i++)
            cipher[blk + i] = (uint8_t)(plain[blk + i] ^ digest[i]);
        prev = cipher + blk;
    }
    off += put_attr(out + off, 2, cipher, padded);      /* User-Password */

    uint32_t nip = nas_ip;
    off += put_attr(out + off, 4, &nip, 4);             /* NAS-IP-Address */

    if (nas_id && *nas_id) {
        size_t nlen = strlen(nas_id);
        if (nlen > 253) nlen = 253;
        off += put_attr(out + off, 32, nas_id, nlen);   /* NAS-Identifier */
    }

    uint32_t port_type = htonl(19);                     /* Wireless-802.11 */
    off += put_attr(out + off, 61, &port_type, 4);      /* NAS-Port-Type */

    out[0] = RADIUS_ACCESS_REQUEST;
    out[1] = id;
    out[2] = (uint8_t)((off >> 8) & 0xff);
    out[3] = (uint8_t)(off & 0xff);
    memcpy(out + 4, authenticator, RADIUS_AUTH_LEN);

    explicit_bzero(plain, sizeof(plain));
    return (int)off;
}

int radius_verify_response(const uint8_t *resp, size_t resplen,
                           const uint8_t req_auth[RADIUS_AUTH_LEN],
                           const char *secret) {
    if (!resp || !req_auth || !secret) return -1;
    if (resplen < RADIUS_HDR_LEN || resplen > RADIUS_MAX_PACKET) return -1;

    size_t declared = ((size_t)resp[2] << 8) | resp[3];
    if (declared != resplen || declared < RADIUS_HDR_LEN) return -1;

    /*
     * ResponseAuth = MD5(Code | ID | Length | RequestAuth | Attributes |
     * Secret). Without this check a forged UDP packet from anywhere would be
     * accepted as an Access-Accept.
     */
    uint8_t recomputed[RADIUS_HDR_LEN + RADIUS_MAX_PACKET];
    memcpy(recomputed, resp, RADIUS_HDR_LEN);
    memcpy(recomputed + 4, req_auth, RADIUS_AUTH_LEN);
    if (resplen > RADIUS_HDR_LEN)
        memcpy(recomputed + RADIUS_HDR_LEN, resp + RADIUS_HDR_LEN,
               resplen - RADIUS_HDR_LEN);

    size_t slen = strlen(secret);
    memcpy(recomputed + resplen, secret, slen);

    uint8_t want[16];
    md5(recomputed, resplen + slen, NULL, 0, want);

    if (!ct_eq(want, resp + 4, RADIUS_AUTH_LEN)) return -1;
    return resp[0];
}

int radius_authenticate(const portal_cfg_t *cfg, const char *user,
                        const char *pass, uint32_t nas_ip,
                        char *why, size_t whylen) {
    if (!cfg || !cfg->radius_host[0] || !cfg->radius_secret[0]) {
        if (why) snprintf(why, whylen, "no RADIUS server is configured");
        return -1;
    }

    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u",
             cfg->radius_port ? cfg->radius_port : 1812);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(cfg->radius_host, portstr, &hints, &res) != 0 || !res) {
        if (why) snprintf(why, whylen, "cannot resolve the RADIUS server");
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        freeaddrinfo(res);
        if (why) snprintf(why, whylen, "no socket for RADIUS");
        return -1;
    }

    uint8_t auth[RADIUS_AUTH_LEN];
    uint8_t id;
    if (!random_bytes(auth, sizeof(auth)) || !random_bytes(&id, 1)) {
        close(fd);
        freeaddrinfo(res);
        if (why) snprintf(why, whylen, "no entropy for a RADIUS request");
        return -1;
    }

    uint8_t req[RADIUS_MAX_PACKET];
    int reqlen = radius_build_request(req, sizeof(req), id, auth, user, pass,
                                      cfg->radius_secret, nas_ip, cfg->nas_id);
    if (reqlen < 0) {
        close(fd);
        freeaddrinfo(res);
        if (why) snprintf(why, whylen, "could not build the RADIUS request");
        return -1;
    }

    int timeout = cfg->radius_timeout_ms > 0 ? cfg->radius_timeout_ms : 3000;
    int tries   = cfg->radius_retries > 0 ? cfg->radius_retries : 2;
    int code = -1;

    for (int attempt = 0; attempt < tries && code < 0; attempt++) {
        if (sendto(fd, req, (size_t)reqlen, 0,
                   res->ai_addr, res->ai_addrlen) != reqlen) continue;

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, timeout) <= 0) continue;

        uint8_t resp[RADIUS_MAX_PACKET];
        ssize_t n = recv(fd, resp, sizeof(resp), 0);
        if (n < RADIUS_HDR_LEN) continue;

        /* A reply for a different request is not ours. */
        if (resp[1] != id) continue;

        int verified = radius_verify_response(resp, (size_t)n, auth,
                                              cfg->radius_secret);
        if (verified < 0) {
            if (why) snprintf(why, whylen,
                "the RADIUS reply failed its signature check; the shared "
                "secret is wrong, or the reply was forged");
            break;
        }
        code = verified;
    }

    close(fd);
    freeaddrinfo(res);
    explicit_bzero(req, sizeof(req));

    if (code < 0 && why && !*why)
        snprintf(why, whylen, "the RADIUS server did not answer");
    return code;
}

/* ═══════════════════ sessions ═══════════════════ */

int portal_init(portal_ctx_t *p, const portal_cfg_t *cfg, bool apply_net) {
    memset(p, 0, sizeof(*p));
    pthread_mutex_init(&p->lock, NULL);
    p->apply_net = apply_net;
    if (cfg) p->cfg = *cfg;

    if (!p->cfg.session_minutes)   p->cfg.session_minutes = 240;
    if (!p->cfg.idle_minutes)      p->cfg.idle_minutes = 30;
    if (!p->cfg.radius_port)       p->cfg.radius_port = 1812;
    if (!p->cfg.radius_timeout_ms) p->cfg.radius_timeout_ms = 3000;
    if (!p->cfg.radius_retries)    p->cfg.radius_retries = 2;
    if (!p->cfg.nas_id[0])
        snprintf(p->cfg.nas_id, PORTAL_USER_LEN, "%s", BRAND_PRODUCT);
    return 0;
}

/* Adds or removes an address from the authenticated set. The set carries a
 * timeout of its own so a crash cannot leave a client authorised forever. */
static void set_allow(portal_ctx_t *p, uint32_t ip, int seconds) {
    if (!p->apply_net) return;
    char cmd[256], abuf[INET_ADDRSTRLEN];
    snprintf(cmd, sizeof(cmd), "ipset add %s %s timeout %d -exist 2>/dev/null",
             PORTAL_AUTH_SET, fx_ip_str(ip, abuf, sizeof(abuf)), seconds);
    fx_try(cmd);
}

static void set_deny(portal_ctx_t *p, uint32_t ip) {
    if (!p->apply_net) return;
    char cmd[256], abuf[INET_ADDRSTRLEN];
    snprintf(cmd, sizeof(cmd), "ipset del %s %s 2>/dev/null",
             PORTAL_AUTH_SET, fx_ip_str(ip, abuf, sizeof(abuf)));
    fx_try(cmd);
}

static portal_session_t *find_session_locked(portal_ctx_t *p, uint32_t ip) {
    for (int i = 0; i < PORTAL_MAX_SESSIONS; i++)
        if (p->sessions[i].used && p->sessions[i].ip == ip)
            return &p->sessions[i];
    return NULL;
}

/* ── vouchers ── */

static portal_voucher_t *find_voucher_locked(portal_ctx_t *p, const char *code) {
    for (int i = 0; i < p->voucher_count; i++)
        if (!strcasecmp(p->vouchers[i].code, code)) return &p->vouchers[i];
    return NULL;
}

int portal_generate_vouchers(portal_ctx_t *p, int count, int minutes,
                             const char *note) {
    if (count <= 0 || minutes <= 0) return -1;

    /* No vowels and no look-alike glyphs: these get read off a printed slip
     * and typed by someone who is already annoyed. */
    static const char A[] = "BCDFGHJKLMNPQRSTVWXYZ23456789";

    pthread_mutex_lock(&p->lock);
    int made = 0;
    for (int i = 0; i < count && p->voucher_count < PORTAL_MAX_VOUCHERS; i++) {
        unsigned char raw[10];
        if (!random_bytes(raw, sizeof(raw))) break;

        portal_voucher_t *v = &p->vouchers[p->voucher_count];
        memset(v, 0, sizeof(*v));
        int o = 0;
        for (int j = 0; j < 10; j++) {
            if (j == 5) v->code[o++] = '-';
            v->code[o++] = A[raw[j] % (sizeof(A) - 1)];
        }
        v->code[o] = '\0';
        v->minutes = minutes;
        v->created = time(NULL);
        v->enabled = true;
        if (note) snprintf(v->note, sizeof(v->note), "%s", note);

        p->voucher_count++;
        made++;
    }
    pthread_mutex_unlock(&p->lock);
    return made;
}

int portal_voucher_snapshot(portal_ctx_t *p, portal_voucher_t *out, int max) {
    pthread_mutex_lock(&p->lock);
    int n = p->voucher_count < max ? p->voucher_count : max;
    for (int i = 0; i < n; i++) out[i] = p->vouchers[i];
    pthread_mutex_unlock(&p->lock);
    return n;
}

int portal_revoke_voucher(portal_ctx_t *p, const char *code) {
    pthread_mutex_lock(&p->lock);
    portal_voucher_t *v = find_voucher_locked(p, code);
    if (!v) { pthread_mutex_unlock(&p->lock); return -1; }
    v->enabled = false;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

/* ── login ── */

int portal_login(portal_ctx_t *p, uint32_t ip, uint16_t vlan_id,
                 const char *user, const char *pass, const char *voucher,
                 char *why, size_t whylen) {
    if (why && whylen) why[0] = '\0';
    if (!p->cfg.enabled) {
        if (why) snprintf(why, whylen, "the portal is not enabled");
        return -1;
    }

    char who[PORTAL_USER_LEN] = "";
    char used_code[PORTAL_CODE_LEN] = "";
    int minutes = p->cfg.session_minutes;

    switch (p->cfg.auth) {
    case PORTAL_AUTH_VOUCHER: {
        if (!voucher || !*voucher) {
            if (why) snprintf(why, whylen, "a voucher code is required");
            p->logins_failed++;
            return -1;
        }
        pthread_mutex_lock(&p->lock);
        portal_voucher_t *v = find_voucher_locked(p, voucher);
        if (!v || !v->enabled) {
            pthread_mutex_unlock(&p->lock);
            if (why) snprintf(why, whylen, "that code is not valid");
            p->logins_failed++;
            return -1;
        }
        if (v->used && v->first_used &&
            time(NULL) > v->first_used + (time_t)v->minutes * 60) {
            pthread_mutex_unlock(&p->lock);
            if (why) snprintf(why, whylen, "that code has expired");
            p->logins_failed++;
            return -1;
        }
        if (!v->first_used) { v->first_used = time(NULL); v->used = true; }

        /* A voucher's remaining time, not a fresh full session: the clock
         * starts when it is first redeemed. */
        int left = v->minutes - (int)((time(NULL) - v->first_used) / 60);
        if (left < 1) left = 1;
        if (left < minutes) minutes = left;
        snprintf(used_code, PORTAL_CODE_LEN, "%s", v->code);
        snprintf(who, PORTAL_USER_LEN, "voucher %s", v->code);
        pthread_mutex_unlock(&p->lock);
        break;
    }
    case PORTAL_AUTH_RADIUS: {
        if (!user || !*user || !pass) {
            if (why) snprintf(why, whylen, "a username and password are required");
            p->logins_failed++;
            return -1;
        }
        char rwhy[160] = "";
        int code = radius_authenticate(&p->cfg, user, pass, ip,
                                       rwhy, sizeof(rwhy));
        if (code != RADIUS_ACCESS_ACCEPT) {
            if (why)
                snprintf(why, whylen, "%s",
                         code == RADIUS_ACCESS_REJECT
                           ? "those credentials were refused"
                           : (rwhy[0] ? rwhy : "authentication failed"));
            p->logins_failed++;
            return -1;
        }
        snprintf(who, PORTAL_USER_LEN, "%s", user);
        break;
    }
    default:
        snprintf(who, PORTAL_USER_LEN, "guest");
        break;
    }

    time_t now = time(NULL);

    pthread_mutex_lock(&p->lock);
    portal_session_t *s = find_session_locked(p, ip);
    if (!s)
        for (int i = 0; i < PORTAL_MAX_SESSIONS; i++)
            if (!p->sessions[i].used) { s = &p->sessions[i]; break; }

    if (!s) {
        pthread_mutex_unlock(&p->lock);
        if (why) snprintf(why, whylen, "the portal is at capacity");
        return -2;
    }

    memset(s, 0, sizeof(*s));
    s->ip        = ip;
    s->vlan_id   = vlan_id;
    s->started   = now;
    s->last_seen = now;
    s->expires   = now + (time_t)minutes * 60;
    s->used      = true;
    snprintf(s->user, PORTAL_USER_LEN, "%s", who);
    snprintf(s->voucher, PORTAL_CODE_LEN, "%s", used_code);
    p->logins_ok++;
    pthread_mutex_unlock(&p->lock);

    set_allow(p, ip, minutes * 60);

    char abuf[INET_ADDRSTRLEN];
    printf("[%s] portal: %s authorised on VLAN %u for %d minute(s) (%s)\n",
           BRAND_PRODUCT, fx_ip_str(ip, abuf, sizeof(abuf)), vlan_id,
           minutes, who);
    return 0;
}

void portal_logout(portal_ctx_t *p, uint32_t ip) {
    pthread_mutex_lock(&p->lock);
    portal_session_t *s = find_session_locked(p, ip);
    if (s) memset(s, 0, sizeof(*s));
    pthread_mutex_unlock(&p->lock);
    set_deny(p, ip);
}

bool portal_session(portal_ctx_t *p, uint32_t ip, portal_session_t *out) {
    time_t now = time(NULL);

    pthread_mutex_lock(&p->lock);
    portal_session_t *s = find_session_locked(p, ip);
    if (!s || now >= s->expires) {
        pthread_mutex_unlock(&p->lock);
        return false;
    }
    s->last_seen = now;
    if (out) *out = *s;
    pthread_mutex_unlock(&p->lock);
    return true;
}

int portal_reap(portal_ctx_t *p, time_t now) {
    int gone = 0;
    uint32_t dropped[PORTAL_MAX_SESSIONS];
    int ndrop = 0;

    pthread_mutex_lock(&p->lock);
    for (int i = 0; i < PORTAL_MAX_SESSIONS; i++) {
        portal_session_t *s = &p->sessions[i];
        if (!s->used) continue;

        bool over_age  = now >= s->expires;
        bool idle_out  = p->cfg.idle_minutes > 0 &&
                         now - s->last_seen >= (time_t)p->cfg.idle_minutes * 60;
        if (!over_age && !idle_out) continue;

        if (ndrop < PORTAL_MAX_SESSIONS) dropped[ndrop++] = s->ip;
        memset(s, 0, sizeof(*s));
        p->expired++;
        gone++;
    }
    pthread_mutex_unlock(&p->lock);

    /* The ipset call shells out, so it happens outside the lock. */
    for (int i = 0; i < ndrop; i++) set_deny(p, dropped[i]);
    return gone;
}

int portal_snapshot(portal_ctx_t *p, portal_session_t *out, int max) {
    pthread_mutex_lock(&p->lock);
    int n = 0;
    for (int i = 0; i < PORTAL_MAX_SESSIONS && n < max; i++)
        if (p->sessions[i].used) out[n++] = p->sessions[i];
    pthread_mutex_unlock(&p->lock);
    return n;
}

static void *reaper_thread(void *arg) {
    portal_ctx_t *p = arg;
    while (p->running) {
        portal_reap(p, time(NULL));
        for (int i = 0; i < 100 && p->running; i++) {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

int portal_start(portal_ctx_t *p) {
    if (!p->cfg.enabled) return 0;

    p->running = true;
    if (pthread_create(&p->reaper, NULL, reaper_thread, p) != 0) {
        p->running = false;
        fprintf(stderr, "[%s] could not start the portal reaper\n", BRAND_PRODUCT);
        return -1;
    }
    printf("[%s] Captive portal: %s auth, %d min session, %d min idle\n",
           BRAND_PRODUCT, portal_auth_name(p->cfg.auth),
           p->cfg.session_minutes, p->cfg.idle_minutes);
    return 0;
}

void portal_stop(portal_ctx_t *p) {
    if (!p->running) return;
    p->running = false;
    pthread_join(p->reaper, NULL);
}

void portal_shutdown(portal_ctx_t *p) {
    if (!p) return;
    portal_stop(p);
    explicit_bzero(p->cfg.radius_secret, sizeof(p->cfg.radius_secret));
    pthread_mutex_destroy(&p->lock);
}

/* ═══════════════════ firewall state ═══════════════════ */

int portal_install_rules(portal_ctx_t *p, vlan_ctx_t *v, const char *portal_ip,
                         int portal_port) {
    if (!p->cfg.enabled || !p->apply_net) return 0;

    struct in_addr probe;
    if (!portal_ip || inet_pton(AF_INET, portal_ip, &probe) != 1) {
        fprintf(stderr, "[%s] portal address '%s' is not an IPv4 address\n",
                BRAND_PRODUCT, portal_ip ? portal_ip : "(null)");
        return -1;
    }

    char cmd[512], sbuf[INET_ADDRSTRLEN];

    /* The set carries its own timeout so a crash cannot leave a client
     * authorised indefinitely. */
    snprintf(cmd, sizeof(cmd),
             "ipset create %s hash:ip timeout %d 2>/dev/null",
             PORTAL_AUTH_SET, p->cfg.session_minutes * 60);
    fx_try(cmd);

    fx_try("iptables -t nat -N FIREX_PORTAL 2>/dev/null");
    fx_run("iptables -t nat -F FIREX_PORTAL");
    fx_try("iptables -t nat -D PREROUTING -j FIREX_PORTAL 2>/dev/null");
    fx_run("iptables -t nat -A PREROUTING -j FIREX_PORTAL");

    fx_try("iptables -N FIREX_PORTAL_FWD 2>/dev/null");
    fx_run("iptables -F FIREX_PORTAL_FWD");
    fx_try("iptables -D FORWARD -j FIREX_PORTAL_FWD 2>/dev/null");
    fx_run("iptables -I FORWARD 1 -j FIREX_PORTAL_FWD");

    int armed = 0;
    for (int i = 0; i < v->vlan_count; i++) {
        vlan_config_t *c = &v->vlans[i];
        if (!c->enabled || !c->captive_portal || !c->subnet) continue;

        fx_ip_str(c->subnet, sbuf, sizeof(sbuf));
        int bits = fx_netmask_to_cidr(c->netmask);

        /*
         * Everything on a captive segment is redirected unless its address
         * is in the authenticated set. Matching on absence rather than
         * presence means a bug in the session code fails closed.
         */
        snprintf(cmd, sizeof(cmd),
            "iptables -t nat -A FIREX_PORTAL -s %s/%d "
            "-m set ! --match-set %s src -p tcp --dport 80 "
            "-j DNAT --to-destination %s:%d",
            sbuf, bits, PORTAL_AUTH_SET, portal_ip, portal_port);
        fx_run(cmd);

        /* DNS has to resolve for the browser to make its probe at all. */
        snprintf(cmd, sizeof(cmd),
            "iptables -t nat -A FIREX_PORTAL -s %s/%d "
            "-m set ! --match-set %s src -p udp --dport 53 "
            "-j DNAT --to-destination %s:53",
            sbuf, bits, PORTAL_AUTH_SET, portal_ip);
        fx_try(cmd);

        /*
         * HTTPS cannot be redirected without terminating TLS and presenting
         * a certificate the client has no reason to trust. Reject instead,
         * so the browser gives up at once and falls back to the plain-HTTP
         * probe that triggers its captive-portal detector.
         */
        snprintf(cmd, sizeof(cmd),
            "iptables -A FIREX_PORTAL_FWD -s %s/%d "
            "-m set ! --match-set %s src -p tcp --dport 443 "
            "-j REJECT --reject-with tcp-reset",
            sbuf, bits, PORTAL_AUTH_SET);
        fx_run(cmd);

        /* Anything else from an unauthenticated client is simply dropped. */
        snprintf(cmd, sizeof(cmd),
            "iptables -A FIREX_PORTAL_FWD -s %s/%d "
            "-m set ! --match-set %s src -j DROP",
            sbuf, bits, PORTAL_AUTH_SET);
        fx_run(cmd);

        printf("  [PORTAL] VLAN %u (%s) %s/%d is captive\n",
               c->vlan_id, c->name, sbuf, bits);
        armed++;
    }

    if (!armed)
        printf("[%s] portal enabled but no VLAN has captive_portal set\n",
               BRAND_PRODUCT);
    return armed;
}

int portal_teardown_rules(portal_ctx_t *p) {
    if (!p->apply_net) return 0;
    fx_try("iptables -t nat -D PREROUTING -j FIREX_PORTAL 2>/dev/null");
    fx_try("iptables -t nat -F FIREX_PORTAL 2>/dev/null");
    fx_try("iptables -t nat -X FIREX_PORTAL 2>/dev/null");
    fx_try("iptables -D FORWARD -j FIREX_PORTAL_FWD 2>/dev/null");
    fx_try("iptables -F FIREX_PORTAL_FWD 2>/dev/null");
    fx_try("iptables -X FIREX_PORTAL_FWD 2>/dev/null");
    return 0;
}

/* ═══════════════════ the pages a client sees ═══════════════════ */

/* Everything interpolated below can come from a client -- the message is
 * built from a failed login, the redirect from the original request -- so it
 * is escaped on the way in. */
static void esc_html(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)(in ? in : ""); *p; p++) {
        const char *rep = NULL;
        switch (*p) {
            case '<':  rep = "&lt;";   break;
            case '>':  rep = "&gt;";   break;
            case '&':  rep = "&amp;";  break;
            case '"':  rep = "&quot;"; break;
            case '\'': rep = "&#39;";  break;
            default: break;
        }
        if (rep) {
            size_t rl = strlen(rep);
            if (o + rl >= outlen - 1) break;
            memcpy(out + o, rep, rl);
            o += rl;
        } else {
            if (o + 1 >= outlen - 1) break;
            out[o++] = (char)*p;
        }
    }
    out[o] = '\0';
}

#define PORTAL_CSS \
    "*{box-sizing:border-box;margin:0;padding:0}" \
    "body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;" \
    "background:" BRAND_COLOR_DARK ";color:" BRAND_COLOR_TEXT ";" \
    "min-height:100vh;display:flex;align-items:center;justify-content:center;" \
    "padding:24px}" \
    ".card{width:100%;max-width:420px;background:" BRAND_COLOR_PANEL ";" \
    "border:1px solid " "#1F2733" ";border-radius:16px;padding:32px}" \
    ".brand{display:flex;align-items:center;gap:12px;margin-bottom:24px}" \
    ".brand .logo{font-size:30px}" \
    ".brand .nm{font-size:19px;font-weight:800;letter-spacing:-.3px}" \
    ".brand .nm span{color:" BRAND_COLOR_PRIMARY "}" \
    ".brand .tag{font-size:9.5px;letter-spacing:2.2px;text-transform:uppercase;" \
    "color:" BRAND_COLOR_MUTED "}" \
    "h1{font-size:21px;margin-bottom:8px}" \
    "p.sub{color:" BRAND_COLOR_MUTED ";font-size:13.5px;margin-bottom:22px;" \
    "line-height:1.55}" \
    "label{display:block;font-size:11px;letter-spacing:.06em;" \
    "color:" BRAND_COLOR_MUTED ";text-transform:uppercase;margin-bottom:6px}" \
    "input{width:100%;font:inherit;font-size:14px;padding:11px 13px;" \
    "border-radius:9px;border:1px solid #2a3344;background:#0d121b;" \
    "color:" BRAND_COLOR_TEXT ";margin-bottom:16px}" \
    "input:focus{outline:none;border-color:" BRAND_COLOR_PRIMARY "}" \
    "button{width:100%;font:inherit;font-size:14px;font-weight:700;" \
    "padding:12px;border:none;border-radius:9px;cursor:pointer;color:#fff;" \
    "background:linear-gradient(135deg," BRAND_COLOR_PRIMARY "," \
    BRAND_COLOR_SECONDARY ")}" \
    ".err{background:#3A141F;border:1px solid " BRAND_COLOR_DANGER ";" \
    "color:" BRAND_COLOR_DANGER ";padding:11px 13px;border-radius:9px;" \
    "font-size:13px;margin-bottom:18px}" \
    ".terms{font-size:11.5px;color:" BRAND_COLOR_MUTED ";line-height:1.6;" \
    "background:#0d121b;border:1px solid " "#1F2733" ";" \
    "border-radius:9px;padding:13px;margin-bottom:18px;max-height:140px;" \
    "overflow-y:auto}" \
    ".ok-badge{display:inline-block;background:#0E2E22;color:" \
    BRAND_COLOR_SUCCESS ";border:1px solid #1d6b4f;border-radius:999px;" \
    "padding:5px 13px;font-size:11px;font-weight:800;letter-spacing:.09em;" \
    "margin-bottom:18px}" \
    "dl{font-size:13px;line-height:1.9}dt{color:" BRAND_COLOR_MUTED ";" \
    "font-size:11px;letter-spacing:.05em;text-transform:uppercase}" \
    "dd{margin-bottom:10px;font-family:ui-monospace,Menlo,monospace}" \
    "footer{margin-top:22px;padding-top:16px;border-top:1px solid " \
    "#1F2733" ";font-size:11px;color:" BRAND_COLOR_MUTED "}"

static const char *PORTAL_BRAND_BLOCK =
    "<div class=\"brand\"><span class=\"logo\">&#128737;</span><div>"
    "<div class=\"nm\">" BRAND_PRODUCT " by <span>" BRAND_VENDOR "</span></div>"
    "<div class=\"tag\">" BRAND_TAGLINE "</div></div></div>";

int portal_render_login(portal_ctx_t *p, char *out, size_t outlen,
                        const char *message, const char *redirect) {
    char msg[512], red[768], terms[PORTAL_TERMS_LEN * 2];
    esc_html(message,  msg,   sizeof(msg));
    esc_html(redirect, red,   sizeof(red));
    esc_html(p->cfg.terms, terms, sizeof(terms));

    const char *fields;
    switch (p->cfg.auth) {
        case PORTAL_AUTH_VOUCHER:
            fields = "<label for=\"voucher\">Access code</label>"
                     "<input id=\"voucher\" name=\"voucher\" autofocus required "
                     "autocomplete=\"off\" autocapitalize=\"characters\" "
                     "placeholder=\"XXXXX-XXXXX\">";
            break;
        case PORTAL_AUTH_RADIUS:
            fields = "<label for=\"username\">Username</label>"
                     "<input id=\"username\" name=\"username\" autofocus required "
                     "autocomplete=\"username\">"
                     "<label for=\"password\">Password</label>"
                     "<input id=\"password\" name=\"password\" type=\"password\" "
                     "required autocomplete=\"current-password\">";
            break;
        default:
            fields = "";
            break;
    }

    const char *blurb =
        p->cfg.auth == PORTAL_AUTH_VOUCHER
          ? "Enter the access code you were given to join this network."
        : p->cfg.auth == PORTAL_AUTH_RADIUS
          ? "Sign in with your organisation account to join this network."
          : "Review the terms below, then continue to join this network.";

    int n = snprintf(out, outlen,
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Connect &middot; %s</title><style>%s</style></head><body>"
        "<div class=\"card\">%s"
        "<h1>Connect to this network</h1>"
        "<p class=\"sub\">%s</p>"
        "%s%s%s"
        "%s%s%s"
        "<form method=\"POST\" action=\"/portal/login\">"
        "<input type=\"hidden\" name=\"redirect\" value=\"%s\">"
        "%s"
        "<button type=\"submit\">%s</button>"
        "</form>"
        "<footer>Access is provided by %s and is subject to its acceptable-use "
        "policy. Questions: %s</footer>"
        "</div></body></html>",
        BRAND_PRODUCT, PORTAL_CSS, PORTAL_BRAND_BLOCK, blurb,
        msg[0] ? "<div class=\"err\">" : "", msg, msg[0] ? "</div>" : "",
        terms[0] ? "<div class=\"terms\">" : "", terms,
        terms[0] ? "</div>" : "",
        red, fields,
        p->cfg.auth == PORTAL_AUTH_CLICK ? "Accept and connect" : "Connect",
        BRAND_VENDOR, BRAND_SUPPORT_EMAIL);

    return (n > 0 && (size_t)n < outlen) ? n : -1;
}

int portal_render_success(portal_ctx_t *p, const portal_session_t *s,
                          char *out, size_t outlen) {
    (void)p;
    char abuf[INET_ADDRSTRLEN], user[PORTAL_USER_LEN * 2];
    esc_html(s->user, user, sizeof(user));

    int mins = (int)((s->expires - time(NULL)) / 60);
    if (mins < 0) mins = 0;

    char until[64];
    struct tm tmv;
    localtime_r(&s->expires, &tmv);
    strftime(until, sizeof(until), "%H:%M", &tmv);

    int n = snprintf(out, outlen,
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Connected &middot; %s</title><style>%s</style></head><body>"
        "<div class=\"card\">%s"
        "<div class=\"ok-badge\">CONNECTED</div>"
        "<h1>You are online</h1>"
        "<p class=\"sub\">You can close this page and carry on browsing.</p>"
        "<dl>"
        "<dt>Signed in as</dt><dd>%s</dd>"
        "<dt>Your address</dt><dd>%s</dd>"
        "<dt>Session ends</dt><dd>%s &mdash; %d minute(s) from now</dd>"
        "</dl>"
        "<footer>Access is provided by %s. Questions: %s</footer>"
        "</div></body></html>",
        BRAND_PRODUCT, PORTAL_CSS, PORTAL_BRAND_BLOCK,
        user, fx_ip_str(s->ip, abuf, sizeof(abuf)), until, mins,
        BRAND_VENDOR, BRAND_SUPPORT_EMAIL);

    return (n > 0 && (size_t)n < outlen) ? n : -1;
}
