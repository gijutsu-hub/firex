/*
 * WireGuard and IPsec configuration. See include/vpn.h for the contract.
 *
 * Key generation goes through OpenSSL's X25519 implementation. Nothing
 * cryptographic is implemented here -- the only key handling in this file is
 * base64 and a fingerprint for display.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <openssl/evp.h>

#include "vpn.h"
#include "netutil.h"
#include "shellcmd.h"
#include "brand.h"

#define WG_KEY_RAW_LEN 32

const char *ike_version_str(ike_version_t v) { return v == IKE_V1 ? "ikev1" : "ikev2"; }

int vpn_init(vpn_ctx_t *v) {
    memset(v, 0, sizeof(*v));
    pthread_mutex_init(&v->lock, NULL);
    return 0;
}

void vpn_shutdown(vpn_ctx_t *v) {
    if (!v) return;
    /* Keys and PSKs live in this struct; do not leave them in freed memory. */
    explicit_bzero(v->wg,      sizeof(v->wg));
    explicit_bzero(v->peers,   sizeof(v->peers));
    explicit_bzero(v->tunnels, sizeof(v->tunnels));
    pthread_mutex_destroy(&v->lock);
}

/* ── keys ───────────────────────────────────────────────────────────── */

static int b64_encode(const unsigned char *raw, size_t n, char *out, size_t outlen) {
    /* 32 bytes -> 44 characters + NUL */
    if (outlen < 45) return -1;
    int w = EVP_EncodeBlock((unsigned char *)out, raw, (int)n);
    return (w == 44) ? 0 : -1;
}

static int b64_decode(const char *in, unsigned char *out, size_t outlen) {
    if (!in || strlen(in) != 44 || outlen < WG_KEY_RAW_LEN) return -1;

    /* EVP_DecodeBlock pads its output to a multiple of three, so a 44-char
     * input yields 33 bytes with one byte of padding to discard. */
    unsigned char buf[48];
    int w = EVP_DecodeBlock(buf, (const unsigned char *)in, 44);
    if (w != 33) return -1;
    memcpy(out, buf, WG_KEY_RAW_LEN);
    explicit_bzero(buf, sizeof(buf));
    return 0;
}

bool wg_key_valid(const char *b64) {
    if (!b64 || strlen(b64) != 44) return false;
    if (b64[43] != '=') return false;
    for (int i = 0; i < 43; i++) {
        char c = b64[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/'))
            return false;
    }
    unsigned char raw[WG_KEY_RAW_LEN];
    bool okdec = b64_decode(b64, raw, sizeof(raw)) == 0;
    explicit_bzero(raw, sizeof(raw));
    return okdec;
}

int wg_generate_keypair(char *priv_b64, char *pub_b64) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!k) {
        fprintf(stderr, "[%s] X25519 key generation failed\n", BRAND_PRODUCT);
        return -1;
    }

    unsigned char priv[WG_KEY_RAW_LEN], pub[WG_KEY_RAW_LEN];
    size_t pl = sizeof(priv), ql = sizeof(pub);
    int rc = -1;

    if (EVP_PKEY_get_raw_private_key(k, priv, &pl) == 1 && pl == WG_KEY_RAW_LEN &&
        EVP_PKEY_get_raw_public_key(k, pub, &ql) == 1 && ql == WG_KEY_RAW_LEN &&
        b64_encode(priv, pl, priv_b64, WG_KEY_B64_LEN) == 0 &&
        b64_encode(pub,  ql, pub_b64,  WG_KEY_B64_LEN) == 0)
        rc = 0;

    explicit_bzero(priv, sizeof(priv));
    explicit_bzero(pub,  sizeof(pub));
    EVP_PKEY_free(k);
    return rc;
}

int wg_public_from_private(const char *priv_b64, char *pub_b64) {
    unsigned char priv[WG_KEY_RAW_LEN], pub[WG_KEY_RAW_LEN];
    if (b64_decode(priv_b64, priv, sizeof(priv)) != 0) return -1;

    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                               priv, WG_KEY_RAW_LEN);
    explicit_bzero(priv, sizeof(priv));
    if (!k) return -1;

    size_t ql = sizeof(pub);
    int rc = -1;
    if (EVP_PKEY_get_raw_public_key(k, pub, &ql) == 1 && ql == WG_KEY_RAW_LEN)
        rc = b64_encode(pub, ql, pub_b64, WG_KEY_B64_LEN);

    explicit_bzero(pub, sizeof(pub));
    EVP_PKEY_free(k);
    return rc;
}

const char *wg_key_fingerprint(const char *b64, char *out, size_t len) {
    if (!b64 || !b64[0]) { snprintf(out, len, "(none)"); return out; }
    if (!wg_key_valid(b64)) { snprintf(out, len, "(invalid)"); return out; }

    unsigned char raw[WG_KEY_RAW_LEN], md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (b64_decode(b64, raw, sizeof(raw)) != 0 ||
        !EVP_Digest(raw, sizeof(raw), md, &mdlen, EVP_sha256(), NULL) ||
        mdlen < 4) {
        snprintf(out, len, "(unreadable)");
        explicit_bzero(raw, sizeof(raw));
        return out;
    }
    /* A public key is not secret, but a private key's fingerprint must not
     * narrow the search for it; four bytes of SHA-256 identifies without
     * revealing. */
    snprintf(out, len, "%02x%02x%02x%02x", md[0], md[1], md[2], md[3]);
    explicit_bzero(raw, sizeof(raw));
    return out;
}

/* ── tables ─────────────────────────────────────────────────────────── */

static wg_iface_t *find_wg_locked(vpn_ctx_t *v, const char *ifname) {
    if (!ifname || !*ifname) return NULL;
    for (int i = 0; i < v->wg_count; i++)
        if (!strcmp(v->wg[i].ifname, ifname)) return &v->wg[i];
    return NULL;
}

static wg_peer_t *find_peer_locked(vpn_ctx_t *v, const char *name) {
    if (!name || !*name) return NULL;
    for (int i = 0; i < v->peer_count; i++)
        if (!strcmp(v->peers[i].name, name)) return &v->peers[i];
    return NULL;
}

int vpn_add_wg(vpn_ctx_t *v, const wg_iface_t *i) {
    if (!i->ifname[0]) return -1;

    pthread_mutex_lock(&v->lock);
    if (v->wg_count >= MAX_WG_INTERFACES || find_wg_locked(v, i->ifname)) {
        pthread_mutex_unlock(&v->lock);
        return -1;
    }
    wg_iface_t *dst = &v->wg[v->wg_count];
    *dst = *i;
    if (dst->mtu <= 0)         dst->mtu = 1420;
    if (dst->listen_port == 0) dst->listen_port = 51820;

    /* The public key is never stored in the config file; derive it so the
     * console can show the peer what to trust. */
    if (dst->private_key[0] &&
        wg_public_from_private(dst->private_key, dst->public_key) != 0)
        dst->public_key[0] = '\0';

    v->wg_count++;
    pthread_mutex_unlock(&v->lock);
    return 0;
}

int vpn_add_peer(vpn_ctx_t *v, const wg_peer_t *p) {
    if (!p->name[0] || !p->public_key[0]) return -1;

    pthread_mutex_lock(&v->lock);
    if (v->peer_count >= MAX_WG_PEERS || find_peer_locked(v, p->name)) {
        pthread_mutex_unlock(&v->lock);
        return -1;
    }
    v->peers[v->peer_count] = *p;
    v->peer_count++;
    pthread_mutex_unlock(&v->lock);
    return 0;
}

int vpn_add_tunnel(vpn_ctx_t *v, const ipsec_tunnel_t *t) {
    if (!t->name[0]) return -1;

    pthread_mutex_lock(&v->lock);
    if (v->tunnel_count >= MAX_IPSEC_TUNNELS) {
        pthread_mutex_unlock(&v->lock);
        return -1;
    }
    for (int i = 0; i < v->tunnel_count; i++)
        if (!strcmp(v->tunnels[i].name, t->name)) {
            pthread_mutex_unlock(&v->lock);
            return -1;
        }

    ipsec_tunnel_t *dst = &v->tunnels[v->tunnel_count];
    *dst = *t;
    if (!dst->ike_proposal[0])
        snprintf(dst->ike_proposal, VPN_PROPOSAL_LEN, "aes256-sha256-modp2048");
    if (!dst->esp_proposal[0])
        snprintf(dst->esp_proposal, VPN_PROPOSAL_LEN, "aes256-sha256-modp2048");
    if (dst->ike_lifetime <= 0) dst->ike_lifetime = 10800;
    if (dst->esp_lifetime <= 0) dst->esp_lifetime = 3600;
    if (dst->dpd_delay    <= 0) dst->dpd_delay    = 30;

    v->tunnel_count++;
    pthread_mutex_unlock(&v->lock);
    return 0;
}

wg_iface_t *vpn_find_wg(vpn_ctx_t *v, const char *ifname) {
    pthread_mutex_lock(&v->lock);
    wg_iface_t *r = find_wg_locked(v, ifname);
    pthread_mutex_unlock(&v->lock);
    return r;
}

wg_peer_t *vpn_find_peer(vpn_ctx_t *v, const char *name) {
    pthread_mutex_lock(&v->lock);
    wg_peer_t *r = find_peer_locked(v, name);
    pthread_mutex_unlock(&v->lock);
    return r;
}

int vpn_remove_peer(vpn_ctx_t *v, const char *name) {
    pthread_mutex_lock(&v->lock);
    wg_peer_t *p = find_peer_locked(v, name);
    if (!p) {
        pthread_mutex_unlock(&v->lock);
        return -1;
    }
    int idx = (int)(p - v->peers);
    for (int i = idx; i < v->peer_count - 1; i++) v->peers[i] = v->peers[i + 1];
    v->peer_count--;
    explicit_bzero(&v->peers[v->peer_count], sizeof(v->peers[0]));
    pthread_mutex_unlock(&v->lock);
    return 0;
}

bool vpn_is_wg_iface(vpn_ctx_t *v, const char *ifname) {
    if (!v || !ifname || !*ifname) return false;
    pthread_mutex_lock(&v->lock);
    bool found = find_wg_locked(v, ifname) != NULL;
    pthread_mutex_unlock(&v->lock);
    return found;
}

zone_t vpn_zone_for(vpn_ctx_t *v, uint32_t ip) {
    if (!v) return ZONE_MAX;

    pthread_mutex_lock(&v->lock);
    zone_t best = ZONE_MAX;
    uint32_t best_mask = 0;      /* host order; wider prefix = larger value */

    for (int i = 0; i < v->peer_count; i++) {
        wg_peer_t *p = &v->peers[i];
        if (!p->enabled) continue;
        for (int j = 0; j < p->allowed_count; j++) {
            uint32_t m = p->allowed[j].mask;
            if ((ip & m) != (p->allowed[j].ip & m)) continue;
            /* Longest prefix wins, so a /32 for one host beats a site /24. */
            if (best == ZONE_MAX || ntohl(m) > ntohl(best_mask)) {
                best = p->zone;
                best_mask = m;
            }
        }
    }

    for (int i = 0; i < v->tunnel_count; i++) {
        ipsec_tunnel_t *t = &v->tunnels[i];
        if (!t->enabled || !t->remote_mask) continue;
        uint32_t m = t->remote_mask;
        if ((ip & m) != (t->remote_subnet & m)) continue;
        if (best == ZONE_MAX || ntohl(m) > ntohl(best_mask)) {
            best = t->zone;
            best_mask = m;
        }
    }

    pthread_mutex_unlock(&v->lock);
    return best;
}

/* ── WireGuard provisioning ─────────────────────────────────────────── */

/* Opens a file that will hold secrets: 0600 from the moment it exists, never
 * briefly world-readable. */
static FILE *open_private(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return NULL; }
    return f;
}

int vpn_generate_wg_config(vpn_ctx_t *v, const char *dir) {
    if (!v->wg_count) return 0;

    struct stat st;
    if (stat(dir, &st) != 0 && mkdir(dir, 0700) != 0) {
        fprintf(stderr, "[%s] cannot create %s (%s)\n",
                BRAND_PRODUCT, dir, strerror(errno));
        return -1;
    }

    char abuf[INET_ADDRSTRLEN], nbuf[64];
    int written = 0;

    pthread_mutex_lock(&v->lock);
    for (int i = 0; i < v->wg_count; i++) {
        wg_iface_t *w = &v->wg[i];
        if (!w->enabled) continue;
        if (!fx_ifname_safe(w->ifname, IFNAME_LEN)) {
            fprintf(stderr, "[%s] WireGuard: refusing unsafe interface name\n",
                    BRAND_PRODUCT);
            continue;
        }

        char path[512];
        snprintf(path, sizeof(path), "%s/%s.conf", dir, w->ifname);

        FILE *f = open_private(path);
        if (!f) {
            fprintf(stderr, "[%s] cannot write %s (%s)\n",
                    BRAND_PRODUCT, path, strerror(errno));
            continue;
        }

        fprintf(f, "# %s %s - generated, do not edit by hand\n",
                BRAND_PRODUCT, BRAND_VERSION);
        fprintf(f, "# Interface %s", w->ifname);
        if (w->description[0]) fprintf(f, " - %s", w->description);
        fprintf(f, "\n\n[Interface]\n");
        fprintf(f, "PrivateKey = %s\n", w->private_key);
        fprintf(f, "ListenPort = %u\n", w->listen_port);
        if (w->address)
            fprintf(f, "Address = %s/%d\n",
                    fx_ip_str(w->address, abuf, sizeof(abuf)),
                    fx_netmask_to_cidr(w->netmask));
        if (w->mtu > 0) fprintf(f, "MTU = %d\n", w->mtu);
        if (w->dns)
            fprintf(f, "DNS = %s\n", fx_ip_str(w->dns, abuf, sizeof(abuf)));

        for (int j = 0; j < v->peer_count; j++) {
            wg_peer_t *p = &v->peers[j];
            if (!p->enabled || strcmp(p->ifname, w->ifname)) continue;

            fprintf(f, "\n# %s", p->name);
            if (p->description[0]) fprintf(f, " - %s", p->description);
            fprintf(f, "\n# zone: %s\n", zone_name(p->zone));
            fprintf(f, "[Peer]\n");
            fprintf(f, "PublicKey = %s\n", p->public_key);
            if (p->preshared_key[0])
                fprintf(f, "PresharedKey = %s\n", p->preshared_key);

            fprintf(f, "AllowedIPs = ");
            for (int k = 0; k < p->allowed_count; k++)
                fprintf(f, "%s%s", k ? ", " : "",
                        fx_cidr_str(p->allowed[k].ip, p->allowed[k].mask,
                                    nbuf, sizeof(nbuf)));
            fputc('\n', f);

            if (p->endpoint_host[0])
                fprintf(f, "Endpoint = %s:%u\n", p->endpoint_host,
                        p->endpoint_port ? p->endpoint_port : 51820);
            if (p->keepalive > 0)
                fprintf(f, "PersistentKeepalive = %d\n", p->keepalive);
        }

        fflush(f);
        if (fsync(fileno(f)) != 0)
            fprintf(stderr, "[%s] %s: fsync failed\n", BRAND_PRODUCT, path);
        fclose(f);
        written++;
        printf("  [WG] %s -> %s\n", w->ifname, path);
    }
    pthread_mutex_unlock(&v->lock);
    return written;
}

int vpn_apply_wg(vpn_ctx_t *v) {
    if (!v->wg_count) return 0;

    printf("[%s] Bringing up WireGuard interfaces...\n", BRAND_PRODUCT);
    if (vpn_generate_wg_config(v, "/etc/wireguard") < 0) return -1;

    char cmd[256], abuf[INET_ADDRSTRLEN];
    int up = 0;

    pthread_mutex_lock(&v->lock);
    for (int i = 0; i < v->wg_count; i++) {
        wg_iface_t *w = &v->wg[i];
        if (!w->enabled || !fx_ifname_safe(w->ifname, IFNAME_LEN)) continue;

        /* wg-quick owns the interface lifecycle; bring it down first so a
         * re-apply after a config change actually reloads. */
        snprintf(cmd, sizeof(cmd), "wg-quick down %s 2>/dev/null", w->ifname);
        fx_try(cmd);
        snprintf(cmd, sizeof(cmd), "wg-quick up %s", w->ifname);
        if (fx_run(cmd) != 0) {
            fprintf(stderr, "[%s] %s did not come up; is wireguard-tools "
                    "installed?\n", BRAND_PRODUCT, w->ifname);
            continue;
        }

        /* Peers are reachable through this box, so the segment behind the
         * tunnel needs a route back. */
        for (int j = 0; j < v->peer_count; j++) {
            wg_peer_t *p = &v->peers[j];
            if (!p->enabled || strcmp(p->ifname, w->ifname)) continue;
            for (int k = 0; k < p->allowed_count; k++) {
                char nb[64];
                fx_cidr_str(p->allowed[k].ip, p->allowed[k].mask, nb, sizeof(nb));
                snprintf(cmd, sizeof(cmd),
                         "ip route replace %s dev %s 2>/dev/null", nb, w->ifname);
                fx_try(cmd);
            }
        }

        up++;
        printf("  [WG] %s up on port %u (%s), address %s/%d\n",
               w->ifname, w->listen_port, zone_name(w->zone),
               fx_ip_str(w->address, abuf, sizeof(abuf)),
               fx_netmask_to_cidr(w->netmask));
    }
    pthread_mutex_unlock(&v->lock);

    /* Let the tunnel in on the WAN, or the handshake never arrives. */
    for (int i = 0; i < v->wg_count; i++) {
        wg_iface_t *w = &v->wg[i];
        if (!w->enabled) continue;
        snprintf(cmd, sizeof(cmd),
                 "iptables -I INPUT -p udp --dport %u -j ACCEPT", w->listen_port);
        fx_run(cmd);
    }
    return up;
}

int vpn_teardown_wg(vpn_ctx_t *v) {
    char cmd[256];
    for (int i = 0; i < v->wg_count; i++) {
        wg_iface_t *w = &v->wg[i];
        if (!fx_ifname_safe(w->ifname, IFNAME_LEN)) continue;
        snprintf(cmd, sizeof(cmd), "wg-quick down %s 2>/dev/null", w->ifname);
        fx_try(cmd);
        snprintf(cmd, sizeof(cmd),
                 "iptables -D INPUT -p udp --dport %u -j ACCEPT 2>/dev/null",
                 w->listen_port);
        fx_try(cmd);
    }
    return 0;
}

/* ── IPsec provisioning ─────────────────────────────────────────────── */

int vpn_generate_ipsec_config(vpn_ctx_t *v, const char *conf_path,
                              const char *secrets_path) {
    if (!v->tunnel_count) return 0;

    FILE *c = open_private(conf_path);
    if (!c) {
        fprintf(stderr, "[%s] cannot write %s (%s)\n",
                BRAND_PRODUCT, conf_path, strerror(errno));
        return -1;
    }
    FILE *s = open_private(secrets_path);
    if (!s) {
        fprintf(stderr, "[%s] cannot write %s (%s)\n",
                BRAND_PRODUCT, secrets_path, strerror(errno));
        fclose(c);
        return -1;
    }

    char lb[64], rb[64];
    int n = 0;

    pthread_mutex_lock(&v->lock);

    fprintf(c, "# %s %s - generated, do not edit by hand\n\nconnections {\n",
            BRAND_PRODUCT, BRAND_VERSION);
    fprintf(s, "# %s %s - generated, do not edit by hand\n\nsecrets {\n",
            BRAND_PRODUCT, BRAND_VERSION);

    for (int i = 0; i < v->tunnel_count; i++) {
        ipsec_tunnel_t *t = &v->tunnels[i];
        if (!t->enabled) continue;

        fx_cidr_str(t->local_subnet,  t->local_mask,  lb, sizeof(lb));
        fx_cidr_str(t->remote_subnet, t->remote_mask, rb, sizeof(rb));

        fprintf(c, "    %s {\n", t->name);
        if (t->description[0]) fprintf(c, "        # %s\n", t->description);
        fprintf(c, "        version = %d\n", t->version == IKE_V1 ? 1 : 2);
        fprintf(c, "        remote_addrs = %s\n", t->remote_host);
        fprintf(c, "        proposals = %s\n", t->ike_proposal);
        fprintf(c, "        rekey_time = %ds\n", t->ike_lifetime);
        if (t->dpd) {
            fprintf(c, "        dpd_delay = %ds\n", t->dpd_delay);
            fprintf(c, "        dpd_timeout = %ds\n", t->dpd_delay * 4);
        }
        fprintf(c, "        local {\n");
        if (t->local_id[0]) fprintf(c, "            id = %s\n", t->local_id);
        fprintf(c, "            auth = psk\n        }\n");
        fprintf(c, "        remote {\n");
        if (t->remote_id[0]) fprintf(c, "            id = %s\n", t->remote_id);
        fprintf(c, "            auth = psk\n        }\n");
        fprintf(c, "        children {\n            %s {\n", t->name);
        fprintf(c, "                local_ts  = %s\n", lb);
        fprintf(c, "                remote_ts = %s\n", rb);
        fprintf(c, "                esp_proposals = %s\n", t->esp_proposal);
        fprintf(c, "                rekey_time = %ds\n", t->esp_lifetime);
        fprintf(c, "                start_action = trap\n");
        fprintf(c, "                # zone: %s\n", zone_name(t->zone));
        fprintf(c, "            }\n        }\n    }\n");

        fprintf(s, "    ike-%s {\n", t->name);
        if (t->local_id[0])  fprintf(s, "        id-local = %s\n", t->local_id);
        if (t->remote_id[0]) fprintf(s, "        id-remote = %s\n", t->remote_id);
        fprintf(s, "        secret = \"%s\"\n    }\n", t->psk);
        n++;
    }

    fprintf(c, "}\n");
    fprintf(s, "}\n");
    pthread_mutex_unlock(&v->lock);

    fflush(c); fflush(s);
    if (fsync(fileno(c)) != 0 || fsync(fileno(s)) != 0)
        fprintf(stderr, "[%s] IPsec config fsync failed\n", BRAND_PRODUCT);
    fclose(c);
    fclose(s);
    return n;
}

int vpn_apply_ipsec(vpn_ctx_t *v) {
    if (!v->tunnel_count) return 0;

    printf("[%s] Configuring IPsec tunnels...\n", BRAND_PRODUCT);
    int n = vpn_generate_ipsec_config(v, "/etc/swanctl/conf.d/firex.conf",
                                      "/etc/swanctl/conf.d/firex-secrets.conf");
    if (n <= 0) return n;

    /* Let IKE and NAT-T in before asking strongSwan to negotiate. */
    fx_run("iptables -I INPUT -p udp --dport 500 -j ACCEPT");
    fx_run("iptables -I INPUT -p udp --dport 4500 -j ACCEPT");
    fx_run("iptables -I INPUT -p esp -j ACCEPT");

    if (fx_run("swanctl --load-all") != 0)
        fprintf(stderr, "[%s] swanctl did not load the configuration; is "
                "strongSwan installed and running?\n", BRAND_PRODUCT);

    printf("  [IPSEC] %d tunnel(s) configured\n", n);
    return n;
}

int vpn_teardown_ipsec(vpn_ctx_t *v) {
    if (!v->tunnel_count) return 0;
    fx_try("swanctl --terminate --ike-all 2>/dev/null");
    fx_try("iptables -D INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null");
    fx_try("iptables -D INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null");
    fx_try("iptables -D INPUT -p esp -j ACCEPT 2>/dev/null");
    return 0;
}
