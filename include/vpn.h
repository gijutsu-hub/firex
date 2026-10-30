#ifndef FIREX_VPN_H
#define FIREX_VPN_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "zone.h"
#include "vlan.h"

/*
 * WireGuard and IPsec.
 *
 * FireX owns the configuration, not the data plane: it generates
 * /etc/wireguard/<if>.conf and the strongSwan files, then hands them to
 * wg-quick and swanctl. Keys are generated with OpenSSL's X25519
 * implementation rather than anything hand-rolled here.
 *
 * Secrets -- the interface private key, peer pre-shared keys and IPsec PSKs --
 * are held in memory and written only to mode-0600 files. They are never put
 * in an API response and never logged; the console sees a fingerprint.
 */

#define MAX_WG_INTERFACES   4
#define MAX_WG_PEERS        64
#define MAX_IPSEC_TUNNELS   16
#define WG_ALLOWED_MAX      16

#define WG_KEY_B64_LEN      45    /* 44 base64 characters + NUL */
#define VPN_NAME_LEN        40
#define VPN_HOST_LEN        128
#define VPN_SECRET_LEN      128
#define VPN_PROPOSAL_LEN    96

typedef struct { uint32_t ip, mask; } vpn_net_t;

/* ── WireGuard ──────────────────────────────────────────────────────── */

typedef struct {
    char      ifname[IFNAME_LEN];           /* wg0 */
    char      private_key[WG_KEY_B64_LEN];  /* secret */
    char      public_key[WG_KEY_B64_LEN];   /* derived from the private key */
    uint16_t  listen_port;
    uint32_t  address, netmask;             /* the tunnel address of this box */
    int       mtu;
    zone_t    zone;                         /* default zone for its peers */
    uint32_t  dns;                          /* pushed to road-warrior peers */
    char      description[VLAN_DESC_LEN];
    bool      enabled;
} wg_iface_t;

typedef struct {
    char      name[VPN_NAME_LEN];
    char      ifname[IFNAME_LEN];           /* which interface it belongs to */
    char      public_key[WG_KEY_B64_LEN];
    char      preshared_key[WG_KEY_B64_LEN];/* secret; optional */
    vpn_net_t allowed[WG_ALLOWED_MAX];
    int       allowed_count;
    char      endpoint_host[VPN_HOST_LEN];  /* empty for roaming peers */
    uint16_t  endpoint_port;
    int       keepalive;                    /* seconds; 0 = off */
    zone_t    zone;                         /* overrides the interface zone */
    char      description[VLAN_DESC_LEN];
    bool      enabled;

    /* live, read back from the kernel */
    unsigned long rx_bytes, tx_bytes;
    time_t    last_handshake;
} wg_peer_t;

/* ── IPsec (site-to-site) ───────────────────────────────────────────── */

typedef enum { IKE_V2 = 0, IKE_V1 } ike_version_t;

typedef struct {
    char          name[VPN_NAME_LEN];
    char          remote_host[VPN_HOST_LEN];
    char          local_id[VPN_HOST_LEN];
    char          remote_id[VPN_HOST_LEN];
    uint32_t      local_subnet, local_mask;
    uint32_t      remote_subnet, remote_mask;
    char          psk[VPN_SECRET_LEN];      /* secret */
    ike_version_t version;
    char          ike_proposal[VPN_PROPOSAL_LEN];
    char          esp_proposal[VPN_PROPOSAL_LEN];
    int           ike_lifetime, esp_lifetime;   /* seconds */
    bool          dpd;
    int           dpd_delay;
    zone_t        zone;
    char          description[VLAN_DESC_LEN];
    bool          enabled;
} ipsec_tunnel_t;

typedef struct {
    wg_iface_t      wg[MAX_WG_INTERFACES];
    int             wg_count;
    wg_peer_t       peers[MAX_WG_PEERS];
    int             peer_count;

    ipsec_tunnel_t  tunnels[MAX_IPSEC_TUNNELS];
    int             tunnel_count;

    pthread_mutex_t lock;
} vpn_ctx_t;

int  vpn_init(vpn_ctx_t *v);
void vpn_shutdown(vpn_ctx_t *v);

/* ── keys ──
 * Both buffers must be at least WG_KEY_B64_LEN. Returns 0 on success.
 */
int  wg_generate_keypair(char *priv_b64, char *pub_b64);
int  wg_public_from_private(const char *priv_b64, char *pub_b64);

/* A WireGuard key is exactly 32 bytes, so base64 is 44 characters ending
 * in '='. Checks the encoding, not that the key is any good. */
bool wg_key_valid(const char *b64);

/* A short, non-reversible label for a key, so the console can show which key
 * is configured without ever handling the key itself. */
const char *wg_key_fingerprint(const char *b64, char *out, size_t len);

/* ── tables ── */
int  vpn_add_wg(vpn_ctx_t *v, const wg_iface_t *i);
int  vpn_add_peer(vpn_ctx_t *v, const wg_peer_t *p);
int  vpn_add_tunnel(vpn_ctx_t *v, const ipsec_tunnel_t *t);

wg_iface_t *vpn_find_wg(vpn_ctx_t *v, const char *ifname);
wg_peer_t  *vpn_find_peer(vpn_ctx_t *v, const char *name);
int         vpn_remove_peer(vpn_ctx_t *v, const char *name);

/*
 * Which zone owns this address, according to the peer and tunnel tables?
 * Longest prefix wins, so a specific peer beats a broad site tunnel.
 * Returns ZONE_MAX when nothing claims it.
 */
zone_t vpn_zone_for(vpn_ctx_t *v, uint32_t ip);

/* True when `ifname` is one of the configured WireGuard interfaces. */
bool vpn_is_wg_iface(vpn_ctx_t *v, const char *ifname);

/* ── provisioning ──
 * `dir` is normally /etc/wireguard. Files are created mode 0600 because they
 * carry private keys. Returns the number of interfaces written, or -1.
 */
int  vpn_generate_wg_config(vpn_ctx_t *v, const char *dir);
int  vpn_apply_wg(vpn_ctx_t *v);
int  vpn_teardown_wg(vpn_ctx_t *v);

/* strongSwan swanctl.conf plus its secrets file. */
int  vpn_generate_ipsec_config(vpn_ctx_t *v, const char *conf_path,
                               const char *secrets_path);
int  vpn_apply_ipsec(vpn_ctx_t *v);
int  vpn_teardown_ipsec(vpn_ctx_t *v);

const char *ike_version_str(ike_version_t v);

#endif
