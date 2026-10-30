#ifndef FIREX_NETCONF_H
#define FIREX_NETCONF_H

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include "vlan.h"
#include "brand.h"
#include "telemetry.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "feeds.h"
#include "response.h"
#include "malware.h"
#include "airgap.h"

#define MAX_PORT_FORWARDS 128
#define MAX_STATIC_ROUTES 64
#define MAX_DHCP_RESERV   256

typedef enum { WAN_DHCP, WAN_STATIC, WAN_PPPOE, WAN_DISABLED } wan_mode_t;

typedef struct {
    char       ifname[IFNAME_LEN];
    wan_mode_t mode;

    /* Static */
    uint32_t   ip, netmask, gateway;
    uint32_t   dns1, dns2;

    /* PPPoE */
    char       pppoe_user[64];
    char       pppoe_pass[64];
    char       pppoe_service[64];

    /* Behaviour */
    int        mtu;
    bool       nat_enabled;          /* masquerade                   */
    bool       block_private_in;     /* RFC1918 ingress drop         */
    bool       block_bogons;
    bool       respond_to_ping;
    bool       upnp_enabled;

    /* Failover */
    bool       is_backup;
    int        failover_priority;
    char       monitor_ip[INET_ADDRSTRLEN];

    /* Live */
    bool       link_up;
    uint32_t   current_ip;
    unsigned long rx_bytes, tx_bytes;
} wan_config_t;

typedef struct {
    int      id;
    char     name[VLAN_NAME_LEN];
    uint8_t  protocol;
    uint16_t wan_port_start, wan_port_end;
    uint32_t internal_ip;
    uint16_t internal_port;
    uint16_t dst_vlan;
    uint32_t source_restrict;       /* 0 = any */
    uint32_t source_mask;
    bool     log_hits;
    bool     enabled;
    char     description[VLAN_DESC_LEN];
    unsigned long hits;
} port_forward_t;

typedef struct {
    uint32_t dest, mask, gateway;
    char     ifname[IFNAME_LEN];   /* optional; empty lets the kernel pick */
    int      metric;
    char     description[VLAN_DESC_LEN];
    bool     enabled;
} static_route_t;

typedef struct {
    unsigned char mac[6];
    uint32_t      ip;
    uint16_t      vlan_id;
    char          hostname[64];
    char          note[64];
    bool          enabled;
} dhcp_reservation_t;

typedef struct netconf_ctx {
    wan_config_t       wan[2];       /* primary + failover */
    int                wan_count;

    port_forward_t     forwards[MAX_PORT_FORWARDS];
    int                forward_count;

    static_route_t     routes[MAX_STATIC_ROUTES];
    int                route_count;

    dhcp_reservation_t reservations[MAX_DHCP_RESERV];
    int                reservation_count;

    bool               ipv6_enabled;
    bool               hairpin_nat;
    char               domain[64];

    /* Observability: where to ship logs and flows, and how often to sample
     * the history ring. Empty hosts mean "do not export". */
    telemetry_cfg_t    telemetry;
    shaper_cfg_t       shaping;
    portal_cfg_t       portal;
    ha_cfg_t           ha;
    threat_cfg_t       threat;
    response_cfg_t     response;
    mw_cfg_t           malware;
    ag_cfg_t           airgap;

    /*
     * The administration console's own listener. Separate from the block
     * page on purpose: the portal faces the segments being defended
     * against, the console must not. bind is an address, "mgmt" for the
     * management zone's gateway, or "any".
     */
    int                console_port;
    char               console_bind[64];

    /*
     * TLS on the console. Defaults ON -- an appliance that ships with its
     * management interface in the clear is one whose first deployment is
     * already a finding, and "secure unless turned off" is the only
     * default that survives an operator who never reads this file.
     * console_tls_cert/key are generated on first start when absent.
     */
    bool               console_tls;
    bool               console_tls_set;   /* the config said so explicitly */
    char               console_tls_cert[256];
    char               console_tls_key[256];

    /* Air-gap transfer windows, applied to the engine at startup. */
    ag_window_t        airgap_windows[AG_MAX_WINDOWS];
    int                airgap_window_count;

    /* Feed definitions; the engine copies them in at startup. */
    feed_t             feeds[FEED_MAX_FEEDS];
    int                feed_count;

    /* Gateway monitor tuning; 0 means "use the gwmon default". */
    int                monitor_interval;
    int                monitor_timeout_ms;
    int                monitor_fail;
    int                monitor_ok;

    pthread_mutex_t    lock;
} netconf_ctx_t;

int  netconf_init(netconf_ctx_t *n);
int  netconf_apply_wan(netconf_ctx_t *n);
int  netconf_apply_nat(netconf_ctx_t *n, vlan_ctx_t *v);
int  netconf_apply_forwards(netconf_ctx_t *n);
int  netconf_generate_dhcp(netconf_ctx_t *n, vlan_ctx_t *v, const char *out);
int  netconf_add_forward(netconf_ctx_t *n, port_forward_t *f);
int  netconf_add_route(netconf_ctx_t *n, static_route_t *r);

/*
 * Installs the static route table. Each route is deleted before it is added,
 * so re-applying after a config change replaces rather than duplicates.
 * Routes FireX did not add are left alone.
 */
int  netconf_apply_routes(netconf_ctx_t *n);
void netconf_shutdown(netconf_ctx_t *n);

#endif
