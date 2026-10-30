#ifndef FIREX_VLAN_H
#define FIREX_VLAN_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>
#include "brand.h"
#include "zone.h"
#include "netutil.h"
#include "policy.h"

#define MAX_VLANS              64
#define MAX_PORTS              16
#define MAX_VLANS_PER_PORT     32
#define VLAN_NAME_LEN          32
#define VLAN_DESC_LEN          96
#define IFNAME_LEN             16

#ifndef ETH_P_8021Q
#define ETH_P_8021Q            0x8100   /* Customer VLAN tag  */
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD           0x88A8   /* QinQ service tag   */
#endif
#define VLAN_ID_MASK           0x0FFF
#define VLAN_PCP_SHIFT         13
#define VLAN_DEI_MASK          0x1000

/* ── Port operating modes (802.1Q) ──────────────────────────── */
typedef enum {
    PORT_MODE_ACCESS,  /* Single untagged VLAN (PVID)            */
    PORT_MODE_TRUNK,   /* Multiple tagged VLANs                  */
    PORT_MODE_HYBRID,  /* Native untagged + tagged VLANs         */
    PORT_MODE_MIRROR,  /* SPAN / monitor port                    */
    PORT_MODE_DISABLED
} port_mode_t;

/* ── VLAN definition ────────────────────────────────────────── */
typedef struct {
    uint16_t vlan_id;                  /* 1-4094                 */
    char     name[VLAN_NAME_LEN];
    char     description[VLAN_DESC_LEN];
    zone_t   zone;

    /* L3 configuration */
    uint32_t subnet;                   /* network addr, net order*/
    uint32_t netmask;
    uint32_t gateway;                  /* FireX SVI address      */

    /* DHCP scope */
    bool     dhcp_enabled;
    uint32_t dhcp_start;
    uint32_t dhcp_end;
    uint32_t dns_primary;
    uint32_t dns_secondary;
    int      lease_time;

    /* Policy flags */
    bool     inter_vlan_routing;
    bool     internet_access;
    bool     client_isolation;
    bool     dpi_enabled;
    bool     ips_enabled;
    bool     malware_scan;
    bool     log_all;

    /* QoS / shaping */
    int      bandwidth_up_mbps;        /* 0 = unlimited            */
    int      bandwidth_down_mbps;
    uint8_t  priority;                 /* 802.1p PCP 0-7           */
    int      max_clients;

    /* Captive / block-page behaviour */
    bool     captive_portal;
    bool     show_block_page;

    bool     enabled;

    /* Live counters */
    unsigned long rx_packets, tx_packets;
    unsigned long rx_bytes,   tx_bytes;
    unsigned long blocked_packets;
    int           active_clients;
} vlan_config_t;

/* ── Physical port definition ───────────────────────────────── */
typedef struct {
    char        ifname[IFNAME_LEN];
    char        label[VLAN_NAME_LEN];
    port_mode_t mode;
    zone_t      zone;

    uint16_t    pvid;
    uint16_t    allowed_vlans[MAX_VLANS_PER_PORT];
    int         allowed_count;

    bool        tag_native;
    bool        drop_untagged;
    bool        stp_enabled;
    bool        storm_control;
    int         storm_pps_limit;

    bool        link_up;
    int         speed_mbps;
    bool        enabled;

    unsigned long rx_packets, tx_packets, dropped;
} port_config_t;

/* ── Inter-VLAN ACL rule ────────────────────────────────────── */
typedef enum { IVR_ALLOW, IVR_DENY, IVR_LOG_ALLOW, IVR_LOG_DENY } ivr_action_t;

typedef struct {
    int          id;
    uint16_t     src_vlan;      /* 0 = any */
    uint16_t     dst_vlan;      /* 0 = any */
    uint32_t     src_ip, src_mask;
    uint32_t     dst_ip, dst_mask;
    uint16_t     dst_port_start, dst_port_end;
    uint8_t      protocol;      /* 0 = any */

    /*
     * Alias and schedule references, resolved at match time against the
     * policy table. An alias name takes precedence over the literal
     * address/port fields above; an empty name means "use the literal".
     */
    char         src_alias[POLICY_NAME_LEN];
    char         dst_alias[POLICY_NAME_LEN];
    char         port_alias[POLICY_NAME_LEN];
    char         schedule[POLICY_NAME_LEN];

    ivr_action_t action;
    int          priority;
    char         description[VLAN_DESC_LEN];
    bool         enabled;
    unsigned long hits;
} ivr_rule_t;

#define MAX_IVR_RULES 256

/* ── VLAN subsystem context ─────────────────────────────────── */
typedef struct {
    vlan_config_t vlans[MAX_VLANS];
    int           vlan_count;

    port_config_t ports[MAX_PORTS];
    int           port_count;

    ivr_rule_t    ivr[MAX_IVR_RULES];
    int           ivr_count;

    ivr_action_t  zone_matrix[ZONE_MAX][ZONE_MAX];

    /*
     * Optional alias/schedule table. Left NULL the engine behaves exactly as
     * it did before: rules fall back to their literal addresses and ports,
     * and a rule carrying a schedule never matches.
     */
    policy_ctx_t *policy;

    /*
     * When HA is running, the gateway addresses are virtual: VRRP moves them
     * between nodes, and a node that also assigns them statically would
     * answer for an address it does not currently own. Set before
     * vlan_apply_to_system() so it leaves them to keepalived.
     */
    bool ha_owns_gateways;

    pthread_mutex_t lock;

    unsigned long inter_vlan_allowed;
    unsigned long inter_vlan_denied;
    unsigned long tagged_rx;
    unsigned long untagged_rx;
    unsigned long vlan_violations;
    unsigned long schedule_skipped;   /* rules that matched but were off-hours */
} vlan_ctx_t;

/* ── API ────────────────────────────────────────────────────── */
int   vlan_init(vlan_ctx_t *v);

/* Attach the alias / schedule table used to resolve rule references. */
void  vlan_set_policy(vlan_ctx_t *v, policy_ctx_t *p);
int   vlan_save_config(vlan_ctx_t *v, const char *file);

int   vlan_add(vlan_ctx_t *v, vlan_config_t *cfg);
int   vlan_remove(vlan_ctx_t *v, uint16_t vid);
vlan_config_t *vlan_get(vlan_ctx_t *v, uint16_t vid);

int   port_configure(vlan_ctx_t *v, port_config_t *p);
port_config_t *port_get(vlan_ctx_t *v, const char *ifname);
bool  port_vlan_permitted(port_config_t *p, uint16_t vid);

int   ivr_add_rule(vlan_ctx_t *v, ivr_rule_t *r);
ivr_action_t vlan_check_forward(vlan_ctx_t *v, uint16_t src_vid, uint16_t dst_vid,
                                uint32_t sip, uint32_t dip, uint16_t dport,
                                uint8_t proto, char *reason, int rlen);

/*
 * Zone matrix lookup on its own, for traffic that belongs to no VLAN -- a
 * VPN peer, say. Counts toward the same allowed/denied totals so the figures
 * still describe all forwarded traffic.
 */
ivr_action_t vlan_check_zones(vlan_ctx_t *v, zone_t from, zone_t to,
                              char *reason, int rlen);

void  vlan_set_zone_policy(vlan_ctx_t *v, zone_t from, zone_t to, ivr_action_t a);
const char *port_mode_name(port_mode_t m);

/* System provisioning (creates real Linux VLAN interfaces) */
int   vlan_apply_to_system(vlan_ctx_t *v);
int   vlan_teardown_system(vlan_ctx_t *v);

void  vlan_shutdown(vlan_ctx_t *v);

#endif /* FIREX_VLAN_H */
