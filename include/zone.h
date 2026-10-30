#ifndef FIREX_ZONE_H
#define FIREX_ZONE_H

/*
 * Security zones live in their own header so that both the packet structures
 * in firewall.h and the segmentation engine in vlan.h can use zone_t without
 * either one having to include the other.
 *
 * New zones are appended before ZONE_MAX so existing values stay put. A
 * configuration written before a zone existed simply has no policy lines for
 * it, and the matrix defaults to deny -- which is the safe direction.
 */
typedef enum {
    ZONE_WAN = 0,      /* Untrusted internet                     */
    ZONE_LAN,          /* Trusted corporate                      */
    ZONE_DMZ,          /* Semi-trusted public services           */
    ZONE_GUEST,        /* Untrusted internal (visitors)          */
    ZONE_IOT,          /* Restricted devices                     */
    ZONE_VOIP,         /* Voice (QoS-prioritised)                */
    ZONE_MGMT,         /* Appliance management only              */
    ZONE_QUARANTINE,   /* Isolated infected hosts                */
    ZONE_VPN,          /* Remote peers reached over WireGuard/IPsec */
    ZONE_MAX
} zone_t;

const char *zone_name(zone_t z);

#endif
