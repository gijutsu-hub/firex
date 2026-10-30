#ifndef FIREX_NETIF_H
#define FIREX_NETIF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Interface inventory.
 *
 * Everything here is read out of /sys/class/net and getifaddrs(), so it
 * reports what the kernel currently believes rather than what the
 * configuration asked for. Those two disagree exactly when something is
 * wrong -- a port configured for a gigabit that negotiated 100, a link
 * that is administratively up with no carrier -- and that disagreement is
 * the most useful thing an interface page can show. Showing the intended
 * configuration back to the operator tells them nothing they did not
 * already type.
 */

#define NETIF_MAX        64
#define NETIF_NAME_LEN   32
#define NETIF_DRIVER_LEN 32

typedef enum {
    NETIF_KIND_PHYSICAL = 0,   /* has a device behind it   */
    NETIF_KIND_LOOPBACK,
    NETIF_KIND_BRIDGE,
    NETIF_KIND_VLAN,
    NETIF_KIND_TUNNEL,         /* wireguard, ppp, tun/tap  */
    NETIF_KIND_VIRTUAL         /* veth, docker, anything else */
} netif_kind_t;

typedef struct {
    char   name[NETIF_NAME_LEN];
    char   mac[18];
    char   ipv4[16];          /* empty when unaddressed */
    char   netmask[16];
    char   driver[NETIF_DRIVER_LEN];

    netif_kind_t kind;

    bool   admin_up;          /* IFF_UP                          */
    bool   carrier;           /* a cable with something on it    */
    char   oper[16];          /* up / down / dormant / unknown   */
    int    mtu;
    int    speed_mbps;        /* -1 when the driver will not say */
    char   duplex[8];         /* full / half / empty             */

    unsigned long rx_bytes, tx_bytes;
    unsigned long rx_packets, tx_packets;
    unsigned long rx_errors, tx_errors;
    unsigned long rx_dropped, tx_dropped;
} netif_t;

/*
 * Fills `out` with up to `max` interfaces and returns how many. Ordered
 * with physical ports first and the loopback last, because that is the
 * order an operator looks for them in -- an alphabetical list puts
 * docker0 above the uplink.
 */
int  netif_list(netif_t *out, int max);

/* One interface by name. False when it does not exist. */
bool netif_get(const char *name, netif_t *out);

/*
 * Brings a link administratively up or down. Needs CAP_NET_ADMIN, and
 * returns -1 with errno set when it is not held -- callers report that
 * rather than silently appearing to succeed. `name` is validated against
 * the interface character set before it reaches the kernel.
 */
int  netif_set_admin(const char *name, bool up);

const char *netif_kind_name(netif_kind_t k);

/*
 * True when `name` is a plausible interface name: 1..15 characters of
 * [A-Za-z0-9._-] only. Exposed because every caller that accepts a name
 * from the network has to check it before it is used in a path or a
 * command, and one shared rule is easier to audit than five.
 */
bool netif_name_ok(const char *name);

#endif /* FIREX_NETIF_H */
