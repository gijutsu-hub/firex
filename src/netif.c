/*
 * Interface inventory -- see include/netif.h.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "netif.h"

#define SYSNET "/sys/class/net"

const char *netif_kind_name(netif_kind_t k) {
    switch (k) {
        case NETIF_KIND_PHYSICAL: return "physical";
        case NETIF_KIND_LOOPBACK: return "loopback";
        case NETIF_KIND_BRIDGE:   return "bridge";
        case NETIF_KIND_VLAN:     return "vlan";
        case NETIF_KIND_TUNNEL:   return "tunnel";
        case NETIF_KIND_VIRTUAL:  return "virtual";
    }
    return "unknown";
}

bool netif_name_ok(const char *name) {
    if (!name || !*name) return false;
    size_t n = strlen(name);
    if (n >= IF_NAMESIZE) return false;          /* the kernel's own limit */
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '.' && c != '_' && c != '-') return false;
    }
    /* "." and ".." would escape the sysfs directory. */
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return false;
    return true;
}

/* ── sysfs helpers ───────────────────────────────────────────────────── */

static bool read_file(const char *path, char *out, size_t outlen) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    if (!fgets(out, (int)outlen, f)) { fclose(f); out[0] = 0; return false; }
    fclose(f);
    char *nl = strpbrk(out, "\r\n");
    if (nl) *nl = 0;
    return true;
}

static bool attr_path(char *buf, size_t buflen, const char *ifname,
                      const char *attr) {
    if (!netif_name_ok(ifname)) return false;
    int n = snprintf(buf, buflen, SYSNET "/%s/%s", ifname, attr);
    return n > 0 && (size_t)n < buflen;
}

static bool read_attr(const char *ifname, const char *attr,
                      char *out, size_t outlen) {
    char path[512];
    out[0] = 0;
    if (!attr_path(path, sizeof(path), ifname, attr)) return false;
    return read_file(path, out, outlen);
}

static long read_attr_long(const char *ifname, const char *attr, long dflt) {
    char v[64];
    if (!read_attr(ifname, attr, v, sizeof(v)) || !v[0]) return dflt;
    errno = 0;
    char *end = NULL;
    long r = strtol(v, &end, 10);
    if (errno || end == v) return dflt;
    return r;
}

static unsigned long read_stat(const char *ifname, const char *which) {
    char attr[64];
    snprintf(attr, sizeof(attr), "statistics/%s", which);
    long v = read_attr_long(ifname, attr, 0);
    return v < 0 ? 0UL : (unsigned long)v;
}

static bool path_exists(const char *ifname, const char *attr) {
    char path[512];
    if (!attr_path(path, sizeof(path), ifname, attr)) return false;
    return access(path, F_OK) == 0;
}

static void read_driver(const char *ifname, char *out, size_t outlen) {
    char path[512], link[256];
    out[0] = 0;
    if (!attr_path(path, sizeof(path), ifname, "device/driver")) return;
    ssize_t n = readlink(path, link, sizeof(link) - 1);
    if (n <= 0) return;
    link[n] = 0;
    const char *slash = strrchr(link, '/');
    const char *drv = slash ? slash + 1 : link;
    /* The symlink target is far longer than a driver name field; the
     * precision makes the truncation deliberate instead of incidental. */
    snprintf(out, outlen, "%.*s", (int)outlen - 1, drv);
}

static netif_kind_t classify(const char *ifname) {
    char type[32];
    long t = read_attr_long(ifname, "type", -1);
    if (t == 772) return NETIF_KIND_LOOPBACK;          /* ARPHRD_LOOPBACK */

    if (path_exists(ifname, "bridge"))      return NETIF_KIND_BRIDGE;
    if (path_exists(ifname, "lower_1") ||
        read_attr(ifname, "vlan", type, sizeof(type))) return NETIF_KIND_VLAN;
    if (strchr(ifname, '.'))                 return NETIF_KIND_VLAN;
    if (path_exists(ifname, "device"))       return NETIF_KIND_PHYSICAL;

    if (strncmp(ifname, "wg", 2) == 0 || strncmp(ifname, "tun", 3) == 0 ||
        strncmp(ifname, "tap", 3) == 0 || strncmp(ifname, "ppp", 3) == 0 ||
        strncmp(ifname, "ipsec", 5) == 0)
        return NETIF_KIND_TUNNEL;

    return NETIF_KIND_VIRTUAL;
}

/* ── addresses ───────────────────────────────────────────────────────── */

static void fill_address(netif_t *n) {
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return;

    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (!p->ifa_name || strcmp(p->ifa_name, n->name) != 0) continue;

        const struct sockaddr_in *sin = (const struct sockaddr_in *)p->ifa_addr;
        inet_ntop(AF_INET, &sin->sin_addr, n->ipv4, sizeof(n->ipv4));
        if (p->ifa_netmask) {
            const struct sockaddr_in *nm = (const struct sockaddr_in *)p->ifa_netmask;
            inet_ntop(AF_INET, &nm->sin_addr, n->netmask, sizeof(n->netmask));
        }
        break;
    }
    freeifaddrs(ifa);
}

/* ── one interface ───────────────────────────────────────────────────── */

static bool fill(const char *ifname, netif_t *n) {
    char v[64];

    memset(n, 0, sizeof(*n));
    snprintf(n->name, sizeof(n->name), "%s", ifname);

    char path[512];
    if (!attr_path(path, sizeof(path), ifname, "flags")) return false;
    if (access(path, F_OK) != 0) return false;

    long flags = read_attr_long(ifname, "flags", 0);   /* hex in sysfs */
    if (read_attr(ifname, "flags", v, sizeof(v)) && v[0])
        flags = strtol(v, NULL, 16);
    n->admin_up = (flags & IFF_UP) != 0;

    read_attr(ifname, "address", n->mac, sizeof(n->mac));
    read_attr(ifname, "operstate", n->oper, sizeof(n->oper));
    if (!n->oper[0]) snprintf(n->oper, sizeof(n->oper), "unknown");

    n->mtu = (int)read_attr_long(ifname, "mtu", 0);

    /*
     * carrier and speed are only readable while the link is up; reading
     * them on a down interface returns EINVAL. That is not an error worth
     * reporting -- it is the normal state of an unplugged port -- so a
     * failed read becomes "no carrier" and "unknown speed".
     */
    n->carrier    = read_attr_long(ifname, "carrier", 0) == 1;
    n->speed_mbps = (int)read_attr_long(ifname, "speed", -1);
    if (n->speed_mbps <= 0) n->speed_mbps = -1;
    read_attr(ifname, "duplex", n->duplex, sizeof(n->duplex));

    n->kind = classify(ifname);
    read_driver(ifname, n->driver, sizeof(n->driver));
    if (!n->driver[0] && n->kind != NETIF_KIND_PHYSICAL)
        snprintf(n->driver, sizeof(n->driver), "%s", netif_kind_name(n->kind));

    n->rx_bytes   = read_stat(ifname, "rx_bytes");
    n->tx_bytes   = read_stat(ifname, "tx_bytes");
    n->rx_packets = read_stat(ifname, "rx_packets");
    n->tx_packets = read_stat(ifname, "tx_packets");
    n->rx_errors  = read_stat(ifname, "rx_errors");
    n->tx_errors  = read_stat(ifname, "tx_errors");
    n->rx_dropped = read_stat(ifname, "rx_dropped");
    n->tx_dropped = read_stat(ifname, "tx_dropped");

    fill_address(n);
    return true;
}

bool netif_get(const char *name, netif_t *out) {
    if (!out || !netif_name_ok(name)) return false;
    return fill(name, out);
}

/* Physical first, then bridges and VLANs, then tunnels and virtual, with
 * loopback last. Within a group, by name. */
static int rank(const netif_t *n) {
    switch (n->kind) {
        case NETIF_KIND_PHYSICAL: return 0;
        case NETIF_KIND_VLAN:     return 1;
        case NETIF_KIND_BRIDGE:   return 2;
        case NETIF_KIND_TUNNEL:   return 3;
        case NETIF_KIND_VIRTUAL:  return 4;
        case NETIF_KIND_LOOPBACK: return 5;
    }
    return 4;
}

static int by_rank(const void *a, const void *b) {
    const netif_t *x = a, *y = b;
    int r = rank(x) - rank(y);
    if (r) return r;
    return strcmp(x->name, y->name);
}

int netif_list(netif_t *out, int max) {
    if (!out || max <= 0) return 0;

    DIR *d = opendir(SYSNET);
    if (!d) return 0;

    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        if (e->d_name[0] == '.') continue;
        if (!netif_name_ok(e->d_name)) continue;
        if (fill(e->d_name, &out[n])) n++;
    }
    closedir(d);

    qsort(out, (size_t)n, sizeof(netif_t), by_rank);
    return n;
}

int netif_set_admin(const char *name, bool up) {
    if (!netif_name_ok(name)) { errno = EINVAL; return -1; }

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) { close(fd); return -1; }

    short want = ifr.ifr_flags;
    if (up) want |= IFF_UP; else want &= (short)~IFF_UP;
    if (want == ifr.ifr_flags) { close(fd); return 0; }

    ifr.ifr_flags = want;
    int rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    int saved = errno;
    close(fd);
    errno = saved;
    return rc < 0 ? -1 : 0;
}
