#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "netutil.h"

const char *fx_ip_str(uint32_t addr_net_order, char *buf, size_t len)
{
    struct in_addr a;
    a.s_addr = addr_net_order;
    if (!inet_ntop(AF_INET, &a, buf, (socklen_t)len))
        snprintf(buf, len, "0.0.0.0");
    return buf;
}

int fx_netmask_to_cidr(uint32_t netmask_net_order)
{
    int bits = 0;
    uint32_t m = ntohl(netmask_net_order);
    while (m & 0x80000000u) { bits++; m <<= 1; }
    return bits;
}

bool fx_ifname_safe(const char *name, size_t maxlen)
{
    if (!name || !name[0] || strlen(name) >= maxlen) return false;
    for (const char *p = name; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-' && *p != '.')
            return false;
    return true;
}

void fx_parse_cidr(const char *s, uint32_t *ip, uint32_t *mask)
{
    *ip = 0;
    *mask = 0;
    if (!s || !*s || !strcasecmp(s, "any") || !strcmp(s, "*")) return;

    char buf[64];
    snprintf(buf, sizeof(buf), "%s", s);

    char *sl = strchr(buf, '/');
    int bits = 32;
    if (sl) { *sl = '\0'; bits = atoi(sl + 1); }
    if (bits < 0 || bits > 32) bits = 32;

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1) return;

    *mask = bits ? htonl(~((1u << (32 - bits)) - 1)) : 0;
    *ip = a.s_addr & *mask;
}

const char *fx_cidr_str(uint32_t ip, uint32_t mask, char *buf, size_t len) {
    if (!ip) { snprintf(buf, len, "*"); return buf; }
    char a[INET_ADDRSTRLEN];
    int bits = mask ? fx_netmask_to_cidr(mask) : 32;
    snprintf(buf, len, "%s/%d", fx_ip_str(ip, a, sizeof(a)), bits);
    return buf;
}
