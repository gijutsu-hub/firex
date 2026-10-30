#ifndef FIREX_NETUTIL_H
#define FIREX_NETUTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>

/*
 * inet_ntoa() returns one shared static buffer, so two calls in a single
 * expression overwrite each other. fx_ip_str() formats into caller storage
 * instead; pass a char[INET_ADDRSTRLEN].
 */
const char *fx_ip_str(uint32_t addr_net_order, char *buf, size_t len);

/* 255.255.255.0 -> 24 */
int fx_netmask_to_cidr(uint32_t netmask_net_order);

/* True when the string can only be a real interface name, so it is safe to
 * paste into a shell command. */
bool fx_ifname_safe(const char *name, size_t maxlen);

/* Parse "10.0.0.0/8", "any" or "*" into address + mask (network order). */
void fx_parse_cidr(const char *s, uint32_t *ip, uint32_t *mask);

/* Inverse of fx_parse_cidr: 10.0.0.0 + 255.0.0.0 -> "10.0.0.0/8", and a zero
 * address -> "*", so the result can be fed straight back to the parser. */
const char *fx_cidr_str(uint32_t ip, uint32_t mask, char *buf, size_t len);

#endif
