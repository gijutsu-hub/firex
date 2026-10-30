#ifndef FW_XDP_FILTER_H
#define FW_XDP_FILTER_H

#include "firewall.h"

/*
 * XDP/eBPF backend. The kernel program (xdp/xdp_firewall.bpf.c) is loaded at
 * runtime from xdp/xdp_firewall.bpf.o and attached to the interface's ingress
 * hook, so it filters inbound traffic only.
 *
 * Not every rule can be offloaded: BPF has no regex engine, so DPI rules stay
 * in userspace and are reported by xdp_engine_status() instead of being
 * silently ignored.
 */
int  xdp_engine_start(firewall_ctx_t *ctx);
void xdp_engine_stop(firewall_ctx_t *ctx);

/* True when the compiled BPF object is present and the process can load it. */
bool xdp_engine_available(void);

/* Why the engine cannot start, or - after a successful start - which rules
 * were offloaded and which were left behind. Never NULL. */
const char *xdp_engine_status(void);

#endif
