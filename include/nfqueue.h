#ifndef FW_NFQUEUE_H
#define FW_NFQUEUE_H

#include "firewall.h"

int nfq_engine_start(firewall_ctx_t *ctx);
void nfq_engine_stop(firewall_ctx_t *ctx);
int nfq_setup_iptables(const char *iface, int queue_num);
int nfq_cleanup_iptables(const char *iface, int queue_num);

#endif
