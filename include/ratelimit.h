#ifndef FW_RATELIMIT_H
#define FW_RATELIMIT_H

#include "firewall.h"

void rate_limiter_init(rate_limiter_t *rl);
void rate_limiter_cleanup(rate_limiter_t *rl);
bool rate_limiter_check(rate_limiter_t *rl, uint32_t ip, int pkt_size,
                        int max_pps, int max_bps);
void rate_limiter_reset(rate_limiter_t *rl);
int rate_limiter_get_count(rate_limiter_t *rl, uint32_t ip);

#endif
