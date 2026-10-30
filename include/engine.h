#ifndef FW_ENGINE_H
#define FW_ENGINE_H

#include "firewall.h"

/*
 * One entry point for all three capture backends, so callers do not have to
 * remember which stop function pairs with which start.
 */
int  engine_start(firewall_ctx_t *ctx, const char *iface, engine_t engine);
void engine_stop(firewall_ctx_t *ctx);
const char *engine_name(engine_t e);

/* Human-readable detail about the last start attempt, or NULL when the
 * backend has nothing to add. */
const char *engine_detail(engine_t e);

#endif
