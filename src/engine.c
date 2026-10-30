#include <string.h>
#include <stdio.h>

#include "engine.h"
#include "nfqueue.h"
#include "xdp_filter.h"

const char *engine_name(engine_t e)
{
    switch (e) {
        case ENGINE_RAW_SOCKET: return "Monitor";
        case ENGINE_NFQUEUE:    return "NFQUEUE";
        case ENGINE_XDP:        return "XDP";
        default:                return "Unknown";
    }
}

const char *engine_detail(engine_t e)
{
    if (e == ENGINE_XDP)
        return xdp_engine_status();
    return NULL;
}

int engine_start(firewall_ctx_t *ctx, const char *iface, engine_t engine)
{
    snprintf(ctx->interface, MAX_IFACE_NAME, "%s", iface);

    switch (engine) {
        case ENGINE_NFQUEUE:
            return nfq_engine_start(ctx);
        case ENGINE_XDP:
            return xdp_engine_start(ctx);
        default:
            return fw_start(ctx, iface, ENGINE_RAW_SOCKET);
    }
}

void engine_stop(firewall_ctx_t *ctx)
{
    if (!ctx->running)
        return;

    switch (ctx->engine) {
        case ENGINE_NFQUEUE: nfq_engine_stop(ctx); break;
        case ENGINE_XDP:     xdp_engine_stop(ctx); break;
        default:             fw_stop(ctx);         break;
    }
}
