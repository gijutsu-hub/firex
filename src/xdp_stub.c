/*
 * Fallback XDP backend, compiled in place of xdp_filter.c when libbpf headers
 * are not installed. Keeps the binary buildable and the engine selectable;
 * starting it reports why it cannot run instead of pretending to filter.
 */
#include "xdp_filter.h"

bool xdp_engine_available(void)
{
    return false;
}

const char *xdp_engine_status(void)
{
    return "This build has no XDP support: libbpf development headers were "
           "missing at compile time. Install them and rebuild:\n\n"
           "    make deps && make clean && make";
}

int xdp_engine_start(firewall_ctx_t *ctx)
{
    (void)ctx;
    return -1;
}

void xdp_engine_stop(firewall_ctx_t *ctx)
{
    (void)ctx;
}
