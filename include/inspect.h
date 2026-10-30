#ifndef FIREX_INSPECT_H
#define FIREX_INSPECT_H

#include "firewall.h"
#include "vlan.h"
#include "netconf.h"
#include "blockpage.h"
#include "policy.h"
#include "gwmon.h"
#include "vpn.h"
#include "histstats.h"
#include "capture.h"
#include "telemetry.h"
#include "shaper.h"
#include "portal.h"
#include "ha.h"
#include "ids.h"
#include "feeds.h"
#include "malware.h"
#include "airgap.h"
#include "response.h"

/* The enterprise subsystems. Defined in inspect.c so every module that needs
 * them shares one instance. */
extern vlan_ctx_t      g_vlan;
extern netconf_ctx_t   g_netconf;
extern blockpage_ctx_t g_blockpage;
extern policy_ctx_t    g_policy;
extern gwmon_ctx_t     g_gwmon;
extern vpn_ctx_t       g_vpn;
extern hist_ctx_t      g_hist;
extern capture_ctx_t   g_capture;
extern telemetry_ctx_t g_telemetry;
extern shaper_ctx_t    g_shaper;
extern portal_ctx_t    g_portal;
extern ha_ctx_t        g_ha;
extern ids_ctx_t       g_ids;
extern feeds_ctx_t     g_feeds;
extern mw_ctx_t        g_malware;
extern ag_ctx_t        g_airgap;
extern response_ctx_t  g_response;

/* Install firex_inspect() as the firewall's inspection hook. */
void firex_inspect_enable(firewall_ctx_t *ctx);
void firex_inspect_disable(firewall_ctx_t *ctx);

/* Full pipeline: VLAN membership -> inter-VLAN/zone policy -> firewall rules.
 * Safe to call with no VLAN configuration, in which case it falls straight
 * through to fw_check_packet(). */
fw_action_t firex_inspect(firewall_ctx_t *ctx, packet_info_t *pkt,
                          const char *ingress_if, int *rule_id);

/* Pull the Host: header out of a plaintext HTTP request, for block-page
 * context. Returns true when one was found. */
bool firex_extract_http_host(const packet_info_t *pkt, char *out, size_t outlen);

#endif
