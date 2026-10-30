#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include "inspect.h"
#include "netutil.h"
#include "brand.h"

vlan_ctx_t      g_vlan;
netconf_ctx_t   g_netconf;
blockpage_ctx_t g_blockpage;
policy_ctx_t    g_policy;
gwmon_ctx_t     g_gwmon;
vpn_ctx_t       g_vpn;
hist_ctx_t      g_hist;
capture_ctx_t   g_capture;
telemetry_ctx_t g_telemetry;
shaper_ctx_t    g_shaper;
portal_ctx_t    g_portal;
ha_ctx_t        g_ha;
ids_ctx_t       g_ids;
feeds_ctx_t     g_feeds;
mw_ctx_t        g_malware;
ag_ctx_t        g_airgap;
response_ctx_t  g_response;

void firex_inspect_enable(firewall_ctx_t *ctx)  { fw_set_inspect_hook(ctx, firex_inspect); }
void firex_inspect_disable(firewall_ctx_t *ctx) { fw_set_inspect_hook(ctx, NULL); }

/* ═══════════ HTTP HOST EXTRACTION ═══════════ */
bool firex_extract_http_host(const packet_info_t *pkt, char *out, size_t outlen) {
    if (!out || !outlen) return false;
    out[0] = '\0';
    if (!pkt->payload || pkt->payload_len < 16) return false;

    const char *p = (const char *)pkt->payload;
    if (strncmp(p, "GET ",  4) && strncmp(p, "POST", 4) &&
        strncmp(p, "HEAD", 4) && strncmp(p, "PUT ", 4) &&
        strncmp(p, "DELE", 4) && strncmp(p, "OPTI", 4))
        return false;

    int n = pkt->payload_len < 1400 ? pkt->payload_len : 1400;
    for (int i = 0; i + 6 < n; i++) {
        if (strncasecmp(p + i, "Host:", 5) != 0) continue;
        int j = i + 5;
        while (j < n && p[j] == ' ') j++;
        size_t k = 0;
        while (j < n && p[j] != '\r' && p[j] != '\n' && k < outlen - 1)
            out[k++] = p[j++];
        out[k] = '\0';
        return k > 0;
    }
    return false;
}

/* ═══════════ VLAN CONTEXT RESOLUTION ═══════════
 * Fills in the PVID for untagged frames, resolves the security zone, and
 * flags a tag that the ingress port is not allowed to carry (VLAN hopping).
 */
static void resolve_vlan_context(packet_info_t *pkt, const char *ingress_if) {
    port_config_t *port = port_get(&g_vlan, ingress_if);

    if (pkt->is_tagged) {
        g_vlan.tagged_rx++;
        if (port && !port_vlan_permitted(port, pkt->vlan_id)) {
            g_vlan.vlan_violations++;
            pkt->vlan_violation = true;
        }
    } else {
        g_vlan.untagged_rx++;
        pkt->vlan_id = port ? port->pvid : 0;
    }

    vlan_config_t *vl = vlan_get(&g_vlan, pkt->vlan_id);
    pkt->zone = vl ? vl->zone : (port ? port->zone : ZONE_WAN);

    /*
     * Traffic arriving over a tunnel carries no VLAN tag and its ingress
     * interface is not a configured port, so without this it would land in
     * ZONE_WAN and be governed by the wrong row of the matrix. Ask the peer
     * table which zone claims the source address instead.
     */
    if (!vl && pkt->has_ip) {
        zone_t vz = vpn_zone_for(&g_vpn, pkt->src_ip);
        if (vz != ZONE_MAX) pkt->zone = vz;
    }

    /*
     * A host under automatic response is evaluated as QUARANTINE regardless
     * of where it actually sits. That is what makes the zone mean something:
     * what a quarantined host may still reach is the operator's row of the
     * forwarding matrix, not a rule hardcoded in the response engine.
     */
    if (pkt->has_ip) {
        zone_t qz = response_zone_for(&g_response, pkt->src_ip);
        if (qz != ZONE_MAX) pkt->zone = qz;
    }
}

/* Which configured VLAN owns this destination address, if any. */
static vlan_config_t *vlan_for_address(uint32_t ip) {
    for (int i = 0; i < g_vlan.vlan_count; i++) {
        vlan_config_t *c = &g_vlan.vlans[i];
        if (c->enabled && c->subnet && c->netmask &&
            (ip & c->netmask) == (c->subnet & c->netmask))
            return c;
    }
    return NULL;
}

/* Serve the branded page for plaintext HTTP so the user sees why. */
static void maybe_serve_block_page(packet_info_t *pkt, vlan_config_t *vl,
                                   const char *rid) {
    if (!vl || !vl->show_block_page) return;
    if (pkt->dst_port != 80 || pkt->payload_len <= 0) return;
    if (!vl->gateway) return;

    char portal[INET_ADDRSTRLEN];
    fx_ip_str(vl->gateway, portal, sizeof(portal));

    blockpage_inject_redirect(pkt->src_ip, pkt->src_port,
                              pkt->dst_ip, pkt->dst_port,
                              pkt->tcp_seq + (uint32_t)pkt->payload_len,
                              pkt->tcp_ack, portal, rid);
}

/* ═══════════════════════════════════════════════════════════
 *  FULL INSPECTION PIPELINE
 *
 *  Stages 3 and 5 in the original design (IDS/Suricata signature matching
 *  and payload malware scanning) are not present: those subsystems have not
 *  been built. The call sites are marked below so they can be dropped in
 *  without reshaping the pipeline, and the per-VLAN ips_enabled /
 *  malware_scan flags gate it.
 * ═══════════════════════════════════════════════════════════ */
fw_action_t firex_inspect(firewall_ctx_t *ctx, packet_info_t *pkt,
                          const char *ingress_if, int *rule_id) {
    char reason[256] = "";
    char policy_id[32];
    char host[256];

    /* No segmentation configured: behave exactly like the plain engine. */
    if (g_vlan.vlan_count == 0 && g_vlan.port_count == 0)
        return fw_check_packet(ctx, pkt, rule_id);

    resolve_vlan_context(pkt, ingress_if);

    vlan_config_t *vl = vlan_get(&g_vlan, pkt->vlan_id);
    const char *vlan_name = vl ? vl->name : "-";

    /* ── 0. VLAN membership violation (tag spoofing / VLAN hopping) ── */
    if (pkt->vlan_violation) {
        snprintf(policy_id, sizeof(policy_id), "%s-VLANVIO", BRAND_POLICY_PREFIX);
        snprintf(reason, sizeof(reason),
                 "VLAN %u not permitted on ingress port %s (possible VLAN hopping)",
                 pkt->vlan_id, ingress_if ? ingress_if : "?");
        blockpage_record(&g_blockpage, pkt->src_ip, pkt->vlan_id, vlan_name,
                         zone_name(pkt->zone), "", BLK_VLAN_ACL,
                         policy_id, reason, 4);
        if (vl) vl->blocked_packets++;
        *rule_id = -10;
        return ACTION_BLOCK;
    }

    /* ── 0.5 Air gap ──
     *
     * Before everything else, because when the gap is shut the answer
     * does not depend on any of it. An isolated appliance that still ran
     * signature matching on traffic it was about to drop would be paying
     * for an answer it had already made.
     */
    if (pkt->has_ip && g_airgap.mode != AG_CONNECTED) {
        zone_t dst_zone = ZONE_WAN;
        vlan_config_t *dz = vlan_for_address(pkt->dst_ip);
        if (dz) {
            dst_zone = dz->zone;
        } else {
            zone_t vz = vpn_zone_for(&g_vpn, pkt->dst_ip);
            if (vz != ZONE_MAX) dst_zone = vz;
        }

        ag_cross_t cross = airgap_classify(pkt->zone, dst_zone);
        char ag_reason[AG_REASON_LEN];
        if (airgap_verdict(&g_airgap, cross, pkt->timestamp,
                           ag_reason, sizeof(ag_reason)) == AG_DENY) {
            firex_extract_http_host(pkt, host, sizeof(host));
            snprintf(policy_id, sizeof(policy_id), "%s-AIRGAP", BRAND_POLICY_PREFIX);
            const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                 pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                 host, BLK_POLICY, policy_id, ag_reason, 2);
            maybe_serve_block_page(pkt, vl, rid);
            if (vl) vl->blocked_packets++;
            *rule_id = -16;
            return ACTION_BLOCK;
        }
    }

    /* ── 1. Inter-VLAN / zone forwarding policy ── */
    if (pkt->has_ip) {
        vlan_config_t *dvl = vlan_for_address(pkt->dst_ip);
        uint16_t dst_vid = dvl ? dvl->vlan_id : 0;

        /* No VLAN owns the destination. If a tunnel does, the zone matrix
         * still has to decide -- otherwise traffic into a VPN would skip
         * forwarding policy entirely. */
        zone_t dst_vpn_zone = ZONE_MAX;
        if (!dst_vid) dst_vpn_zone = vpn_zone_for(&g_vpn, pkt->dst_ip);

        if (!dst_vid && dst_vpn_zone != ZONE_MAX) {
            ivr_action_t a = vlan_check_zones(&g_vlan, pkt->zone, dst_vpn_zone,
                                              reason, sizeof(reason));
            if (a == IVR_DENY || a == IVR_LOG_DENY) {
                firex_extract_http_host(pkt, host, sizeof(host));
                snprintf(policy_id, sizeof(policy_id), "%s-VPN", BRAND_POLICY_PREFIX);
                const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                     pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                     host, BLK_ZONE, policy_id, reason, 2);
                maybe_serve_block_page(pkt, vl, rid);
                if (vl) vl->blocked_packets++;
                *rule_id = -12;
                return ACTION_BLOCK;
            }
        }

        if (dst_vid) {
            ivr_action_t a = vlan_check_forward(&g_vlan, pkt->vlan_id, dst_vid,
                                                pkt->src_ip, pkt->dst_ip,
                                                pkt->dst_port, pkt->protocol,
                                                reason, sizeof(reason));
            if (a == IVR_DENY || a == IVR_LOG_DENY) {
                firex_extract_http_host(pkt, host, sizeof(host));
                snprintf(policy_id, sizeof(policy_id), "%s-SEG", BRAND_POLICY_PREFIX);

                const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                     pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                     host, BLK_VLAN_ACL, policy_id, reason, 2);
                maybe_serve_block_page(pkt, vl, rid);

                if (vl) vl->blocked_packets++;
                *rule_id = -11;
                return ACTION_BLOCK;
            }
        }
    }

    /* ── 2. Blocklist feeds ──
     * Cheaper than anything below it: a binary search over merged ranges,
     * so it runs before the signature engine rather than after. */
    if (pkt->has_ip && g_feeds.enabled) {
        bool src_bad = feeds_match_ip(&g_feeds, pkt->src_ip);
        bool dst_bad = !src_bad && feeds_match_ip(&g_feeds, pkt->dst_ip);

        if (src_bad || dst_bad) {
            firex_extract_http_host(pkt, host, sizeof(host));
            snprintf(policy_id, sizeof(policy_id), "%s-FEED", BRAND_POLICY_PREFIX);
            snprintf(reason, sizeof(reason),
                     "%s address is on a blocklist",
                     src_bad ? "source" : "destination");

            const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                 pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                 host, BLK_C2, policy_id, reason, 3);
            maybe_serve_block_page(pkt, vl, rid);

            if (src_bad)
                response_record(&g_response, pkt->src_ip, 3,
                                "source on a blocklist");
            if (vl) vl->blocked_packets++;
            *rule_id = -13;
            return ACTION_BLOCK;
        }

        /* A name in a DNS blocklist, read from the request itself. */
        if (firex_extract_http_host(pkt, host, sizeof(host)) &&
            feeds_match_domain(&g_feeds, host)) {
            snprintf(policy_id, sizeof(policy_id), "%s-DNSBL", BRAND_POLICY_PREFIX);
            /* A Host: header is attacker-controlled and can be long; bound
             * it so the explanation survives rather than the hostname. */
            snprintf(reason, sizeof(reason),
                     "'%.200s' is on a domain blocklist", host);

            const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                 pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                 host, BLK_CATEGORY, policy_id, reason, 2);
            maybe_serve_block_page(pkt, vl, rid);

            if (vl) vl->blocked_packets++;
            *rule_id = -14;
            return ACTION_BLOCK;
        }
    }

    /* ── 3. Signature matching ──
     *
     * Runs before the firewall rules, not after: a signature that says drop
     * should win over a rule that says allow. Scanning only what the rules
     * already permitted would save work and let a known exploit through an
     * open port, which is the wrong trade.
     *
     * One scan serves both switches. With ips_enabled the whole ruleset
     * applies; with only malware_scan, just the malware and C2 classes do.
     */
    if (pkt->payload && pkt->payload_len > 0 && g_ids.enabled && vl &&
        (vl->ips_enabled || vl->malware_scan)) {

        ids_hit_t hits[8];
        int n = ids_scan(&g_ids, pkt->payload, pkt->payload_len,
                         pkt->protocol, pkt->src_port, pkt->dst_port,
                         hits, 8);

        if (!vl->ips_enabled) {
            /* Keep only what malware_scan covers. */
            int keep = 0;
            for (int i = 0; i < n; i++)
                if (hits[i].cls == SIG_CLASS_MALWARE || hits[i].cls == SIG_CLASS_C2)
                    hits[keep++] = hits[i];
            n = keep;
        }

        if (n > 0) {
            sig_action_t act = ids_verdict(&g_ids, hits, n);
            firex_extract_http_host(pkt, host, sizeof(host));

            snprintf(policy_id, sizeof(policy_id), "%s-SID%d",
                     BRAND_POLICY_PREFIX, hits[0].sid);
            snprintf(reason, sizeof(reason), "%s (sid %d, %s)",
                     hits[0].msg, hits[0].sid, sig_class_name(hits[0].cls));

            block_reason_t br =
                hits[0].cls == SIG_CLASS_MALWARE ? BLK_MALWARE :
                hits[0].cls == SIG_CLASS_C2      ? BLK_C2      :
                hits[0].cls == SIG_CLASS_EXPLOIT ? BLK_INTRUSION :
                                                   BLK_POLICY;

            const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                 pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                 host, br, policy_id, reason, hits[0].severity);

            response_record(&g_response, pkt->src_ip, hits[0].severity,
                            hits[0].msg);

            if (act != SIG_ALERT) {
                g_ids.dropped++;
                if (act == SIG_REJECT) maybe_serve_block_page(pkt, vl, rid);
                if (vl) vl->blocked_packets++;
                *rule_id = -15;
                return ACTION_BLOCK;
            }
            /* alert: recorded, and the packet carries on. */
        }
    }

    /* ── 3.5 Live malware protection ──
     *
     * Runs after the per-packet signatures and before the rules, for the
     * same reason they do: a file identified as malware should not be
     * saved by a rule that allows the port it arrived on.
     *
     * Unlike the signature scan this one is stateful -- it only answers
     * once the object is complete -- so the overwhelming majority of
     * packets return MW_CLEAN having only been buffered.
     */
    if (pkt->payload && pkt->payload_len > 0 && g_malware.enabled && vl &&
        vl->malware_scan) {

        mw_event_t ev;
        mw_verdict_t v = mw_scan_packet(&g_malware, pkt, &ev);

        if (v != MW_CLEAN) {
            firex_extract_http_host(pkt, host, sizeof(host));
            snprintf(policy_id, sizeof(policy_id), "%s-MW", BRAND_POLICY_PREFIX);
            snprintf(reason, sizeof(reason), "%s (%s match, %zu bytes)",
                     ev.name, mw_source_name(ev.source), ev.size);

            const char *rid = blockpage_record(&g_blockpage, pkt->src_ip,
                                 pkt->vlan_id, vlan_name, zone_name(pkt->zone),
                                 host, BLK_MALWARE, policy_id, reason,
                                 ev.severity);

            response_record(&g_response, pkt->src_ip, ev.severity, ev.name);

            if (v == MW_BLOCK) {
                maybe_serve_block_page(pkt, vl, rid);
                if (vl) vl->blocked_packets++;
                *rule_id = -17;
                return ACTION_BLOCK;
            }
        }
    }

    /* ── 3. Standard firewall rules ── */
    fw_action_t action = fw_check_packet(ctx, pkt, rule_id);
    if (action == ACTION_BLOCK) {
        firex_extract_http_host(pkt, host, sizeof(host));
        snprintf(policy_id, sizeof(policy_id), "%s-%04d",
                 BRAND_POLICY_PREFIX, *rule_id);
        const char *rid = blockpage_record(&g_blockpage, pkt->src_ip, pkt->vlan_id,
                             vlan_name, zone_name(pkt->zone), host, BLK_POLICY,
                             policy_id, "Firewall rule match", 2);
        maybe_serve_block_page(pkt, vl, rid);

        if (vl) vl->blocked_packets++;
        return ACTION_BLOCK;
    }

    /* Payload scanning happens at step 3 above, before the rules rather than
     * after them, for the reason given there. */

    if (vl) {
        vl->rx_packets++;
        vl->rx_bytes += (unsigned long)pkt->total_len;
    }
    return action;
}
