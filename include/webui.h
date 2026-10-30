#ifndef FIREX_WEBUI_H
#define FIREX_WEBUI_H

#include <stdbool.h>
#include "blockpage.h"
#include "audit.h"
#include "auth.h"
#include "configstore.h"

/*
 * Admin console. It rides on the block-page HTTP server rather than opening a
 * second listener.
 *
 *   Public
 *     GET  /ui, /ui/vlan.js, /ui/style.css   console shell + login form
 *     POST /api/auth/login                   { username, password }
 *
 *   Any signed-in role
 *     GET  /api/auth/whoami
 *     POST /api/auth/logout
 *     GET  /api/vlans                        VLANs, ports, zone matrix, counters
 *     GET  /api/blockpage/events             recent block events
 *     GET  /api/config/revisions             saved revision history
 *     GET  /api/config/backup                the active config, as text
 *     GET  /api/config/validate              dry-run the active file
 *     GET  /api/state                        kernel connection table
 *     GET  /api/history                      counter history for charting
 *     GET  /api/capture                      capture status
 *     GET  /api/capture/download             the capture, as a pcap file
 *     GET  /api/telemetry                    syslog / NetFlow exporter state
 *
 *   Admin only, and each requires the session's CSRF token in X-FireX-CSRF
 *     PUT  /api/vlans/<vid>                  edit one VLAN
 *     POST /api/zones/matrix                 { from, to, action }
 *     POST /api/config/save                  { note } -> new revision
 *     POST /api/config/apply                 validate + reload + re-provision
 *     POST /api/config/rollback              { revision }
 *     POST /api/config/restore               a whole config file as the body
 *     POST /api/auth/password                { password }
 *     POST /api/capture/start                { iface, host, port, proto, ... }
 *     POST /api/capture/stop
 *
 * The session cookie is HttpOnly and SameSite=Strict but NOT Secure, because
 * the console is served over plain HTTP. On an untrusted network the console
 * should be reached over a tunnel until TLS lands.
 */

/* Owned by the console, initialised from the daemon. */
extern auth_ctx_t g_auth;
extern cfgstore_t g_cfgstore;

/* Loads the user file and opens the config store. Returns 0 on success; the
 * console refuses every write when this has not succeeded. */
int  webui_init(const char *users_path, const char *active_config);

/* Tells the console which file to reload from and whether it may touch the
 * network, so apply/rollback behave the same as the daemon's own startup. */
void webui_set_runtime(const char *active_config, bool apply_net);

/* Where packet captures are written. Set before any capture is started. */
void webui_set_capture_dir(const char *dir);

void webui_attach(blockpage_ctx_t *bp);
void webui_shutdown(void);

/*
 * The administrative trail. Lives in webui.c because that is where the
 * administrators are, and is opened by the daemon so that a record exists
 * from before the console accepts its first request.
 */
extern audit_ctx_t g_audit;

#endif