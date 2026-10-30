#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "blockpage.h"
#include "shellcmd.h"
#include "netutil.h"

static const char *REASON_TITLE[BLK_MAX] = {
    "Malware Detected",
    "Phishing Site Blocked",
    "Command &amp; Control Traffic",
    "Intrusion Attempt Blocked",
    "Security Policy Violation",
    "Content Category Restricted",
    "Network Segment Access Denied",
    "Zone Policy Enforcement",
    "Geographic Restriction",
    "Rate Limit Exceeded",
    "Device Quarantined",
    "Data Loss Prevention"
};

static const char *REASON_ICON[BLK_MAX] = {
    "&#9888;", "&#128997;", "&#128272;", "&#128737;",
    "&#128683;", "&#127918;", "&#128279;", "&#9937;",
    "&#127758;", "&#9201;", "&#9763;", "&#128194;"
};

static const char *REASON_DESC[BLK_MAX] = {
    "The requested resource was found to contain malicious code and has been intercepted before reaching your device.",
    "This destination is a known credential-harvesting site. Your connection has been terminated for your protection.",
    "This connection matched a known malware command-and-control channel. The session was severed immediately.",
    "An exploitation attempt was detected within this traffic stream and neutralised in-line.",
    "Your organisation's acceptable-use policy prohibits access to this resource.",
    "This destination belongs to a content category that is restricted on your network segment.",
    "Your network segment is not permitted to communicate with the requested destination segment.",
    "Inter-zone traffic policy denies this communication path.",
    "Connections to or from this geographic region are restricted by policy.",
    "Your device exceeded the permitted connection rate and has been temporarily throttled.",
    "This device has been isolated pending security review. Contact your administrator.",
    "The transmission contained data classified as sensitive and was prevented from leaving the network."
};

const char *blockpage_reason_title(block_reason_t r) {
    return ((unsigned)r < BLK_MAX) ? REASON_TITLE[r] : "Access Blocked";
}

/* ═══════════ OUTPUT BUFFER ═══════════ */
typedef struct { char *p; size_t left; bool overflow; } sink_t;

static void put(sink_t *s, const char *str) {
    size_t n = strlen(str);
    if (n >= s->left) { s->overflow = true; n = s->left ? s->left - 1 : 0; }
    memcpy(s->p, str, n);
    s->p += n; s->left -= n; *s->p = '\0';
}

static void putf(sink_t *s, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s->p, s->left, fmt, ap);
    va_end(ap);
    if (n < 0) { s->overflow = true; return; }
    if ((size_t)n >= s->left) { s->overflow = true; n = (int)s->left - 1; }
    s->p += n; s->left -= (size_t)n;
}

/* The Host header and URL come straight off the wire, so everything that
 * reaches the page has to be escaped or a hostile site could script into it. */
static void html_escape(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    if (!outlen) return;
    for (const unsigned char *p = (const unsigned char *)(in ? in : ""); *p; p++) {
        const char *rep = NULL;
        char one[2] = { (char)*p, 0 };
        switch (*p) {
            case '&':  rep = "&amp;";  break;
            case '<':  rep = "&lt;";   break;
            case '>':  rep = "&gt;";   break;
            case '"':  rep = "&quot;"; break;
            case '\'': rep = "&#39;";  break;
            default:
                /* drop control characters rather than emit raw bytes */
                rep = (*p < 0x20 || *p == 0x7f) ? "" : one;
        }
        size_t rl = strlen(rep);
        if (o + rl >= outlen - 1) break;
        memcpy(out + o, rep, rl);
        o += rl;
    }
    out[o] = '\0';
}

/* ═══════════ EVENT RECORDING ═══════════ */
static void gen_request_id(char *out) {
    static const char hex[] = "0123456789ABCDEF";
    unsigned char r[8];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(r, 1, sizeof(r), f) != sizeof(r)) {
        for (size_t i = 0; i < sizeof(r); i++) r[i] = (unsigned char)(rand() & 0xFF);
    }
    if (f) fclose(f);
    for (int i = 0; i < 8; i++) {
        out[i*2]   = hex[r[i] >> 4];
        out[i*2+1] = hex[r[i] & 0xF];
    }
    out[16] = '\0';
}

const char *blockpage_record(blockpage_ctx_t *bp, uint32_t client_ip,
                             uint16_t vlan_id, const char *vlan_name,
                             const char *zone, const char *host,
                             block_reason_t reason, const char *policy_id,
                             const char *detail, int severity) {
    pthread_mutex_lock(&bp->lock);

    int idx = bp->event_idx % MAX_BLOCK_EVENTS;
    block_event_t *e = &bp->events[idx];
    memset(e, 0, sizeof(*e));

    gen_request_id(e->request_id);
    e->timestamp = time(NULL);
    e->client_ip = client_ip;
    e->vlan_id   = vlan_id;
    e->reason    = reason;
    e->severity  = severity;

    if (vlan_name) snprintf(e->vlan_name, sizeof(e->vlan_name), "%s", vlan_name);
    if (zone)      snprintf(e->zone,      sizeof(e->zone),      "%s", zone);
    if (host)      snprintf(e->host,      sizeof(e->host),      "%s", host);
    if (policy_id) snprintf(e->policy_id, sizeof(e->policy_id), "%s", policy_id);
    if (detail)    snprintf(e->detail,    sizeof(e->detail),    "%s", detail);

    bp->event_idx++;
    if (bp->event_count < MAX_BLOCK_EVENTS) bp->event_count++;

    const char *rid = e->request_id;
    pthread_mutex_unlock(&bp->lock);
    return rid;
}

/* Callers hold bp->lock. */
static block_event_t *find_event(blockpage_ctx_t *bp, const char *rid) {
    for (int i = 0; i < bp->event_count; i++)
        if (strcmp(bp->events[i].request_id, rid) == 0) return &bp->events[i];
    return NULL;
}

static block_event_t *latest_for_ip(blockpage_ctx_t *bp, uint32_t ip) {
    block_event_t *best = NULL;
    for (int i = 0; i < bp->event_count; i++)
        if (bp->events[i].client_ip == ip &&
            (!best || bp->events[i].timestamp > best->timestamp))
            best = &bp->events[i];
    return best;
}

/* ═══════════ HTML RENDERER ═══════════
 * The stylesheet is built by compile-time concatenation of the BRAND_COLOR_*
 * literals, so there is no format string holding CSS percent signs and no
 * argument list to keep in step. Only the dynamic values go through putf().
 */
static const char *PAGE_CSS =
"*{margin:0;padding:0;box-sizing:border-box}"
"body{font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;"
"background:radial-gradient(1200px 600px at 50% -10%,#1b2030 0%," BRAND_COLOR_DARK " 60%);"
"color:" BRAND_COLOR_TEXT ";min-height:100vh;display:flex;align-items:center;"
"justify-content:center;padding:24px}"
".shell{max-width:720px;width:100%}"
".brandbar{display:flex;align-items:center;gap:12px;margin-bottom:22px}"
".brandbar .nm{font-size:20px;font-weight:800;letter-spacing:-.4px}"
".brandbar .nm span{background:linear-gradient(135deg," BRAND_COLOR_PRIMARY "," BRAND_COLOR_SECONDARY ");"
"-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}"
".brandbar .tag{font-size:11px;color:" BRAND_COLOR_MUTED ";letter-spacing:2.4px;"
"text-transform:uppercase;margin-top:2px}"
".card{background:" BRAND_COLOR_PANEL ";border:1px solid #1E2736;border-radius:18px;"
"overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,.55)}"
".stripe{height:4px;background:linear-gradient(90deg," BRAND_COLOR_PRIMARY "," BRAND_COLOR_SECONDARY ")}"
".body{padding:40px}"
".icon{font-size:56px;line-height:1;margin-bottom:18px}"
"h1{font-size:27px;font-weight:800;margin-bottom:10px;letter-spacing:-.5px}"
".sev{display:inline-block;padding:4px 11px;border-radius:999px;font-size:10px;"
"font-weight:800;letter-spacing:1.4px;margin-bottom:16px}"
".desc{color:" BRAND_COLOR_MUTED ";font-size:15px;line-height:1.65;margin-bottom:26px}"
".target{background:#0C1119;border:1px solid #1E2736;border-radius:11px;"
"padding:14px 16px;margin-bottom:24px;font-family:ui-monospace,Menlo,monospace;"
"font-size:13px;word-break:break-all;color:" BRAND_COLOR_TEXT "}"
".target b{color:" BRAND_COLOR_MUTED ";font-weight:600;display:block;font-size:10px;"
"letter-spacing:1.3px;text-transform:uppercase;margin-bottom:5px;font-family:inherit}"
".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));"
"gap:1px;background:#1E2736;border:1px solid #1E2736;border-radius:11px;"
"overflow:hidden;margin-bottom:26px}"
".cell{background:#0E131C;padding:14px 16px}"
".cell .k{font-size:10px;color:" BRAND_COLOR_MUTED ";letter-spacing:1.3px;"
"text-transform:uppercase;margin-bottom:5px}"
".cell .v{font-size:13.5px;font-weight:600;font-family:ui-monospace,Menlo,monospace;"
"word-break:break-all}"
".actions{display:flex;gap:10px;flex-wrap:wrap}"
".btn{padding:11px 20px;border-radius:10px;border:none;font-size:14px;font-weight:650;"
"cursor:pointer;text-decoration:none;display:inline-block;transition:.18s}"
".btn.p{background:linear-gradient(135deg," BRAND_COLOR_PRIMARY "," BRAND_COLOR_SECONDARY ");color:#fff}"
".btn.p:hover{filter:brightness(1.12);transform:translateY(-1px)}"
".btn.s{background:#18202E;color:" BRAND_COLOR_TEXT ";border:1px solid #27324A}"
".btn.s:hover{background:#1F2938}"
".foot{border-top:1px solid #1E2736;padding:18px 40px;display:flex;"
"justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;"
"font-size:11.5px;color:" BRAND_COLOR_MUTED ";background:#0C1119}"
".foot a{color:" BRAND_COLOR_PRIMARY ";text-decoration:none}"
".rid{font-family:ui-monospace,Menlo,monospace;letter-spacing:.6px}"
"#ovmsg{margin-top:14px;font-size:13px;color:" BRAND_COLOR_SUCCESS ";display:none}"
"@media(max-width:560px){.body{padding:28px 22px}.foot{padding:16px 22px}h1{font-size:22px}}";

static int render_block_page(blockpage_ctx_t *bp, block_event_t *e,
                             char *out, size_t outlen) {
    sink_t s = { out, outlen, false };

    char timestr[64] = "-";
    char clientip[INET_ADDRSTRLEN] = "unknown";
    char host_esc[1024], vlan_esc[128], zone_esc[64], pol_esc[128];

    const char *title = blockpage_reason_title(e->reason);
    const char *icon  = ((unsigned)e->reason < BLK_MAX) ? REASON_ICON[e->reason] : "&#128683;";
    const char *desc  = ((unsigned)e->reason < BLK_MAX) ? REASON_DESC[e->reason]
                        : "This request was blocked by network security policy.";

    struct tm tmb;
    localtime_r(&e->timestamp, &tmb);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %Z", &tmb);
    fx_ip_str(e->client_ip, clientip, sizeof(clientip));

    html_escape(e->host[0]      ? e->host      : "-", host_esc, sizeof(host_esc));
    html_escape(e->vlan_name[0] ? e->vlan_name : "-", vlan_esc, sizeof(vlan_esc));
    html_escape(e->zone[0]      ? e->zone      : "-", zone_esc, sizeof(zone_esc));
    html_escape(e->policy_id[0] ? e->policy_id : "-", pol_esc,  sizeof(pol_esc));

    int sev = e->severity;
    const char *sevlabel = sev >= 4 ? "CRITICAL" : sev == 3 ? "HIGH"
                         : sev == 2 ? "MEDIUM"   : "LOW";
    const char *sevcolor = sev >= 3 ? BRAND_COLOR_DANGER
                         : sev == 2 ? BRAND_COLOR_WARNING : BRAND_COLOR_MUTED;

    put(&s, "<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='robots' content='noindex,nofollow'>"
            "<title>Blocked &middot; " BRAND_FULL "</title><style>");
    put(&s, PAGE_CSS);
    put(&s, "</style></head><body><div class='shell'>");

    /* Brand bar */
    put(&s, "<div class='brandbar'>");
    if (bp->show_logo) put(&s, BRAND_LOGO_SVG);
    put(&s, "<div><div class='nm'>" BRAND_PRODUCT " by <span>" BRAND_VENDOR
            "</span></div><div class='tag'>" BRAND_TAGLINE "</div></div></div>");

    /* Card */
    put(&s, "<div class='card'><div class='stripe'></div><div class='body'>");
    putf(&s, "<div class='icon'>%s</div>", icon);
    putf(&s, "<div class='sev' style='background:%s22;color:%s;border:1px solid %s55'>"
             "%s SEVERITY</div>", sevcolor, sevcolor, sevcolor, sevlabel);
    putf(&s, "<h1>%s</h1><p class='desc'>%s</p>", title, desc);
    putf(&s, "<div class='target'><b>Requested Destination</b>%s</div>", host_esc);

    put(&s, "<div class='grid'>");
    putf(&s, "<div class='cell'><div class='k'>Policy Reference</div>"
             "<div class='v'>%s</div></div>", pol_esc);
    putf(&s, "<div class='cell'><div class='k'>Network Segment</div>"
             "<div class='v'>%s (VLAN %u)</div></div>", vlan_esc, e->vlan_id);
    putf(&s, "<div class='cell'><div class='k'>Security Zone</div>"
             "<div class='v'>%s</div></div>", zone_esc);
    putf(&s, "<div class='cell'><div class='k'>Source Address</div>"
             "<div class='v'>%s</div></div>", clientip);
    putf(&s, "<div class='cell'><div class='k'>Timestamp</div>"
             "<div class='v'>%s</div></div>", timestr);
    putf(&s, "<div class='cell'><div class='k'>Request ID</div>"
             "<div class='v rid'>%s</div></div>", e->request_id);
    put(&s, "</div>");

    /* Actions */
    put(&s, "<div class='actions'>"
            "<a href='javascript:history.back()' class='btn p'>&larr; Return to Safety</a>");
    if (bp->allow_override)
        put(&s, "<button id='ovbtn' class='btn s'>Request Access</button>");
    /*
     * Only the contact routes that actually exist. An empty value in
     * brand.h means "not configured", not "render it anyway": a dead
     * mailto: or a placeholder phone number on the page a blocked user
     * is staring at is worse than no button, because they will try it.
     *
     * admin_contact comes from the configuration file, so it is escaped
     * before it goes anywhere near an attribute -- operator-supplied is
     * not the same as trusted, and this page already escapes everything
     * else it renders.
     */
    {
        const char *mail = bp->admin_contact[0] ? bp->admin_contact
                                                : BRAND_SUPPORT_EMAIL;
        if (mail[0]) {
            char mail_esc[256];
            html_escape(mail, mail_esc, sizeof(mail_esc));
            putf(&s, "<a href='mailto:%s?subject=" BRAND_PRODUCT
                     "%%20Block%%20Review%%20-%%20%s' "
                     "class='btn s'>Contact Security Team</a>",
                 mail_esc, e->request_id);
        }
        if (sizeof(BRAND_SUPPORT_URL) > 1)
            put(&s, "<a href='" BRAND_SUPPORT_URL "' target='_blank' "
                    "rel='noopener noreferrer' class='btn s'>Support</a>");
        if (sizeof(BRAND_SUPPORT_PHONE) > 1)
            put(&s, "<a href='tel:" BRAND_SUPPORT_PHONE "' class='btn s'>"
                    "Call " BRAND_SUPPORT_PHONE "</a>");
    }
    put(&s, "</div>");

    putf(&s, "<div id='ovmsg'>&#10003; Access request submitted. Reference "
             "<b>%s</b> &mdash; your administrator has been notified.</div>",
         e->request_id);
    put(&s, "</div>");

    /* Footer */
    putf(&s, "<div class='foot'><div>Protected by <b>%s</b> &middot; "
             BRAND_FULL " v" BRAND_VERSION "</div><div>",
         bp->org_name[0] ? bp->org_name : BRAND_VENDOR);
    /* Same rule in the footer: no documentation site, no link to one. */
    if (sizeof(BRAND_DOC_URL) > 1)
        put(&s, "<a href='" BRAND_DOC_URL "' target='_blank' "
                "rel='noopener noreferrer'>Security Documentation</a> &middot; ");
    putf(&s, "<span class='rid'>%s</span></div></div></div></div>",
         e->request_id);

    /* The request id is hex from our own generator, so it is safe to inline. */
    if (bp->allow_override)
        putf(&s, "<script>document.getElementById('ovbtn')"
                 ".addEventListener('click',function(){"
                 "fetch('/override?rid=%s',{method:'POST'}).catch(function(){});"
                 "document.getElementById('ovmsg').style.display='block';"
                 "this.style.display='none';});</script>", e->request_id);

    put(&s, "</body></html>");

    if (s.overflow)
        fprintf(stderr, "[%s] block page truncated\n", BRAND_PRODUCT);

    return (int)(outlen - s.left);
}


/* ═══════════ TLS ═══════════
 *
 * Only the console listener is wrapped. See blockpage.h for why the portal
 * is not.
 */

/*
 * The connection this thread is serving. The server is thread-per-
 * connection and a thread serves exactly one, so thread-local storage is
 * the whole of the bookkeeping -- no map, no lock, and nothing to leak
 * between requests as long as bp_client clears it on the way out, which it
 * does unconditionally.
 */
static __thread SSL *t_ssl;

ssize_t bp_write(int fd, const void *buf, size_t len) {
    if (!t_ssl) return write(fd, buf, len);

    /*
     * SSL_write is all-or-nothing for the length it is given, but a
     * partial write is still possible on a non-blocking socket. These are
     * blocking, so a short count means a real error; looping on the
     * remainder costs nothing and removes the assumption.
     */
    const unsigned char *p = buf;
    size_t done = 0;
    while (done < len) {
        int n = SSL_write(t_ssl, p + done, (int)(len - done));
        if (n <= 0) return done ? (ssize_t)done : -1;
        done += (size_t)n;
    }
    return (ssize_t)done;
}

ssize_t bp_read(int fd, void *buf, size_t len) {
    if (!t_ssl) return read(fd, buf, len);
    int n = SSL_read(t_ssl, buf, (int)len);
    return n > 0 ? (ssize_t)n : (n == 0 ? 0 : -1);
}

bool blockpage_tls_active(const blockpage_ctx_t *bp) {
    return bp && bp->tls_enabled && bp->tls_ctx;
}

static void tls_fingerprint(X509 *crt, char *out, size_t outlen) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  n = 0;
    out[0] = 0;
    if (!X509_digest(crt, EVP_sha256(), md, &n)) return;

    size_t o = 0;
    for (unsigned int i = 0; i < n && o + 3 < outlen; i++)
        o += (size_t)snprintf(out + o, outlen - o, "%s%02X", i ? ":" : "", md[i]);
}

/*
 * Write a self-signed certificate and its key.
 *
 * Done in C rather than by shelling out to `openssl req` so that the
 * console cannot be left unreachable by a missing CLI in a slimmed image,
 * and so the key file's mode is set before the key is in it rather than
 * after -- a chmod that follows the write leaves a window in which the
 * private key is world-readable.
 */
static int tls_self_sign(const char *cert_path, const char *key_path,
                         const char *cn) {
    EVP_PKEY *pkey = EVP_RSA_gen(3072);
    if (!pkey) return -1;

    X509 *crt = X509_new();
    if (!crt) { EVP_PKEY_free(pkey); return -1; }

    X509_set_version(crt, 2);                       /* v3 */

    /* A random 64-bit serial: two appliances generating on the same second
     * must not produce the same one. */
    unsigned char ser[8];
    if (RAND_bytes(ser, sizeof(ser)) != 1) { X509_free(crt); EVP_PKEY_free(pkey); return -1; }
    ser[0] &= 0x7f;                                 /* keep it positive */
    BIGNUM *bn = BN_bin2bn(ser, sizeof(ser), NULL);
    ASN1_INTEGER *ai = BN_to_ASN1_INTEGER(bn, NULL);
    X509_set_serialNumber(crt, ai);
    ASN1_INTEGER_free(ai);
    BN_free(bn);

    X509_gmtime_adj(X509_getm_notBefore(crt), 0);
    /* Ten years. A console certificate the operator has pinned by
     * fingerprint should not expire during the appliance's service life
     * and lock them out of the box that would let them replace it. */
    X509_gmtime_adj(X509_getm_notAfter(crt), 60L * 60 * 24 * 3652);
    X509_set_pubkey(crt, pkey);

    X509_NAME *name = X509_get_subject_name(crt);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                               (const unsigned char *)BRAND_VENDOR, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                               (const unsigned char *)BRAND_PRODUCT " console", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(crt, name);                /* self-signed */

    /*
     * Modern browsers ignore CN entirely and read subjectAltName, so a
     * certificate without one is rejected outright rather than merely
     * warned about. Both the hostname and the loopback address are listed
     * because the console is reached either way during setup.
     */
    char san[256];
    snprintf(san, sizeof(san), "DNS:%s,DNS:localhost,IP:127.0.0.1", cn);
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, crt, crt, NULL, NULL, 0);
    struct { const char *nid; const char *val; } ext[] = {
        { "subjectAltName",     san },
        { "basicConstraints",   "critical,CA:FALSE" },
        { "keyUsage",           "critical,digitalSignature,keyEncipherment" },
        { "extendedKeyUsage",   "serverAuth" },
    };
    for (size_t i = 0; i < sizeof(ext) / sizeof(ext[0]); i++) {
        X509_EXTENSION *e = X509V3_EXT_conf(NULL, &v3, (char *)ext[i].nid,
                                            (char *)ext[i].val);
        if (e) { X509_add_ext(crt, e, -1); X509_EXTENSION_free(e); }
    }

    if (!X509_sign(crt, pkey, EVP_sha256())) {
        X509_free(crt); EVP_PKEY_free(pkey); return -1;
    }

    /* Key first, and created 0600 by open() rather than chmod()ed after. */
    int kfd = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (kfd < 0) { X509_free(crt); EVP_PKEY_free(pkey); return -1; }
    FILE *kf = fdopen(kfd, "w");
    if (!kf) { close(kfd); X509_free(crt); EVP_PKEY_free(pkey); return -1; }
    int okk = PEM_write_PrivateKey(kf, pkey, NULL, NULL, 0, NULL, NULL);
    fflush(kf);
    fsync(fileno(kf));
    fclose(kf);

    FILE *cf = fopen(cert_path, "w");
    int okc = 0;
    if (cf) {
        okc = PEM_write_X509(cf, crt);
        fflush(cf);
        fsync(fileno(cf));
        fclose(cf);
        chmod(cert_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    }

    X509_free(crt);
    EVP_PKEY_free(pkey);
    return (okk && okc) ? 0 : -1;
}

int blockpage_set_tls(blockpage_ctx_t *bp, const char *cert, const char *key) {
    if (!bp || !cert || !*cert || !key || !*key) return -1;

    snprintf(bp->tls_cert, sizeof(bp->tls_cert), "%s", cert);
    snprintf(bp->tls_key,  sizeof(bp->tls_key),  "%s", key);

    bool have_cert = access(cert, R_OK) == 0;
    bool have_key  = access(key,  R_OK) == 0;

    if (!have_cert || !have_key) {
        char cn[128];
        if (gethostname(cn, sizeof(cn)) != 0 || !cn[0])
            snprintf(cn, sizeof(cn), BRAND_HOSTNAME);
        cn[sizeof(cn) - 1] = 0;

        printf("[%s] console: generating a self-signed certificate for '%s'\n",
               BRAND_PRODUCT, cn);
        if (tls_self_sign(cert, key, cn) != 0) {
            fprintf(stderr, "[%s] console: could not generate a certificate "
                    "(%s); the console will serve in the CLEAR\n",
                    BRAND_PRODUCT, strerror(errno));
            return -1;
        }
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "[%s] console: no TLS context; serving in the CLEAR\n",
                BRAND_PRODUCT);
        return -1;
    }

    /*
     * TLS 1.2 is the floor. 1.0 and 1.1 are withdrawn (RFC 8996) and an
     * appliance that offers them hands an auditor a finding on the very
     * interface that is meant to answer for the rest of the box.
     */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION |
                             SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "[%s] console: %s and %s do not load as a usable "
                "key pair; serving in the CLEAR\n", BRAND_PRODUCT, cert, key);
        SSL_CTX_free(ctx);
        return -1;
    }

    /* The fingerprint the operator compares on the first visit. Printed at
     * boot and shown on the System page, so the browser warning can be
     * answered with something better than "probably fine". */
    FILE *cf = fopen(cert, "r");
    if (cf) {
        X509 *crt = PEM_read_X509(cf, NULL, NULL, NULL);
        if (crt) {
            tls_fingerprint(crt, bp->tls_fingerprint, sizeof(bp->tls_fingerprint));
            X509_free(crt);
        }
        fclose(cf);
    }

    if (bp->tls_ctx) SSL_CTX_free((SSL_CTX *)bp->tls_ctx);
    bp->tls_ctx     = ctx;
    bp->tls_enabled = true;
    return 0;
}

/* ═══════════ HTTP SERVER ═══════════ */
typedef struct {
    int              fd;
    blockpage_ctx_t *bp;
    uint32_t         peer;
    bool             admin;   /* arrived on the console listener */
} conn_t;

void blockpage_send_ex(int fd, const char *status, const char *ctype,
                       const char *extra, const char *body, size_t len) {
    char hdr[1024];
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Cache-Control: no-store\r\n"
        "%s"
        "Connection: close\r\n\r\n", status, ctype, len, extra ? extra : "");
    if (hl < 0 || hl >= (int)sizeof(hdr)) return;
    if (bp_write(fd, hdr, (size_t)hl) < 0) return;
    if (len && bp_write(fd, body, len) < 0) return;
}

void blockpage_send(int fd, const char *status, const char *ctype,
                    const char *body, size_t len) {
    blockpage_send_ex(fd, status, ctype, NULL, body, len);
}

static void send_simple(int fd, const char *status, const char *ctype,
                        const char *body) {
    blockpage_send(fd, status, ctype, body, strlen(body));
}

void blockpage_set_router(blockpage_ctx_t *bp, bp_route_fn fn) {
    bp->router = fn;
}

/*
 * Serves one request. Deliberately does NOT own the socket: bp_client
 * below opens and closes it, so the TLS teardown happens in exactly one
 * place instead of at each of the eleven returns this function has.
 */
static void *bp_serve(int fd, blockpage_ctx_t *bp, uint32_t peer_ip,
                      bool c_admin) {

    char *req = malloc(BP_MAX_REQUEST);
    if (!req) { return NULL; }

    /* Read until the header block is complete. A single read() is not enough
     * once requests carry bodies: TCP may split anywhere. */
    size_t total = 0;
    char *hdr_end = NULL;
    while (total < BP_MAX_REQUEST - 1) {
        ssize_t n = bp_read(fd, req + total, BP_MAX_REQUEST - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
        req[total] = '\0';
        if ((hdr_end = strstr(req, "\r\n\r\n")) != NULL) break;
    }
    if (!hdr_end) { free(req); return NULL; }

    char method[8] = {0}, path[512] = {0};
    if (sscanf(req, "%7s %511s", method, path) != 2) {
        free(req); return NULL;
    }

    /* Pull in the body when one is declared. */
    size_t head_len = (size_t)(hdr_end - req) + 4;
    long clen = 0;
    const char *clh = strcasestr(req, "\nContent-Length:");
    if (clh) {
        clen = strtol(clh + 16, NULL, 10);
        if (clen < 0) clen = 0;
    }
    if (clen > (long)(BP_MAX_REQUEST - 1 - head_len)) {
        send_simple(fd, "413 Payload Too Large", "application/json",
                    "{\"error\":\"request too large\"}");
        free(req); return NULL;
    }
    while (total - head_len < (size_t)clen) {
        ssize_t n = bp_read(fd, req + total, BP_MAX_REQUEST - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
        req[total] = '\0';
    }
    size_t body_len = (total > head_len) ? total - head_len : 0;
    if (body_len > (size_t)clen) body_len = (size_t)clen;

    /*
     * Which listener this arrived on decides what it may reach. The two
     * are not interchangeable: the portal is exposed to the segments the
     * appliance is defending against, so the console must be unreachable
     * from it even if a path matches.
     */
    if (c_admin) {
        if (bp->router && bp->router(fd, method, path, peer_ip,
                                     req, req + head_len, body_len)) {
            free(req);
            /* fd closed by bp_client */
            return NULL;
        }
        /* Nothing else is served here. The console listener does not
         * render block pages, so a probe cannot use it to learn what the
         * appliance has been blocking. */
        send_simple(fd, "404 Not Found", "application/json",
                    "{\"error\":\"no such endpoint\"}");
        free(req);
        /* fd closed by bp_client */
        return NULL;
    }

    /* The portal listener never consults the console router. */
    if (!strcmp(path, "/ui") || !strncmp(path, "/ui/", 4) ||
        !strncmp(path, "/api/", 5)) {
        send_simple(fd, "404 Not Found", "text/plain",
                    "The administration console is not served on this port.\n");
        free(req);
        /* fd closed by bp_client */
        return NULL;
    }

    /* ---- Override request endpoint ---- */
    if (strncmp(path, "/override", 9) == 0) {
        char rid[20] = {0};
        char *q = strstr(path, "rid=");
        if (q) sscanf(q + 4, "%16[0-9A-Fa-f]", rid);

        pthread_mutex_lock(&bp->lock);
        bp->override_requests++;
        pthread_mutex_unlock(&bp->lock);

        char abuf[INET_ADDRSTRLEN];
        printf("[%s] ACCESS OVERRIDE REQUEST  rid=%s  client=%s\n",
               BRAND_PRODUCT, rid, fx_ip_str(peer_ip, abuf, sizeof(abuf)));

        send_simple(fd, "200 OK", "application/json", "{\"status\":\"submitted\"}");
        free(req);
        /* fd closed by bp_client */
        return NULL;
    }

    /* ---- Health probe ---- */
    if (strncmp(path, "/healthz", 8) == 0) {
        send_simple(fd, "200 OK", "text/plain", "OK");
        free(req);
        /* fd closed by bp_client */
        return NULL;
    }

    /* ---- Resolve which block event to display ---- */
    block_event_t snapshot;
    pthread_mutex_lock(&bp->lock);

    block_event_t *ev = NULL;
    char *ridq = strstr(path, "rid=");
    if (ridq) {
        char rid[20] = {0};
        sscanf(ridq + 4, "%16[0-9A-Fa-f]", rid);
        if (rid[0]) ev = find_event(bp, rid);
    }
    if (!ev) ev = latest_for_ip(bp, peer_ip);

    if (ev) {
        snapshot = *ev;
    } else {
        /* No record: synthesise one from the request itself. */
        memset(&snapshot, 0, sizeof(snapshot));
        gen_request_id(snapshot.request_id);
        snapshot.timestamp = time(NULL);
        snapshot.client_ip = peer_ip;
        snapshot.reason    = BLK_POLICY;
        snapshot.severity  = 2;
        snprintf(snapshot.policy_id, sizeof(snapshot.policy_id),
                 "%s-DEFAULT", BRAND_POLICY_PREFIX);
        char *hh = strcasestr(req, "\nHost:");
        if (hh) sscanf(hh + 6, " %255[^\r\n]", snapshot.host);
    }
    bp->pages_served++;
    pthread_mutex_unlock(&bp->lock);

    size_t cap = 65536;
    char *page = malloc(cap);
    if (!page) { free(req); return NULL; }

    int len = render_block_page(bp, &snapshot, page, cap);

    char hdr[640];
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 403 Forbidden\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Cache-Control: no-store, no-cache, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "X-Blocked-By: " BRAND_FULL "\r\n"
        "X-Request-ID: %s\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; "
        "img-src data:; script-src 'unsafe-inline'; form-action 'none'\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Connection: close\r\n\r\n",
        len, snapshot.request_id);

    if (bp_write(fd, hdr, (size_t)hl) > 0)
        (void)!bp_write(fd, page, (size_t)len);

    free(page);
    free(req);
    /* fd closed by bp_client */
    return NULL;
}

/*
 * Reserve a slot for one connection, or refuse it.
 *
 * Counted per listener rather than globally so a flood against the portal
 * -- which anyone the appliance is filtering can reach -- cannot take the
 * management console down with it. That separation is the same reason the
 * two listeners exist at all.
 */
static bool conn_admit(blockpage_ctx_t *bp, bool admin) {
    bool ok;
    pthread_mutex_lock(&bp->lock);
    int *n = admin ? &bp->conns_admin : &bp->conns_portal;
    ok = (*n < BP_MAX_CONNS);
    if (ok) (*n)++;
    else    bp->conns_refused++;
    pthread_mutex_unlock(&bp->lock);
    return ok;
}

static void conn_release(blockpage_ctx_t *bp, bool admin) {
    pthread_mutex_lock(&bp->lock);
    int *n = admin ? &bp->conns_admin : &bp->conns_portal;
    if (*n > 0) (*n)--;
    pthread_mutex_unlock(&bp->lock);
}

static void *bp_client(void *arg) {
    conn_t *c = arg;
    int fd = c->fd;
    blockpage_ctx_t *bp = c->bp;
    uint32_t peer_ip = c->peer;
    bool     c_admin = c->admin;
    free(c);

    /* A client that connects and then stalls must not pin this thread.
     * Set before the handshake, because a half-open TLS handshake is just
     * as effective a way to hold a thread as a half-sent request. */
    struct timeval rtv = { BP_READ_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &rtv, sizeof(rtv));

    if (c_admin && blockpage_tls_active(bp)) {
        t_ssl = SSL_new((SSL_CTX *)bp->tls_ctx);
        if (!t_ssl) { conn_release(bp, c_admin); close(fd); return NULL; }
        SSL_set_fd(t_ssl, fd);

        if (SSL_accept(t_ssl) != 1) {
            /*
             * Almost always a browser that was pointed at http:// on a
             * TLS port, or a scanner. Nothing is written back -- replying
             * in cleartext to a failed handshake would be a plaintext
             * channel on the encrypted listener, which is the thing this
             * is here to remove.
             */
            __atomic_add_fetch(&bp->tls_handshake_fail, 1, __ATOMIC_RELAXED);
            SSL_free(t_ssl);
            t_ssl = NULL;
            conn_release(bp, c_admin);
            close(fd);
            return NULL;
        }
    }

    bp_serve(fd, bp, peer_ip, c_admin);

    conn_release(bp, c_admin);

    if (t_ssl) {
        /* close_notify, so the peer can tell a finished response from a
         * truncated one. Once only: waiting for the peer's own alert would
         * hand a thread back to whoever declines to send it. */
        SSL_shutdown(t_ssl);
        SSL_free(t_ssl);
        t_ssl = NULL;
    }
    close(fd);
    return NULL;
}

/* Which of the two listeners a thread is running. */
typedef struct { blockpage_ctx_t *bp; bool admin; } listener_t;

static void *bp_thread(void *arg) {
    listener_t      *L  = arg;
    blockpage_ctx_t *bp = L->bp;
    bool             is_admin = L->admin;
    free(L);

    int  *fdp  = is_admin ? &bp->admin_fd : &bp->server_fd;
    int   port = is_admin ? bp->admin_port : bp->port;
    uint32_t addr = is_admin ? bp->admin_bind : INADDR_ANY;
    const char *what = is_admin ? "Admin console" : "Block page portal";

    *fdp = socket(AF_INET, SOCK_STREAM, 0);
    if (*fdp < 0) { perror("[blockpage] socket"); return NULL; }

    int opt = 1;
    setsockopt(*fdp, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = addr;

    if (bind(*fdp, (struct sockaddr*)&a, sizeof(a)) < 0) {
        fprintf(stderr, "[%s] %s: cannot bind :%d (%s)\n",
                BRAND_PRODUCT, what, port, strerror(errno));
        close(*fdp);
        *fdp = -1;
        /*
         * A console that cannot bind is an inconvenience; a PORTAL that
         * cannot bind leaves blocked users with a timeout and no
         * explanation, so only that one stops the server.
         */
        if (!is_admin) bp->running = false;
        return NULL;
    }
    if (listen(*fdp, 128) < 0) {
        perror("[blockpage] listen");
        close(*fdp);
        *fdp = -1;
        if (!is_admin) bp->running = false;
        return NULL;
    }

    {
        char ip[INET_ADDRSTRLEN] = "0.0.0.0";
        struct in_addr in = { .s_addr = addr };
        inet_ntop(AF_INET, &in, ip, sizeof(ip));
        printf("[%s] %s listening on %s:%d\n", BRAND_PRODUCT, what, ip, port);
        if (is_admin && addr == INADDR_ANY)
            printf("[%s]   (on every interface -- give it a management "
                   "address to narrow it)\n", BRAND_PRODUCT);
    }

    while (bp->running) {
        struct sockaddr_in cl;
        socklen_t cl_len = sizeof(cl);
        int cfd = accept(*fdp, (struct sockaddr*)&cl, &cl_len);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /*
         * Checked BEFORE the thread is created, which is the whole point:
         * refusing inside bp_client would mean the thread already exists
         * and the resource this is protecting has already been spent.
         */
        if (!conn_admit(bp, is_admin)) {
            close(cfd);
            continue;
        }

        conn_t *c = malloc(sizeof(*c));
        if (!c) { conn_release(bp, is_admin); close(cfd); continue; }
        c->fd = cfd; c->bp = bp; c->peer = cl.sin_addr.s_addr;
        c->admin = is_admin;

        pthread_t t;
        if (pthread_create(&t, NULL, bp_client, c) != 0) {
            conn_release(bp, is_admin);
            close(cfd);
            free(c);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

int blockpage_set_admin(blockpage_ctx_t *bp, int port, uint32_t bind_addr) {
    if (!bp || port <= 0 || port > 65535) return -1;

    /*
     * Refuse rather than collapse. If the console would land on the same
     * socket as the portal, starting anyway would quietly restore the
     * exposure this split exists to remove -- and it would look like it
     * had worked.
     */
    if (port == bp->port &&
        (bind_addr == INADDR_ANY || bind_addr == 0)) {
        fprintf(stderr, "[%s] console port %d is the portal's port, on every "
                        "interface: that is one listener again, refusing\n",
                BRAND_PRODUCT, port);
        return -1;
    }

    bp->admin_port    = port;
    bp->admin_bind    = bind_addr;
    bp->admin_enabled = true;
    return 0;
}

int blockpage_start(blockpage_ctx_t *bp) {
    if (bp->port == 0) bp->port = BLOCKPAGE_PORT;
    bp->server_fd = -1;
    bp->admin_fd  = -1;
    bp->running = true;
    bp->enabled = true;
    pthread_mutex_init(&bp->lock, NULL);

    listener_t *portal = malloc(sizeof(*portal));
    if (!portal) { bp->running = false; return -1; }
    portal->bp = bp; portal->admin = false;

    pthread_t t;
    if (pthread_create(&t, NULL, bp_thread, portal) != 0) {
        free(portal);
        bp->running = false;
        return -1;
    }
    pthread_detach(t);

    if (bp->admin_enabled && bp->admin_port > 0) {
        listener_t *adm = malloc(sizeof(*adm));
        if (adm) {
            adm->bp = bp; adm->admin = true;
            pthread_t at;
            if (pthread_create(&at, NULL, bp_thread, adm) != 0) free(adm);
            else pthread_detach(at);
        }
    } else {
        fprintf(stderr, "[%s] no console listener configured; the "
                        "administration console is not being served\n",
                BRAND_PRODUCT);
    }
    return 0;
}

void blockpage_stop(blockpage_ctx_t *bp) {
    bp->running = false;
    if (bp->admin_fd >= 0) {
        shutdown(bp->admin_fd, SHUT_RDWR);
        close(bp->admin_fd);
        bp->admin_fd = -1;
    }
    if (bp->server_fd >= 0) {
        shutdown(bp->server_fd, SHUT_RDWR);
        close(bp->server_fd);
        bp->server_fd = -1;
    }
}

/* ═══════════ IN-LINE HTTP 302 INJECTION ═══════════
 * For flows the policy engine drops we forge a redirect that appears to come
 * from the origin server, so the browser lands on the branded page instead of
 * timing out.
 */
static uint16_t ip_checksum(const void *buf, int len) {
    uint32_t sum = 0;
    const uint16_t *w = buf;
    for (; len > 1; len -= 2) sum += *w++;
    if (len == 1) sum += *(const uint8_t *)w;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

struct pseudo_hdr {
    uint32_t src, dst;
    uint8_t  zero, proto;
    uint16_t tcp_len;
};

int blockpage_inject_redirect(uint32_t client_ip, uint16_t client_port,
                              uint32_t server_ip, uint16_t server_port,
                              uint32_t seq, uint32_t ack,
                              const char *portal_ip, const char *request_id) {
    char body[512];
    int blen = snprintf(body, sizeof(body),
        "HTTP/1.1 302 Found\r\n"
        "Location: http://%s:%d/?rid=%s\r\n"
        "X-Blocked-By: " BRAND_FULL "\r\n"
        "Content-Length: 0\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n",
        portal_ip ? portal_ip : "0.0.0.0", BLOCKPAGE_PORT,
        request_id ? request_id : "");
    if (blen < 0) return -1;

    int pktlen = (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)) + blen;
    char *pkt = calloc(1, (size_t)pktlen);
    if (!pkt) return -1;

    struct iphdr  *ip  = (struct iphdr *)pkt;
    struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));
    char          *pay = pkt + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memcpy(pay, body, (size_t)blen);

    ip->version  = 4;
    ip->ihl      = 5;
    ip->tot_len  = htons((uint16_t)pktlen);
    ip->id       = htons((uint16_t)(rand() & 0xFFFF));
    ip->ttl      = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr    = server_ip;    /* appear to be the origin server */
    ip->daddr    = client_ip;
    ip->check    = ip_checksum(ip, sizeof(struct iphdr));

    tcp->source  = htons(server_port);
    tcp->dest    = htons(client_port);
    tcp->seq     = htonl(ack);
    tcp->ack_seq = htonl(seq);
    tcp->doff    = 5;
    tcp->psh     = 1;
    tcp->ack     = 1;
    tcp->fin     = 1;            /* close right after the redirect */
    tcp->window  = htons(5840);
    tcp->check   = 0;

    struct pseudo_hdr ph;
    memset(&ph, 0, sizeof(ph));
    ph.src     = ip->saddr;
    ph.dst     = ip->daddr;
    ph.proto   = IPPROTO_TCP;
    ph.tcp_len = htons((uint16_t)(sizeof(struct tcphdr) + blen));

    int cslen = (int)sizeof(ph) + (int)sizeof(struct tcphdr) + blen;
    char *csbuf = calloc(1, (size_t)cslen);
    if (!csbuf) { free(pkt); return -1; }
    memcpy(csbuf, &ph, sizeof(ph));
    memcpy(csbuf + sizeof(ph), tcp, sizeof(struct tcphdr) + (size_t)blen);
    tcp->check = ip_checksum(csbuf, cslen);
    free(csbuf);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) { free(pkt); return -1; }
    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = client_ip;

    ssize_t sent = sendto(s, pkt, (size_t)pktlen, 0,
                          (struct sockaddr*)&dst, sizeof(dst));
    close(s);
    free(pkt);
    return sent < 0 ? -1 : 0;
}

/* Transparent interception: send quarantined hosts to the portal. */
int blockpage_install_intercept(const char *portal_ip, int port) {
    char cmd[512];

    if (!portal_ip) return -1;
    struct in_addr probe;
    if (inet_pton(AF_INET, portal_ip, &probe) != 1) {
        fprintf(stderr, "[%s] portal address \"%s\" is not an IPv4 address\n",
                BRAND_PRODUCT, portal_ip);
        return -1;
    }

    fx_try("ipset create firex_quarantine hash:ip timeout 3600 2>/dev/null");

    fx_try("iptables -t nat -N FIREX_PORTAL 2>/dev/null");
    fx_run("iptables -t nat -F FIREX_PORTAL");
    fx_try("iptables -t nat -D PREROUTING -j FIREX_PORTAL 2>/dev/null");
    fx_run("iptables -t nat -A PREROUTING -j FIREX_PORTAL");

    /* HTTP -> portal */
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A FIREX_PORTAL -m set --match-set firex_quarantine src "
        "-p tcp --dport 80 -j DNAT --to-destination %s:%d 2>/dev/null",
        portal_ip, port);
    fx_try(cmd);

    /* HTTPS cannot be rewritten without terminating TLS, so reset the flow
     * and let the browser fail fast instead of hanging. */
    fx_try("iptables -A FORWARD -m set --match-set firex_quarantine src "
           "-p tcp --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null");

    /* DNS hijack so name resolution lands on the portal */
    snprintf(cmd, sizeof(cmd),
        "iptables -t nat -A FIREX_PORTAL -m set --match-set firex_quarantine src "
        "-p udp --dport 53 -j DNAT --to-destination %s:53 2>/dev/null", portal_ip);
    fx_try(cmd);

    printf("[%s] Transparent block-page interception armed (portal %s:%d)\n",
           BRAND_PRODUCT, portal_ip, port);
    return 0;
}
