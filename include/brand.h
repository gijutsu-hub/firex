#ifndef FIREX_BRAND_H
#define FIREX_BRAND_H

/* ═══════════════════════════════════════════════════════════════
 *  FireX — White-Label Branding Configuration
 *  Change ONLY this file to re-skin the entire product.
 * ═══════════════════════════════════════════════════════════════ */

#define BRAND_PRODUCT          "FireX"
#define BRAND_VENDOR           "Sumon"
#define BRAND_FULL             "FireX by Sumon"
#define BRAND_TAGLINE          "The Hidden Defend Layer"

/* The byline on the boot splash and the console's sign-in screen. It was
 * written out in make-splash.py and gui_login.c instead, which put two
 * more files in the way of a re-skin. */
#define BRAND_AUTHOR           "Made by Sumon Nath"
#define BRAND_VERSION          "3.0.0"
#define BRAND_BUILD            "ENT-2024"
#define BRAND_EDITION          "Enterprise"

#define BRAND_HOSTNAME         "firex"

/* The GTK/D-Bus application id. Reverse-DNS, lowercase, no hyphens --
 * D-Bus rejects anything else, so it cannot simply be derived from
 * BRAND_VENDOR at compile time and gets its own line here. */
#define BRAND_APP_ID           "com.sumon.firex"
#define BRAND_DAEMON           "firexd"
#define BRAND_CONFIG_DIR       "/etc/firex"
#define BRAND_LOG_DIR          "/var/log/firex"
#define BRAND_QUARANTINE_DIR   "/var/firex/quarantine"
#define BRAND_SPOOL_DIR        "/var/spool/firex"
#define BRAND_STATE_DIR        "/var/lib/firex"

/*
 * Support contacts.
 *
 * EMPTY MEANS "NOT CONFIGURED", and the block page simply omits that
 * route rather than rendering a dead mailto: or a fake number. So these
 * can be filled in one at a time as they come to exist, without anybody
 * having to invent a placeholder that end users would then be invited to
 * contact.
 *
 * At least one of EMAIL or URL should be set: between them they are the
 * only way a blocked user can reach anyone.
 */
#define BRAND_SUPPORT_EMAIL    "snath2973@gmail.com"
#define BRAND_SUPPORT_URL      "https://www.linkedin.com/in/gijutsu-hub/"
#define BRAND_SUPPORT_PHONE    ""     /* no support line yet    */
#define BRAND_DOC_URL          ""     /* no documentation site yet */

/* Visual identity */
#define BRAND_COLOR_PRIMARY    "#FF4B2B"   /* FireX orange-red  */
#define BRAND_COLOR_SECONDARY  "#FF416C"   /* accent            */
#define BRAND_COLOR_DARK       "#0B0E14"   /* background        */
#define BRAND_COLOR_PANEL      "#141A24"
#define BRAND_COLOR_SUCCESS    "#00E58B"
#define BRAND_COLOR_WARNING    "#FFC247"
#define BRAND_COLOR_DANGER     "#FF3B5C"
#define BRAND_COLOR_TEXT       "#E7ECF3"
#define BRAND_COLOR_MUTED      "#7A879B"

#define BRAND_LOGO_ASCII \
"  ###### #  #####  ###### #    #\n" \
"  #      #  #    # #       #  # \n" \
"  #####  #  #####  #####    ##  \n" \
"  #      #  #  #   #        ##  \n" \
"  #      #  #   #  #       #  # \n" \
"  #      #  #    # ###### #    #\n"

/* Inline SVG logo for web UI / block page */
#define BRAND_LOGO_SVG \
"<svg viewBox='0 0 48 48' width='42' height='42' xmlns='http://www.w3.org/2000/svg'>" \
"<defs><linearGradient id='fxg' x1='0' y1='0' x2='1' y2='1'>" \
"<stop offset='0%' stop-color='#FF4B2B'/><stop offset='100%' stop-color='#FF416C'/>" \
"</linearGradient></defs>" \
"<path fill='url(#fxg)' d='M24 2C24 2 12 14 12 26a12 12 0 0 0 24 0C36 14 24 2 24 2z'/>" \
"<path fill='#0B0E14' opacity='.55' d='M24 14c0 0-6 6.5-6 12a6 6 0 0 0 12 0c0-5.5-6-12-6-12z'/>" \
"</svg>"

/* Policy / event identifier prefixes */
#define BRAND_POLICY_PREFIX    "FX-POL"
#define BRAND_EVENT_PREFIX     "FX-EVT"
#define BRAND_INCIDENT_PREFIX  "FX-INC"

#endif /* FIREX_BRAND_H */
