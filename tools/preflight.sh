#!/bin/bash
# =============================================================================
#  Check everything that can be checked before building an appliance image.
#
#  Runs without root and changes nothing. The point is to catch the problems
#  that otherwise surface ten minutes into a build: a missing tool, an
#  unreachable mirror, a kernel package that will not resolve, a stale mount
#  from a previous failed run.
#
#      tools/preflight.sh        (or: make image-check)
# =============================================================================
set -uo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
HOST_SUITE="$( . /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-}" )"
SUITE="${FIREX_SUITE:-$HOST_SUITE}"
MIRROR="${FIREX_MIRROR:-http://archive.ubuntu.com/ubuntu}"
SECMIRROR="${FIREX_SECURITY_MIRROR:-http://security.ubuntu.com/ubuntu}"
SIZE="${FIREX_IMAGE_SIZE:-8G}"

PASS=0; WARN=0; FAIL=0

ok()   { printf '  \033[1;32mOK\033[0m    %s\n' "$*"; PASS=$((PASS+1)); }
warn() { printf '  \033[1;33mWARN\033[0m  %s\n' "$*"; WARN=$((WARN+1)); }
bad()  { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }
sec()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }

sec "Build tools"
for t in debootstrap parted losetup mkfs.ext4 mkfs.vfat grub-install rsync blkid sgdisk resize2fs e2fsck fallocate; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t"
    else bad "$t missing  ->  sudo apt-get install -y debootstrap parted dosfstools grub-pc-bin grub-efi-amd64-bin rsync gdisk e2fsprogs"; fi
done

sec "FireX build artifacts"
if [ -x "$PROJ/firexd" ]; then ok "firexd built"
else bad "firexd missing  ->  run: make"; fi

for f in config/firex.conf config/rules.conf; do
    [ -f "$PROJ/$f" ] && ok "$f" || bad "$f missing"
done

if [ -x "$PROJ/firexd" ]; then
    if "$PROJ/firexd" --help >/dev/null 2>&1; then ok "firexd runs"
    else bad "firexd will not execute on this host"; fi
    if "$PROJ/firexd" --dump -c "$PROJ/config/firex.conf" >/dev/null 2>&1; then
        ok "firex.conf parses"
    else bad "firex.conf does not parse  ->  firexd --dump -c config/firex.conf"; fi
fi

[ -f "$PROJ/xdp/xdp_firewall.bpf.o" ] && ok "XDP object built" \
    || warn "xdp_firewall.bpf.o missing - the XDP engine will be unavailable in the image"

sec "Rootfs overlay"
for f in etc/systemd/system/firexd.service etc/systemd/system/firex-segmentation.service \
         etc/systemd/system/firex-boot-check.service \
         etc/systemd/system/firex-confirm.service \
         etc/systemd/system/firex-console.service \
         usr/local/bin/firex-boot-check usr/local/bin/firex-confirm \
         etc/firex/segmentation-up.sh etc/firex/segmentation-down.sh; do
    [ -f "$PROJ/board/rootfs_overlay/$f" ] && ok "$f" || bad "overlay $f missing"
done
for f in "$PROJ"/board/rootfs_overlay/etc/firex/*.sh \
         "$PROJ"/board/rootfs_overlay/usr/local/bin/firex-*; do
    [ -f "$f" ] || continue
    sh -n "$f" 2>/dev/null && ok "$(basename "$f") syntax" || bad "$(basename "$f") has a syntax error"
done
for f in "$PROJ"/board/rootfs_overlay/usr/local/bin/firex-*; do
    [ -x "$f" ] && ok "$(basename "$f") is executable" \
                || bad "$(basename "$f") is not executable"
done

sec "Boot splash"
# The PNGs are committed so the image build needs no Pillow and no fonts.
# If one is missing the build stops halfway through, by which point it has
# already spent ten minutes on debootstrap.
SPLASH_OK=1
for f in background logo title tagline byline bar track grub; do
    if [ -f "$PROJ/board/splash/$f.png" ]; then
        ok "splash/$f.png"
    else
        bad "board/splash/$f.png missing - run: make splash"
        SPLASH_OK=0
    fi
done
for f in board/plymouth/firex/firex.plymouth board/plymouth/firex/firex.script \
         board/grub/themes/firex/theme.txt; do
    [ -f "$PROJ/$f" ] && ok "$f" || bad "$f missing"
done
if [ "$SPLASH_OK" = 1 ] && [ -x "$PROJ/firexd" ]; then
    S="$(mktemp)"
    if "$PROJ/firexd" --write-grub "$S" --slots-file /nonexistent >/dev/null 2>&1 \
       && grep -q ' quiet splash' "$S" \
       && grep -q 'themes/firex/theme.txt' "$S"; then
        ok "grub.cfg asks for the splash and the theme"
    else
        bad "firexd --write-grub produced no splash entry"
    fi
    rm -f "$S"
fi
apt-cache show plymouth >/dev/null 2>&1 && ok "plymouth available" \
    || warn "plymouth is not in the apt index - the image will fail to install it"

# Plymouth's script language is C-like and knows only the two C comment
# forms. A '#' line is a parse error -- and the script plugin says
# nothing about it: it logs "executing script file", stops at the first
# '#', and leaves a black screen behind a renderer that is working
# perfectly. This theme shipped that way and drew nothing at all.
PS="$PROJ/board/plymouth/firex/firex.script"
if [ -f "$PS" ]; then
    if grep -qn '^[[:space:]]*#' "$PS"; then
        bad "firex.script uses '#' comments; Plymouth stops parsing there (use //)"
        grep -n '^[[:space:]]*#' "$PS" | head -3 | sed 's/^/        /'
    else
        ok "firex.script has no '#' comments"
    fi
    # And the other half of the same trap. C comments do not nest: a
    # "/*" written INSIDE a block comment means the first "*/" after it
    # closes the whole thing, and the prose that follows is parsed as
    # code. The note explaining the '#' bug above was nearly written that
    # way, which would have reintroduced the very fault it describes.
    CSTATE="$(awk '
        BEGIN { inc = 0; nested = 0 }
        {
            line = $0
            while (length(line)) {
                if (!inc) {
                    i = index(line, "/*")
                    if (!i) break
                    inc = 1; line = substr(line, i + 2)
                } else {
                    i = index(line, "*" "/")
                    j = index(line, "/*")
                    if (j && (!i || j < i)) { nested = NR; line = substr(line, j + 2); continue }
                    if (!i) break
                    inc = 0; line = substr(line, i + 2)
                }
            }
        }
        END {
            if (nested) print "nested " nested
            else if (inc) print "unterminated"
            else print "ok"
        }' "$PS")"
    case "$CSTATE" in
        ok)  ok "firex.script block comments are balanced" ;;
        nested*) bad "firex.script line ${CSTATE#nested }: '/*' inside a block comment -- the next '*/' ends it early and the rest is parsed as code" ;;
        *)   bad "firex.script has an unterminated block comment" ;;
    esac
fi

# GRUB matches a theme font by the name stored inside the .pf2, not by the
# file name, and a name it cannot match renders the menu with no text at
# all -- silently. Check the two agree before spending a build on it.
HOSTFONT=""
for cand in /usr/share/grub/unicode.pf2 /usr/share/grub/ascii.pf2; do
    [ -f "$cand" ] && { HOSTFONT="$cand"; break; }
done
if [ -n "$HOSTFONT" ]; then
    FNAME="$(grep -ao '[A-Za-z][A-Za-z0-9 ]* Regular [0-9][0-9]*' \
             "$HOSTFONT" 2>/dev/null | head -1 || true)"
    if [ -z "$FNAME" ]; then
        warn "could not read the font name out of $HOSTFONT"
    elif grep -qF "\"$FNAME\"" "$PROJ/board/grub/themes/firex/theme.txt"; then
        ok "theme.txt names the installed font ($FNAME)"
    else
        bad "theme.txt does not name '$FNAME' - the GRUB menu would have no text"
    fi
else
    warn "no grub .pf2 font on this host - the image installs its own, unchecked"
fi

# The build runs these INSIDE the chroot, so the host is only a proxy --
# but it is a good one when the suites match, and it is the difference
# between finding out now and finding out ten minutes into a debootstrap.
# plymouth-set-default-theme is deliberately not among them: it is not
# shipped on every release, which is why the build drives
# update-alternatives directly.
for c in update-alternatives lsinitramfs plymouth chpasswd useradd; do
    if command -v "$c" >/dev/null 2>&1; then
        ok "$c (the image build calls it in the chroot)"
    elif [ "$SUITE" != "$HOST_SUITE" ]; then
        warn "$c is not on this host; cross-building '$SUITE', so unverified"
    else
        bad "$c is missing and the image build needs it in the chroot"
    fi
done

sec "Desktop console"
if [ "${FIREX_DESKTOP:-1}" = 1 ]; then
    if [ -x "$PROJ/flamewall" ]; then
        ok "flamewall built"
        "$PROJ/flamewall" --help >/dev/null 2>&1 \
            && ok "flamewall runs" || bad "flamewall will not start"
    else
        bad "flamewall is not built - run: make   (or build with FIREX_DESKTOP=0)"
    fi
    for f in usr/local/bin/firex-gui usr/local/bin/firex-session \
             etc/systemd/system/firex-gui.service; do
        [ -f "$PROJ/board/rootfs_overlay/$f" ] && ok "$f" || bad "overlay $f missing"
    done
    # The packages the image installs for it. Same host-as-proxy caveat as
    # the chroot tools above.
    for pkg in xserver-xorg-core xinit libgtk-4-1; do
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            ok "$pkg available"
        else
            warn "$pkg is not in the apt index - the desktop console will not install"
        fi
    done
    # The console reads its port out of [blockpage] in firex.conf. A flat
    # grep for the key picks up netflow_port instead, and a console on the
    # wrong port reports the daemon as missing -- so the lookup the shipped
    # script uses is run here against the shipped config.
    CFGPORT="$(awk -F= '
        /^[ \t]*\[/        { s = $1; gsub(/[ \t]/, "", s) }
        s == "[blockpage]" && $1 ~ /^[ \t]*port[ \t]*$/ {
            gsub(/[ \t]/, "", $2); print $2; exit
        }' "$PROJ/config/firex.conf" 2>/dev/null)"
    if [ -n "$CFGPORT" ]; then
        ok "console port resolves to $CFGPORT from [blockpage]"
    else
        bad "the console port cannot be read from config/firex.conf"
    fi

    if command -v systemd-analyze >/dev/null 2>&1; then
        # Verify the unit as it will SHIP, not as it sits in the tree:
        # the overlay carries @BRAND_...@ placeholders that the image
        # build fills, and systemd rightly calls a placeholder an invalid
        # URL. Checking the template instead of the artifact would mean
        # either a permanent false failure or dropping the check.
        UDIR="$(mktemp -d)"
        cp "$PROJ"/board/rootfs_overlay/etc/systemd/system/*.service "$UDIR/" 2>/dev/null || true
        DOCV="$(sed -n 's/^#define BRAND_DOC_URL[[:space:]]*"\(.*\)".*$/\1/p' \
                 "$PROJ/include/brand.h" | head -1)"
        if [ -z "$DOCV" ]; then
            sed -i '/^Documentation=@BRAND_DOC@$/d' "$UDIR"/*.service
        else
            sed -i "s|@BRAND_DOC@|$DOCV|" "$UDIR"/*.service
        fi
        # Read here, not borrowed from a later section: preflight runs
        # under "set -u", so referencing a variable that section has not
        # defined yet aborts the whole script -- which is exactly what
        # this did, silently truncating every check after it.
        UPROD="$(grep -oP '#define BRAND_PRODUCT\s+"\K[^"]+' "$PROJ/include/brand.h" || echo product)"
        UVEND="$(grep -oP '#define BRAND_VENDOR\s+"\K[^"]+' "$PROJ/include/brand.h" || echo vendor)"
        sed -i -e "s|@BRAND_FULL@|$UPROD by $UVEND|g" \
               -e "s|@BRAND_PRODUCT@|$UPROD|g" \
               -e "s|@BRAND_VENDOR@|$UVEND|g" \
               -e "s|@BRAND_TAGLINE@|tagline|g" \
               -e "s|@BRAND_SUPPORT@|support|g" "$UDIR"/*.service 2>/dev/null || true

        VOUT="$(systemd-analyze verify "$UDIR/firex-gui.service" \
                2>&1 | grep -v 'is not executable' || true)"
        [ -z "$VOUT" ] && ok "firex-gui.service parses (with placeholders filled)" \
                       || bad "firex-gui.service: $VOUT"

        # And every other unit, since they all carry the same placeholder.
        UBAD=""
        for u in "$UDIR"/*.service; do
            UO="$(systemd-analyze verify "$u" 2>&1 \
                  | grep -v 'is not executable' || true)"
            [ -n "$UO" ] && UBAD="$UBAD $(basename "$u")"
        done
        [ -z "$UBAD" ] && ok "every shipped unit parses" \
                       || bad "units with problems:$UBAD"
        rm -rf "$UDIR"
    fi

    # Both are needed: without them getty@tty1 and Plymouth each hold what
    # X needs, and the screen stays dark with nothing said about why.
    U="$PROJ/board/rootfs_overlay/etc/systemd/system/firex-gui.service"
    grep -q '^Conflicts=getty@tty1.service' "$U" \
        && ok "the unit yields tty1 from getty" \
        || bad "firex-gui.service does not conflict with getty@tty1"
    grep -q '^After=plymouth-quit-wait.service' "$U" \
        && ok "the unit waits for Plymouth to release the framebuffer" \
        || bad "firex-gui.service does not order after plymouth-quit-wait"

    # This one is a trap worth a guard of its own. Conflicting with
    # plymouth-quit is what a display manager does, because it ends the
    # splash itself; this console does not, so the conflict drops the only
    # job that tells plymouthd to quit. plymouth-quit-wait then blocks for
    # ever and, because the console is ordered after it, the boot stops
    # dead with the console never starting.
    grep -q '^Conflicts=plymouth-quit.service' "$U" \
        && bad "firex-gui.service conflicts with plymouth-quit: that deadlocks the boot" \
        || ok "the unit leaves plymouth-quit alone (no boot deadlock)"

    PQW="$PROJ/board/rootfs_overlay/etc/systemd/system/plymouth-quit-wait.service.d/firex-timeout.conf"
    [ -f "$PQW" ] && grep -q '^TimeoutStartSec=' "$PQW" \
        && ok "plymouth-quit-wait has a timeout (a wedged splash cannot hang the boot)" \
        || bad "no timeout drop-in for plymouth-quit-wait.service"

    # The root filesystem is mounted read-only and no fstab line turns it
    # back: without this unit X cannot write its auth file or its log, and
    # dies before it draws anything.
    RW="$PROJ/board/rootfs_overlay/etc/systemd/system/firex-rootfs-rw.service"
    [ -f "$RW" ] && grep -q 'remount,rw /' "$RW" \
        && ok "firex-rootfs-rw.service remounts the root writable" \
        || bad "nothing remounts the root filesystem read-write"
    grep -q 'systemctl enable firex-rootfs-rw.service' "$PROJ/tools/build-image.sh" \
        && ok "the image enables firex-rootfs-rw.service" \
        || bad "firex-rootfs-rw.service is never enabled in the image"

    # X must come up even if the remount is skipped, so neither of its two
    # mandatory files may land on the root filesystem.
    G="$PROJ/board/rootfs_overlay/usr/local/bin/firex-gui"
    grep -q 'XAUTHORITY=' "$G" && grep -q '\-logfile' "$G" \
        && ok "X writes its auth file and log to /run, not the root fs" \
        || bad "firex-gui leaves X writing to a read-only root"

    SCR="${FIREX_SCREEN:-1024x768}"
    case "$SCR" in
        [0-9]*x[0-9]*) ok "screen size $SCR" ;;
        *) bad "FIREX_SCREEN='$SCR' is not WxH" ;;
    esac
else
    warn "desktop console disabled (FIREX_DESKTOP=0)"
fi

sec "Reachability"
# Three services failed on the first appliance that booted this image --
# ssh, logind and the desktop console -- and all three for the same
# reason. These checks are here so that reason cannot come back quietly.

SSHK="$PROJ/board/rootfs_overlay/etc/systemd/system/firex-sshd-keygen.service"
if [ -f "$SSHK" ]; then
    ok "SSH host keys are generated on the appliance"
    grep -q 'ssh-keygen -A' "$SSHK" \
        && ok "  it calls ssh-keygen -A" \
        || bad "  firex-sshd-keygen.service does not run ssh-keygen -A"
    # A key baked into the image would be shared by every appliance built
    # from it, so the condition that keeps it per-machine matters.
    grep -q '^ConditionPathExists=!' "$SSHK" \
        && ok "  it only runs when the appliance has no key of its own" \
        || bad "  firex-sshd-keygen.service would overwrite existing host keys"
    D="$PROJ/board/rootfs_overlay/etc/systemd/system/ssh.service.d/firex-hostkeys.conf"
    [ -f "$D" ] && grep -q 'After=firex-sshd-keygen.service' "$D" \
        && ok "  ssh waits for the keys" \
        || bad "  ssh.service is not ordered after the key generator"
else
    bad "nothing generates SSH host keys; sshd will not start"
fi
# A host key inside the image would be shared by every appliance built
# from it, so the build must strip whatever the packages left behind.
grep -qE 'rm -f.*ssh_host_\*' "$PROJ/tools/build-image.sh" \
    && ok "the build strips host keys, so each appliance generates its own" \
    || bad "the build leaves SSH host keys in the image (every unit would share them)"

ML="$PROJ/board/rootfs_overlay/usr/local/bin/firex-mgmt-link"
if [ -x "$ML" ]; then
    ok "management link helper present"
    if sh -n "$ML" 2>/dev/null; then ok "  it parses"; else bad "  firex-mgmt-link has a syntax error"; fi

    # Exercise it for real against a fixture, so the selection rules are
    # tested rather than just present. Nothing here touches a link on the
    # machine running preflight.
    FIX="$(mktemp -d)"
    for n in lo eth0 eth1; do mkdir -p "$FIX/$n"; done
    for n in eth0 eth1; do : > "$FIX/$n/device"; echo 0 > "$FIX/$n/carrier"; done
    echo 1 > "$FIX/eth0/carrier"
    ST="$FIX/state"

    OUT="$(FIREX_SYSNET="$FIX" FIREX_MGMT_DRYRUN=1 FIREX_MGMT_STATE="$ST" \
           FIREX_MGMT_HAVE_ADDR=1 sh "$ML" 2>&1 || true)"
    echo "$OUT" | grep -q 'would: ip link set eth0 up' \
        && echo "$OUT" | grep -q 'would: ip link set eth1 up' \
        && ok "  it brings every physical link up" \
        || bad "  it does not bring the links up: $OUT"
    echo "$OUT" | grep -q 'lo up' \
        && bad "  it tries to configure the loopback" \
        || ok "  it leaves the loopback alone"
    grep -q 'dhcp on eth0' "$ST" 2>/dev/null \
        && ok "  with no address it asks DHCP on the link that has carrier" \
        || bad "  it did not fall back to DHCP: $(cat "$ST" 2>/dev/null)"

    # And the other half of the rule: once anything has an address it must
    # keep its hands off, or it would fight firexd for the interface.
    : > "$ST"
    FIREX_SYSNET="$FIX" FIREX_MGMT_DRYRUN=1 FIREX_MGMT_STATE="$ST" \
        FIREX_MGMT_HAVE_ADDR=0 sh "$ML" >/dev/null 2>&1 || true
    grep -q 'already configured' "$ST" 2>/dev/null \
        && ok "  with an address already set it does nothing" \
        || bad "  it runs DHCP even when an address is configured"
    rm -rf "$FIX"
else
    bad "firex-mgmt-link is missing or not executable"
fi
grep -q 'systemctl enable firex-mgmt-link.service' "$PROJ/tools/build-image.sh" \
    && ok "the image enables firex-mgmt-link.service" \
    || bad "firex-mgmt-link.service is never enabled in the image"

C="$PROJ/board/rootfs_overlay/etc/systemd/system/firex-console.service"
grep -q '^StartLimitIntervalSec=0' "$C" \
    && ok "the serial console never gives up (no start limit)" \
    || bad "firex-console.service can exhaust its start limit and leave the serial port dead"

sec "Branding is one file"
# include/brand.h claims to be the only file a re-skin edits. It was not:
# nine files carried the vendor name literally, including the systemd
# unit description shown by `systemctl status` on every appliance, and
# nothing failed when a re-skin missed them. These checks make the claim
# enforceable instead of aspirational.
VENDOR="$(grep -oP '#define BRAND_VENDOR\s+"\K[^"]+' "$PROJ/include/brand.h" || true)"
PRODUCT="$(grep -oP '#define BRAND_PRODUCT\s+"\K[^"]+' "$PROJ/include/brand.h" || true)"

if [ -n "$VENDOR" ] && [ -n "$PRODUCT" ]; then
    ok "brand.h defines $PRODUCT by $VENDOR"

    # The vendor name must not appear in code, assets or build scripts.
    # webui_assets.c is generated from the static files, so it is excluded
    # the way any build output would be.
    # Case-INSENSITIVE, and it searches config/ too. The first version of
    # this check was neither, so it reported a clean tree while four
    # config lines still carried the old vendor's domain in lowercase
    # inside an email address -- and admin_contact overrides
    # BRAND_SUPPORT_EMAIL, so that address was what the block page would
    # actually have shown to end users.
    HITS="$(grep -rli --fixed-strings "$VENDOR" \
              --include='*.c' --include='*.h' --include='*.js' \
              --include='*.css' --include='*.html' --include='*.sh' \
              --include='*.py' --include='*.service' --include='*.script' \
              --include='*.txt' --include='*.plymouth' --include='*.conf' \
              "$PROJ/src" "$PROJ/include" "$PROJ/tools" "$PROJ/board" \
              "$PROJ/config" \
              2>/dev/null | grep -v 'include/brand.h' \
                          | grep -v 'webui_assets.c' || true)"
    if [ -z "$HITS" ]; then
        ok "  the vendor name appears nowhere outside it"
    else
        bad "  '$VENDOR' is hard-coded outside brand.h:"
        printf '%s\n' "$HITS" | sed "s|$PROJ/|        |"
    fi
else
    bad "could not read BRAND_PRODUCT / BRAND_VENDOR from include/brand.h"
fi

# Every placeholder the overlay uses must be one the build substitutes.
PH="$(grep -rhoE '@BRAND_[A-Z_]+@' "$PROJ/board/rootfs_overlay" 2>/dev/null \
        | sort -u || true)"
missing=""
for t in $PH; do
    grep -q -- "$t" "$PROJ/tools/build-image.sh" || missing="$missing $t"
done
if [ -z "$missing" ]; then
    [ -n "$PH" ] && ok "every @BRAND_...@ placeholder is substituted at build" \
                 || ok "the overlay uses no brand placeholders"
else
    bad "the overlay uses placeholders the build never fills:$missing"
fi

# The artwork is generated from brand.h, so it has to be newer than it or
# the splash still shows the previous name.
if [ -f "$PROJ/board/splash/title.png" ]; then
    if [ "$PROJ/board/splash/title.png" -nt "$PROJ/include/brand.h" ]; then
        ok "the boot artwork is newer than brand.h"
    else
        bad "brand.h changed after the artwork was generated -- run: make splash"
    fi
fi

# A literal URL or email in a unit file or in C is a brand string that a
# re-skin cannot reach. Nine units carried a previous vendor's docs URL
# through a rebrand this way: the guard above searches for the CURRENT
# vendor name, so by construction it cannot see a leftover of the old one.
# This looks for the shape instead of the name.
# Dependency directives are skipped: "After=getty@tty1.service" matches
# an email pattern and is not a brand string. Filtering by key is more
# honest than weakening the pattern until the false positive goes away.
LIT=""
for u in "$PROJ"/board/rootfs_overlay/etc/systemd/system/*.service; do
    [ -f "$u" ] || continue
    if grep -vE '^(After|Before|Wants|Requires|Requisite|Conflicts|BindsTo|PartOf|PropagatesReloadTo|ReloadPropagatedFrom|Alias|Also)=' "$u" \
       | grep -qE 'https?://[a-zA-Z0-9.-]+|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}'; then
        LIT="$LIT$u
"
    fi
done
LIT="$(printf '%s' "$LIT" | grep -v '^$' || true)"
if [ -z "$LIT" ]; then
    ok "no unit file hard-codes a URL or address"
else
    bad "a unit file hard-codes a URL or address a re-skin cannot reach:"
    printf '%s\n' "$LIT" | sed "s|$PROJ/|        |"
fi

# Same shape check over the C that renders user-facing text.
LITC="$(grep -rlE '"https?://[a-zA-Z0-9.-]+|"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}"' \
          --include='*.c' "$PROJ/src" 2>/dev/null | grep -v 'webui_assets.c' || true)"
if [ -z "$LITC" ]; then
    ok "no source file hard-codes a URL or address"
else
    warn "a source file hard-codes a URL or address:"
    printf '%s\n' "$LITC" | sed "s|$PROJ/|        |"
fi

# The shipped config's admin_contact OVERRIDES BRAND_SUPPORT_EMAIL on the
# block page, so when the two disagree the address end users are told to
# write to is not the one in the brand header. That is how four lines
# carrying a previous vendor's domain survived a rebrand unnoticed.
SUPB="$(grep -oP '#define BRAND_SUPPORT_EMAIL\s+"\K[^"]+' "$PROJ/include/brand.h" || true)"
badcfg=""
# config/*.conf AND config/config.d/*.conf: the second is where the
# versioned store writes revisions, and a stale revision left in the tree
# carried the previous vendor's support address past a rebrand.
for cf in "$PROJ"/config/*.conf "$PROJ"/config/config.d/*.conf; do
    [ -f "$cf" ] || continue
    while IFS= read -r got; do
        [ -n "$got" ] || continue
        [ "$got" = "$SUPB" ] || badcfg="$badcfg $(basename "$cf"):$got"
    done <<EOF
$(sed -n 's/^[[:space:]]*admin_contact[[:space:]]*=[[:space:]]*//p' "$cf")
EOF
done
if [ -z "$badcfg" ]; then
    ok "every shipped config's admin_contact matches the brand"
else
    bad "a shipped config overrides the support address with another domain:"
    printf '%s\n' "$badcfg" | tr ' ' '\n' | grep -v '^$' | sed 's/^/        /'
fi

# Constants nothing reads are not configuration, they are decoration --
# and they invite somebody to "set" them and believe it took effect.
for c in BRAND_SUPPORT_URL BRAND_SUPPORT_PHONE; do
    if grep -rq --include='*.c' --include='*.h' "$c" "$PROJ/src" 2>/dev/null; then
        ok "$c is used"
    else
        warn "$c is defined but nothing reads it; setting it changes nothing"
    fi
done

# The support contact is printed on the block page end users see, so a
# placeholder domain shipping to production is worth saying out loud.
# Empty is a legitimate state -- it means "no such route", and the block
# page omits it. What is NOT acceptable is every route being empty: a
# blocked user would then have a page telling them to contact someone and
# no way to do it.
sup_of() { sed -n "s/^#define $1[[:space:]]*\"\(.*\)\"[[:space:]]*\(\/\*.*\)\?$/\1/p" \
                   "$PROJ/include/brand.h" | head -1; }
SUP_MAIL="$(sup_of BRAND_SUPPORT_EMAIL)"
SUP_URL="$(sup_of BRAND_SUPPORT_URL)"
SUP_TEL="$(sup_of BRAND_SUPPORT_PHONE)"

if [ -z "$SUP_MAIL$SUP_URL$SUP_TEL" ]; then
    bad "no support contact of any kind is set; a blocked user has no route"
else
    ok "a support route is configured"
fi
for pair in "mail:$SUP_MAIL" "url:$SUP_URL" "phone:$SUP_TEL"; do
    val="${pair#*:}"
    case "$val" in
        *.example|*.example.com|*@example.*|*000-000*)
            warn "support ${pair%%:*} is still a placeholder: $val" ;;
    esac
done
[ -z "$SUP_MAIL" ] && warn "no support email; the block page omits the mailto button" || true

sec "Listener separation"
# The block page faces the untrusted segments; the console must not. One
# listener meant one exposure -- a host on GUEST could reach the login
# page of the appliance quarantining it.
grep -q '^\[console\]' "$PROJ/config/firex.conf" \
    && ok "config has a [console] section" \
    || bad "config/firex.conf does not configure a console listener"

CPORT="$(grep -A3 '^\[console\]' "$PROJ/config/firex.conf" | sed -n 's/^port *= *//p' | head -1)"
PPORT="$(grep -A6 '^\[blockpage\]' "$PROJ/config/firex.conf" | sed -n 's/^port *= *//p' | head -1)"
: "${PPORT:=8080}"
if [ -n "$CPORT" ] && [ "$CPORT" != "$PPORT" ]; then
    ok "console ($CPORT) and block page ($PPORT) are different ports"
else
    bad "console and block page would share port ${CPORT:-unset}"
fi

if [ -x "$PROJ/firexd" ]; then
    T="$(mktemp)"

    # NOTE: the output is captured BEFORE it is matched, not piped into
    # grep. This script runs under "set -o pipefail", and firexd exits
    # non-zero on an invalid config -- which is the whole point of these
    # probes. Piped, the pipeline inherits that non-zero status even when
    # grep matched, so the `if` takes the else branch and a passing check
    # reports as a failure. Both of these probes were written that way
    # first, and both lied.
    printf '[blockpage]\nport = 8080\n\n[console]\nport = 8080\nbind = any\n' > "$T"
    OUT="$("$PROJ/firexd" --check -c "$T" 2>&1 || true)"
    case "$OUT" in
        *"block page's port"*) ok "a collapsed listener is refused at validation" ;;
        *) bad "a console sharing the block page's port is accepted" ;;
    esac

    # manual + scheduled + require_time_sync is a deadlock: manual fetches
    # no time, so the clock never disciplines, so every window stays shut.
    printf '[airgap]\nmode = manual\nrequire_time_sync = yes\nwindow = w,-MTWTF-,02:00,04:00,1,1\n' > "$T"
    OUT="$("$PROJ/firexd" --check -c "$T" 2>&1 || true)"
    case "$OUT" in
        *"never be satisfied"*) ok "the manual + scheduled clock deadlock is refused" ;;
        *) bad "manual + scheduled + require_time_sync is accepted; every window would stay shut" ;;
    esac
    rm -f "$T"
fi

# A digest of part of a file cannot match a database of whole files, so a
# truncated object must get no hash verdict at all.
grep -q 'if (f->overflowed)' "$PROJ/src/malware.c" && \
grep -q 'm->partial++' "$PROJ/src/malware.c" \
    && ok "truncated objects get no hash verdict" \
    || bad "src/malware.c may compare a prefix hash against whole-file hashes"

# Which accounts are still on a shipped password is not a read-only fact.
grep -q 'reveal' "$PROJ/src/webui.c" \
    && ok "shipped-password state is redacted from non-admins" \
    || bad "/api/accounts reports shipped passwords to every authenticated role"

sec "Interface naming"
# The shipped configuration and the kernel command line have to agree
# about what the ports are called. When they do not, the appliance boots
# cleanly and segments nothing: a port that is not in the configuration
# is not an error, it is just a port nobody mentioned.
CFG_ETH="$(grep -cE '^\[port:eth[0-9]' "$PROJ/config/firex.conf" || true)"
if [ "${CFG_ETH:-0}" -gt 0 ]; then
    if [ -x "$PROJ/firexd" ]; then
        G="$(mktemp)"
        "$PROJ/firexd" --write-grub "$G" --slots-file /nonexistent >/dev/null 2>&1
        if grep -q 'net.ifnames=0' "$G" && grep -q 'biosdevname=0' "$G"; then
            ok "config names eth0.. and the kernel line asks for classic names"
        else
            bad "config/firex.conf names eth0.. but the kernel line does not set"
            bad "  net.ifnames=0; the ports will come up as enp0s3 and every"
            bad "  [port:ethN] stanza will miss"
        fi
        rm -f "$G"
    fi
else
    ok "config does not depend on classic interface names"
fi

sec "Security engines"
# These three are new surfaces and each has a way of failing silently:
# a scanner that is configured but has no database, an air gap whose mode
# is a typo, and a console page that cannot reach its endpoint.

for f in include/malware.h src/malware.c include/airgap.h src/airgap.c \
         include/netif.h src/netif.c; do
    [ -f "$PROJ/$f" ] && ok "$f" || bad "$f missing"
done

grep -q '$(SRCDIR)/malware.c' "$PROJ/Makefile" && \
grep -q '$(SRCDIR)/airgap.c'  "$PROJ/Makefile" && \
grep -q '$(SRCDIR)/netif.c'   "$PROJ/Makefile" \
    && ok "all three are in the build" \
    || bad "a new module is not in SOURCES; it would silently not ship"

# The shipped configuration has to name them, or the appliance boots with
# the engines compiled in and switched off, which looks identical to
# their not existing.
for section in malware airgap; do
    grep -q "^\[$section\]" "$PROJ/config/firex.conf" \
        && ok "config has a [$section] section" \
        || bad "config/firex.conf has no [$section] section"
done

# Detect-only is the shipped default on purpose. A scanner that starts
# dropping traffic the first time it is switched on gets switched off.
if grep -A6 '^\[malware\]' "$PROJ/config/firex.conf" | grep -q '^block *= *no'; then
    ok "malware ships in detect-only mode"
else
    warn "malware does not ship in detect-only mode; first-run drops are likely"
fi

# The air gap must never ship isolated: an appliance that comes up with
# no path out is indistinguishable from one that is broken.
AGMODE="$(grep -A3 '^\[airgap\]' "$PROJ/config/firex.conf" \
          | sed -n 's/^mode *= *//p' | head -1)"
case "$AGMODE" in
    connected) ok "air gap ships connected" ;;
    "")        bad "no air gap mode in config/firex.conf" ;;
    *)         bad "air gap ships as '$AGMODE'; a factory image must come up reachable" ;;
esac

[ -f "$PROJ/config/malware.db" ] \
    && ok "a signature database ships (may be empty)" \
    || warn "no config/malware.db; the scanner runs on built-in patterns only"

if [ -x "$PROJ/firexd" ]; then
    # The parser must refuse a mode it does not know rather than falling
    # back to "connected" -- a typo in the one setting that isolates the
    # appliance must not be the thing that quietly connects it.
    T="$(mktemp)"
    sed 's/^mode              = connected/mode              = isolted/' \
        "$PROJ/config/firex.conf" > "$T"
    # Captured, not piped: see the note under "Listener separation" --
    # pipefail would make firexd's exit status decide this, not the match.
    OUT="$("$PROJ/firexd" --check --enterprise-config "$T" 2>&1 || true)"
    case "$OUT" in
        *"not recognised"*) ok "a misspelt air gap mode is reported, not silently accepted" ;;
        *) bad "a misspelt air gap mode is accepted silently" ;;
    esac
    rm -f "$T"
fi

# Every console page needs an endpoint behind it, and every endpoint
# needs a page, or one of the two was forgotten mid-change.
JS="$PROJ/src/webui/static/vlan.js"
C="$PROJ/src/webui.c"
for ep in system interfaces malware airgap; do
    if grep -q "\"/api/$ep\"" "$C" && grep -q "/api/$ep" "$JS"; then
        ok "/api/$ep is served and used"
    elif grep -q "\"/api/$ep\"" "$C"; then
        warn "/api/$ep is served but the console never calls it"
    else
        bad "/api/$ep is referenced by the console but not served"
    fi
done

# No emoji anywhere in the console. They are drawn by the operating
# system, so the same appliance looks different on every workstation and
# shows a dotted box on the ones with no colour font -- which on a
# hardened management station is most of them.
# Matched as UTF-8 BYTES, not as codepoints: under LC_ALL=C grep treats
# input as bytes and a \x{1F6E1} class silently never matches, which is
# how this check passed a file with an emoji in it the first time.
#   F0 9F ..      U+1F300-U+1FBFF  pictographs
#   E2 98..9E ..  U+2600-U+27BF    dingbats and symbols
#   EF B8 8F      U+FE0F           the variation selector
EMOJI_RE='\xF0\x9F[\x8C-\xAF]|\xE2[\x98-\x9E]|\xEF\xB8\x8F'
if LC_ALL=C grep -qP "$EMOJI_RE" \
       "$PROJ/src/webui/static/index.html" "$JS" 2>/dev/null; then
    bad "the web console contains emoji; use the inline SVG icon set instead"
else
    ok "the web console uses no emoji"
fi

# The DESKTOP console was never checked, and had thirty-eight of them.
# They survived because the source does not contain emoji BYTES -- it
# contains the C escape sequences that produce them ("\xf0\x9f\x9b\xa1"),
# which a byte scan of the .c file cannot see. So scan both forms: the
# escapes in the source, and the real bytes in the built binary, which is
# the only place that cannot be written around.
if grep -rqE '\\x(f0\\x9f|ef\\xb8\\x8f)' "$PROJ"/src/gui/*.c 2>/dev/null; then
    bad "the desktop console has emoji written as C escapes"
else
    ok "the desktop console source has no emoji escapes"
fi
# Through strings(1), not over the raw file. A two-byte pattern matched
# against machine code hits by chance in any binary of this size -- the
# first version of this check failed on both binaries while strings(1)
# found nothing, which is a guard that reports a defect that is not there
# and is worth no more than one that misses one that is.
for b in flamewall firexd; do
    [ -x "$PROJ/$b" ] || continue
    if LC_ALL=C strings -n 2 "$PROJ/$b" 2>/dev/null | grep -qP "$EMOJI_RE"; then
        bad "$b contains emoji; they render as a dotted box without a colour font"
    else
        ok "$b carries no emoji"
    fi
done

sec "Air gap: the appliance's own egress"
# The defect this section exists for: airgap_network_permitted() was
# written, documented in the README with a table, and covered by five
# passing assertions -- and NOTHING IN THE PRODUCT CALLED IT. Every mode
# stopped user traffic and let the appliance go on fetching feeds, which
# is the one property that separates an air gap from a strict firewall.
#
# So this does not check that the function exists. It checks that each
# subsystem that opens an outbound connection calls the gate.

for f in include/egress.h src/egress.c; do
    [ -f "$PROJ/$f" ] && ok "$f" || bad "$f missing"
done

grep -q '$(SRCDIR)/egress.c' "$PROJ/Makefile" \
    && ok "the egress gate is in the build" \
    || bad "src/egress.c is not in SOURCES; the gate would not ship"

for pair in feeds:EGRESS_FEEDS telemetry:EGRESS_TELEMETRY \
            ha:EGRESS_HA gwmon:EGRESS_GWMON; do
    mod="${pair%%:*}"; kind="${pair##*:}"
    if grep -q "egress_permitted($kind" "$PROJ/src/$mod.c" 2>/dev/null; then
        ok "src/$mod.c asks the gate before reaching the network"
    else
        bad "src/$mod.c never calls egress_permitted($kind); that subsystem ignores the air gap"
    fi
done

# A gate nothing binds is a gate that always says yes, which is the exact
# shape of the original defect one level up.
if grep -q 'airgap_bind_egress' "$PROJ/src/firexd.c"; then
    ok "firexd binds the air gap to the gate"
else
    bad "firexd never calls airgap_bind_egress(); every subsystem would be ungated"
fi

# Ordering is load-bearing: the feed refresher used to start sixty lines
# before the air gap was initialised and got its first fetch away while
# the appliance was, on paper, isolated.
# "airgap_bind_egress(" with the bracket: the first bare mention in this
# file is the comment that explains why the ordering matters, and matching
# that made the check pass with the call itself moved to the bottom.
BIND_LINE="$(grep -n 'airgap_bind_egress(&' "$PROJ/src/firexd.c" | head -1 | cut -d: -f1)"
EARLIEST=""
for sym in feeds_start gwmon_start telemetry_init; do
    L="$(grep -n "$sym" "$PROJ/src/firexd.c" | head -1 | cut -d: -f1)"
    [ -n "$L" ] || continue
    if [ -z "$EARLIEST" ] || [ "$L" -lt "$EARLIEST" ]; then EARLIEST="$L"; fi
done
if [ -n "$BIND_LINE" ] && [ -n "$EARLIEST" ] && [ "$BIND_LINE" -lt "$EARLIEST" ]; then
    ok "the gate is bound before any subsystem can open a socket"
else
    bad "a subsystem starts before airgap_bind_egress(); its first request escapes the gap"
fi

# file:// must stay ungated, or `manual` mode becomes useless rather than
# strict: a hand-carried list is how an isolated appliance gets signatures.
# The FIRST file:// is the branch that handles it; later ones are text in
# the messages around the gate. Taking the last match made this compare
# the gate against its own error string and fail on correct code.
if awk '/file:\/\//{ if (!f) f=NR } /egress_permitted\(EGRESS_FEEDS/{ if (!g) g=NR } END{exit !(f && g && f < g)}' \
       "$PROJ/src/feeds.c"; then
    ok "a file:// list loads with the gap shut"
else
    bad "feeds.c gates file:// lists; an isolated appliance could not be fed by hand"
fi

sec "Console TLS"
# 8443 is the conventional number for an admin interface. For a while it
# was only the number: the console served plain HTTP on it, so an operator
# typing https:// got nothing and one typing http:// got a login form that
# sent their password in the clear.

grep -q 'blockpage_set_tls' "$PROJ/src/firexd.c" \
    && ok "firexd enables console TLS" \
    || bad "firexd never calls blockpage_set_tls(); the console serves in the clear"

# Default ON. "Off unless configured" is a default that survives exactly
# as long as nobody reads the file.
if grep -q 'console_tls_set' "$PROJ/src/firexd.c" && \
   grep -q '? g_netconf.console_tls : true' "$PROJ/src/firexd.c"; then
    ok "TLS is on unless the configuration switches it off"
else
    bad "console TLS is not the default"
fi

# A certificate in the image is a private key every appliance shares.
# By NAME and by CONTENT. The first version grepped contents only, so a
# file literally called console.crt sitting in the overlay sailed through
# -- which is the exact thing being guarded against, not a near miss.
CERTS="$(find "$PROJ/board/rootfs_overlay" \
              \( -name '*.crt' -o -name '*.key' -o -name '*.pem' \) \
              -print 2>/dev/null)"
PEMS="$(grep -rl -- '-----BEGIN .*PRIVATE KEY-----\|-----BEGIN CERTIFICATE-----' \
             "$PROJ/board/rootfs_overlay" 2>/dev/null)"
if [ -n "$CERTS$PEMS" ]; then
    bad "a certificate or key ships in the image; every appliance would share it:"
    for f in $CERTS $PEMS; do bad "    ${f#$PROJ/}"; done
else
    ok "no certificate ships in the image (generated on first start)"
fi

# Secure must track TLS, not be hard-coded either way: sent over plain
# HTTP the browser drops the cookie and every login fails silently.
if grep -q 'blockpage_tls_active(&g_blockpage)' "$PROJ/src/webui.c" && \
   grep -q 'HttpOnly; Secure; SameSite=Strict' "$PROJ/src/webui.c"; then
    ok "the session cookie is Secure only when TLS is on"
else
    bad "the Secure cookie attribute does not track the TLS state"
fi

# Every write to a client socket has to go through the transport, or it
# lands outside the TLS record stream and truncates the response.
# \bwrite(, so webui_route_write(fd, ...) is not mistaken for a syscall.
# The one legitimate raw write is the plaintext branch inside bp_write
# itself, which is where the decision belongs.
if grep -nE '(^|[^_[:alnum:]])write\(fd,' "$PROJ/src/webui.c" "$PROJ/src/blockpage.c" \
     | grep -v 'if (!t_ssl) return write' | grep -q .; then
    bad "a raw write() on a client fd would corrupt the TLS record stream"
else
    ok "client writes all go through bp_write()"
fi

sec "Audit trail"
for f in include/audit.h src/audit.c; do
    [ -f "$PROJ/$f" ] && ok "$f" || bad "$f missing"
done
grep -q '$(SRCDIR)/audit.c' "$PROJ/Makefile" \
    && ok "the audit trail is in the build" \
    || bad "src/audit.c is not in SOURCES"

grep -q 'audit_open(&g_audit' "$PROJ/src/firexd.c" \
    && ok "firexd opens the trail at startup" \
    || bad "firexd never opens the audit trail"

# The actions worth being able to point at afterwards.
for act in auth.login airgap.mode account.password config.apply; do
    grep -q "\"$act\"" "$PROJ/src/webui.c" \
        && ok "'$act' is recorded" \
        || bad "'$act' is not recorded in the audit trail"
done

# Every write endpoint, not just the ones somebody remembered.
grep -q 'audit_record(&g_audit, s.user, peer_ip, AUDIT_OK' "$PROJ/src/webui.c" \
    && ok "the dispatcher records every write endpoint" \
    || bad "writes are only recorded where a handler remembered to"

sec "A/B updates"
if [ -x "$PROJ/firexd" ]; then
    G="$(mktemp)"
    if "$PROJ/firexd" --write-grub "$G" --slots-file /nonexistent >/dev/null 2>&1 \
       && grep -q 'root=LABEL=firex-root-a' "$G" \
       && grep -q 'root=LABEL=firex-root-b' "$G"; then
        ok "firexd generates an A/B grub.cfg with both slots"
    else
        bad "firexd --write-grub did not produce a usable grub.cfg"
    fi
    rm -f "$G"
fi
if [ -n "${FIREX_UPDATE_KEY:-}" ]; then
    [ -f "$FIREX_UPDATE_KEY" ] && ok "update signing key $FIREX_UPDATE_KEY" \
        || bad "FIREX_UPDATE_KEY=$FIREX_UPDATE_KEY does not exist"
else
    warn "FIREX_UPDATE_KEY not set - the image will trust no update keys, so"
    warn "  every update bundle will be refused. Create one with:"
    warn "    make bundle-tool && ./firex-bundle keygen --out firex-signing"
    warn "  then build with:"
    warn "    sudo env FIREX_UPDATE_KEY=\"\$PWD/firex-signing.pub\" tools/build-image.sh"
fi

sec "Image scripts"
for f in "$PROJ"/tools/*.sh; do
    bash -n "$f" 2>/dev/null && ok "$(basename "$f") syntax" || bad "$(basename "$f") has a syntax error"
done

sec "Archive reachability (suite '$SUITE')"
if [ -z "$SUITE" ]; then
    bad "could not determine the suite - set FIREX_SUITE"
else
    for u in "$MIRROR/dists/$SUITE/Release" \
             "$MIRROR/dists/$SUITE-updates/Release" \
             "$SECMIRROR/dists/$SUITE-security/Release"; do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$u" 2>/dev/null)"
        short="$(echo "$u" | sed 's|https\?://||; s|/Release$||')"
        [ "$code" = 200 ] && ok "$short" || bad "$short returned $code"
    done
fi

sec "Kernel packages"
KPKG="$(apt-cache depends linux-image-generic 2>/dev/null | awk '/Depends: linux-image-[0-9]/{print $2; exit}')"
MPKG="$(apt-cache depends linux-image-generic 2>/dev/null | awk '/Depends: linux-modules-[0-9]/{print $2; exit}')"
if [ -n "$KPKG" ] && [ -n "$MPKG" ]; then
    ok "resolve to $KPKG + $MPKG"
else
    bad "could not resolve kernel package names from linux-image-generic"
fi
apt-cache show initramfs-tools >/dev/null 2>&1 && ok "initramfs-tools available" \
    || bad "initramfs-tools not in the archive"

sec "Host state"
AVAIL_MB="$(df -m "$PROJ" | awk 'NR==2{print $4}')"
NEED_MB=$(( $(echo "$SIZE" | sed 's/[Gg]//') * 1024 + 1024 ))
if [ "${AVAIL_MB:-0}" -gt "$NEED_MB" ]; then
    ok "disk space: ${AVAIL_MB}MB free (need about ${NEED_MB}MB for a $SIZE image)"
else
    bad "only ${AVAIL_MB}MB free; a $SIZE image plus the chroot needs about ${NEED_MB}MB"
fi

# Match only a real invocation of the script, and never this shell or its
# parent: a loose "build-image" pattern also matches any command line that
# merely mentions the filename, including the one that started this check.
RUNNING="$(pgrep -f '(^|/)build-image\.sh([[:space:]]|$)' 2>/dev/null \
           | grep -vx "$$" | grep -vx "$PPID" | tr '\n' ' ')"
if [ -n "${RUNNING// /}" ]; then
    bad "a build is already running (pid${RUNNING% })"
else
    ok "no build in progress"
fi

if mount 2>/dev/null | grep -q "$PROJ/build/imgroot"; then
    bad "stale mounts under build/imgroot  ->  sudo umount -lR $PROJ/build/imgroot"
else
    ok "no stale mounts"
fi

if losetup -a 2>/dev/null | grep -q 'firex.img'; then
    bad "firex.img still attached to a loop device  ->  sudo losetup -D"
else
    ok "no stale loop device"
fi

sec "Result"
printf "  %d passed, %d warnings, %d failures\n\n" "$PASS" "$WARN" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '  \033[1;31mNot ready.\033[0m Fix the failures above first.\n\n'
    exit 1
fi
printf '  \033[1;32mReady to build:\033[0m\n'
printf '      sudo tools/build-image.sh\n\n'
