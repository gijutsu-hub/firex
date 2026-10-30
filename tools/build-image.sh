#!/bin/bash
# =============================================================================
#  FireX - bootable appliance image builder
#
#  Produces a hybrid BIOS + UEFI raw disk image that boots on real hardware
#  (dd it to a USB stick or SSD) and under QEMU.
#
#  Layout (GPT):
#    p1   1MiB    BIOS boot partition   (GRUB core for legacy boot)
#    p2   128MiB  EFI System Partition  (FAT32, GRUB EFI)
#    p3   rest    root                  (ext4)
#
#  Run from the project root, as root:
#      sudo tools/build-image.sh
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${FIREX_IMAGE:-$PROJ/build/firex.img}"
# Sized for PEAK build usage, not the finished image: during install the
# rootfs holds the unpacked packages AND the .deb cache at the same time.
# The image is sparse and gets trimmed at the end, so this costs little;
# run tools/shrink-image.sh --resize afterwards to shrink it to fit.
# Two root slots plus a data partition. 4G was enough for one root;
# it is not enough for two.
SIZE="${FIREX_IMAGE_SIZE:-8G}"
# Default to the host's own suite: firexd is compiled here and copied in, so
# the image needs a matching glibc and libbpf or it will not even start.
HOST_SUITE="$( . /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-}" )"
SUITE="${FIREX_SUITE:-${HOST_SUITE:-noble}}"
MIRROR="${FIREX_MIRROR:-http://archive.ubuntu.com/ubuntu}"
SECMIRROR="${FIREX_SECURITY_MIRROR:-http://security.ubuntu.com/ubuntu}"
HOSTNAME_="${FIREX_HOSTNAME:-firex}"
MNT="$PROJ/build/imgroot"

LOOP=""
MOUNTED=0
KREL=""
UPDATE_KEY_STATE="none"

log()  { printf '\033[1;36m[image]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[image] ERROR:\033[0m %s\n' "$*" >&2; }

cleanup() {
    set +e
    if [ "$MOUNTED" = 1 ]; then
        for d in run dev/pts dev proc sys data boot/efi ""; do
            umount -lf "$MNT/$d" 2>/dev/null
        done
    fi
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    set -e
}
trap cleanup EXIT

# ---- preflight --------------------------------------------------------------
[ "$(id -u)" = 0 ] || { err "must run as root (sudo tools/build-image.sh)"; exit 1; }

MISSING=""
for t in debootstrap parted losetup mkfs.ext4 mkfs.vfat grub-install rsync; do
    command -v "$t" >/dev/null 2>&1 || MISSING="$MISSING $t"
done
if [ -n "$MISSING" ]; then
    err "missing tools:$MISSING"
    echo "    sudo apt-get install -y debootstrap parted dosfstools grub-pc-bin grub-efi-amd64-bin rsync"
    exit 1
fi

for f in "$PROJ/firexd" "$PROJ/config/firex.conf" "$PROJ/config/rules.conf" \
         "$PROJ/config/rules.ids" "$PROJ/config/blocklist.txt" \
         "$PROJ/config/malware.db"; do
    [ -e "$f" ] || { err "missing $f - run 'make' first"; exit 1; }
done

if [ -n "$HOST_SUITE" ] && [ "$SUITE" != "$HOST_SUITE" ]; then
    log "WARNING: building a '$SUITE' image on a '$HOST_SUITE' host."
    log "         firexd is linked against this host's glibc/libbpf; if the"
    log "         target suite ships older ones it will fail to start."
fi

# ---- shipped credentials ----------------------------------------------------
#
# Two accounts, and each one works in both places:
#
#   root / root     the Linux account  -- SSH and the shell
#   admin / admin   the FireX account  -- web console and the serial menu
#
# Both are also enrolled in the other database, so either pair signs in
# anywhere. They are deliberately guessable: an appliance you cannot reach
# is an appliance you reinstall, and a generated password printed once into
# a terminal scrollback is a password you have already lost.
#
# The console says so on every page until they are changed, and
# System -> Accounts in the web UI changes both. Override at build time:
#
#     sudo env FIREX_ROOT_PASSWORD=... FIREX_ADMIN_PASSWORD=... \
#          tools/build-image.sh
ROOT_PW="${FIREX_ROOT_PASSWORD:-root}"
ADMIN_PW="${FIREX_ADMIN_PASSWORD:-${FIREX_CONSOLE_PASSWORD:-admin}}"

# Written as `if`, not `test && assign`: this script runs under `set -e`,
# and an AND-list whose test fails returns non-zero, which would end the
# build right here the first time somebody set a password of their own.
DEFAULT_ROOT_PW=0
DEFAULT_ADMIN_PW=0
if [ "$ROOT_PW"  = root  ]; then DEFAULT_ROOT_PW=1;  fi
if [ "$ADMIN_PW" = admin ]; then DEFAULT_ADMIN_PW=1; fi

# firexd enforces an 8-character minimum on a password an operator picks.
# "root" and "admin" are shorter, so seeding them has to say so out loud.
WEAK_ADMIN=""
WEAK_ROOT=""
if [ "${#ADMIN_PW}" -lt 8 ]; then WEAK_ADMIN="--allow-weak"; fi
if [ "${#ROOT_PW}"  -lt 8 ]; then WEAK_ROOT="--allow-weak";  fi

if [ -z "$ROOT_PW" ] || [ -z "$ADMIN_PW" ]; then
    err "an empty password was given; refusing to build an unreachable image"
    exit 1
fi
# chpasswd reads one "user:password" line at a time, so a newline in a
# password would be read as the start of a second record. Matched with a
# bracket expression, not against $(printf '\n'): command substitution
# strips trailing newlines, so that pattern is the empty string and
# rejects every password ever given.
case "$ROOT_PW$ADMIN_PW" in
    *[$'\n\r']*)
        err "a password contains a line break; chpasswd cannot take one"
        exit 1 ;;
esac

BOOT_SPLASH="${FIREX_BOOT_SPLASH:-1}"

# The desktop console. The appliance has one screen at one size and no
# way to resize a window on it, so the size is pinned here and the same
# value reaches GRUB's framebuffer, Xorg and the console's own window --
# three places that otherwise disagree and leave the GUI letterboxed.
DESKTOP="${FIREX_DESKTOP:-1}"
SCREEN="${FIREX_SCREEN:-1024x768}"
case "$SCREEN" in
    [0-9]*x[0-9]*) ;;
    *) err "FIREX_SCREEN wants WxH, for example 1280x800"; exit 1 ;;
esac
SCREEN_W="${SCREEN%x*}"
SCREEN_H="${SCREEN#*x}"
if [ "$SCREEN_W" -lt 640 ] || [ "$SCREEN_H" -lt 480 ]; then
    err "FIREX_SCREEN must be at least 640x480"
    exit 1
fi

# slots.c names the GRUB theme directory after BRAND_HOSTNAME, so take it
# from the same header rather than from $HOSTNAME_, which an operator may
# have overridden with FIREX_HOSTNAME.
THEME_NAME="$(grep -oP '#define BRAND_HOSTNAME\s+"\K[^"]+' \
              "$PROJ/include/brand.h")"
if [ -z "$THEME_NAME" ]; then
    err "could not read BRAND_HOSTNAME from include/brand.h"
    exit 1
fi

# The rest of the brand, read from the same header. Every user-visible
# string this script writes into the image -- the motd, the unit
# descriptions -- comes from here, so a re-skin really is one file. They
# were hard-coded, which made that claim untrue and silently so: nothing
# failed when a re-skin forgot them.
brand_of() {
    grep -oP "#define $1\s+\"\K[^\"]+" "$PROJ/include/brand.h"
}
BRAND_PRODUCT_="$(brand_of BRAND_PRODUCT)"
BRAND_VENDOR_="$(brand_of BRAND_VENDOR)"
BRAND_TAGLINE_="$(brand_of BRAND_TAGLINE)"
BRAND_SUPPORT_="$(brand_of BRAND_SUPPORT_EMAIL)"
BRAND_DOC_="$(brand_of BRAND_DOC_URL || true)"
for v in BRAND_PRODUCT_ BRAND_VENDOR_ BRAND_TAGLINE_ BRAND_SUPPORT_; do
    eval "val=\$$v"
    if [ -z "$val" ]; then
        err "could not read ${v%_} from include/brand.h"
        exit 1
    fi
done
BRAND_FULL_="$BRAND_PRODUCT_ by $BRAND_VENDOR_"

# ---- disk -------------------------------------------------------------------
# This script runs as root and partitions whatever $OUT names. $OUT comes
# from FIREX_IMAGE, so the one thing that must never happen is it naming a
# real disk. Refuse anything that is not a plain file, and refuse the
# obvious device paths outright, before parted is anywhere near it.
case "$OUT" in
    /dev/*)
        err "FIREX_IMAGE points at $OUT, which is a device path."
        err "This script partitions and reformats what it is given. It builds"
        err "a disk IMAGE; it does not install onto a disk. Refusing."
        exit 1
        ;;
esac
if [ -e "$OUT" ] && [ ! -f "$OUT" ]; then
    err "$OUT exists and is not a regular file."
    err "Refusing to partition it. Remove it, or set FIREX_IMAGE to a path"
    err "where an image file can be created."
    exit 1
fi

log "Creating $SIZE image at $OUT"
mkdir -p "$(dirname "$OUT")" "$MNT"
# The marker says "this image finished building". Remove it first, so a run
# that dies partway leaves an image that nothing downstream will boot. A
# half-built image has a full partition table and a real filesystem in it;
# there is no way to tell it apart by looking.
rm -f "$OUT" "$OUT.manifest"
truncate -s "$SIZE" "$OUT"

# Belt and braces: after this point everything addresses the image through a
# loop device, so prove it really is one.
[ -f "$OUT" ] || { err "$OUT is not a regular file after creation"; exit 1; }

# A/B layout. Two root slots of equal size plus a data partition that
# outlives both of them:
#
#   p1  bios_grub   1-2MiB      so the same image boots BIOS and UEFI
#   p2  ESP         2-130MiB    shared; holds the one grub.cfg
#   p3  root A      130MiB-45%  the slot this build populates
#   p4  root B      45%-88%     empty; the first update lands here
#   p5  data        88%-100%    /etc/firex and /var/lib/firex live here
#
# Configuration must not live in a root slot. If it did, updating a slot
# would either lose the configuration or require copying it across, and
# a rollback would silently take the configuration back in time with it.
log "Partitioning (GPT: bios_grub + ESP + root A + root B + data)"
parted -s "$OUT" mklabel gpt
parted -s "$OUT" mkpart bios_grub 1MiB 2MiB
parted -s "$OUT" set 1 bios_grub on
parted -s "$OUT" mkpart ESP fat32 2MiB 130MiB
parted -s "$OUT" set 2 esp on
parted -s "$OUT" mkpart root-a ext4 130MiB 45%
parted -s "$OUT" mkpart root-b ext4 45% 88%
parted -s "$OUT" mkpart data   ext4 88% 100%

LOOP="$(losetup --find --show --partscan "$OUT")"
case "$LOOP" in
    /dev/loop[0-9]*) ;;
    *) err "losetup returned '$LOOP', which is not a loop device. Refusing"
       err "to run mkfs or grub-install against it."
       exit 1 ;;
esac
log "Loop device: $LOOP (backing file $OUT)"
sleep 1

mkfs.vfat -F 32 -n FIREX-ESP "${LOOP}p2" >/dev/null
mkfs.ext4 -q -F -L firex-root-a "${LOOP}p3"
mkfs.ext4 -q -F -L firex-root-b "${LOOP}p4"
mkfs.ext4 -q -F -L firex-data   "${LOOP}p5"

log "  slot A $(blockdev --getsize64 "${LOOP}p3" | awk '{printf "%.1fG", $1/1073741824}'), slot B $(blockdev --getsize64 "${LOOP}p4" | awk '{printf "%.1fG", $1/1073741824}'), data $(blockdev --getsize64 "${LOOP}p5" | awk '{printf "%.1fG", $1/1073741824}')"

mount "${LOOP}p3" "$MNT"
MOUNTED=1
mkdir -p "$MNT/boot/efi"
mount "${LOOP}p2" "$MNT/boot/efi"

# The data partition is mounted where the appliance expects to find its
# configuration, so everything debootstrap and the install steps below
# write to /etc/firex lands on persistent storage from the start.
mkdir -p "$MNT/data"
mount "${LOOP}p5" "$MNT/data"

# ---- base system ------------------------------------------------------------
log "Bootstrapping $SUITE (this downloads ~200MB)"
debootstrap --arch=amd64 --variant=minbase \
    --include=systemd,systemd-sysv,udev,dbus \
    "$SUITE" "$MNT" "$MIRROR"

mount --bind /dev     "$MNT/dev"
mount --bind /dev/pts "$MNT/dev/pts"
mount -t proc  proc  "$MNT/proc"
mount -t sysfs sysfs "$MNT/sys"

# Exclude documentation before anything is installed, so it is never written
# rather than deleted afterwards. Stays in place for the running appliance.
mkdir -p "$MNT/etc/dpkg/dpkg.cfg.d"
cat > "$MNT/etc/dpkg/dpkg.cfg.d/01-firex-nodoc" <<'EOF'
# FireX appliance: no documentation or translations on the image.
path-exclude /usr/share/doc/*
path-exclude /usr/share/man/*
path-exclude /usr/share/groff/*
path-exclude /usr/share/info/*
path-exclude /usr/share/lintian/*
path-exclude /usr/share/locale/*
path-include /usr/share/locale/en*
path-include /usr/share/locale/locale.alias
EOF

# A fresh debootstrap rootfs has no usable resolver, and the host's
# /etc/resolv.conf points at systemd-resolved on 127.0.0.53, which does not
# exist inside the chroot. Without this, apt-get update cannot resolve the
# mirror and every package install below fails.
cat > "$MNT/etc/resolv.conf" <<'EOF'
nameserver 1.1.1.1
nameserver 9.9.9.9
EOF

# -security lives on security.ubuntu.com, not on the archive mirror; pointing
# it at the archive gives a 404 and fails the whole apt-get update.
cat > "$MNT/etc/apt/sources.list" <<EOF
deb $MIRROR $SUITE main restricted universe
deb $MIRROR $SUITE-updates main restricted universe
deb $SECMIRROR $SUITE-security main restricted universe
EOF

WITH_FW=""
if [ "${FIREX_WITH_FIRMWARE:-0}" = 1 ]; then
    WITH_FW="linux-firmware"
    log "Including linux-firmware (adds roughly 1GB)"
fi

log "Installing kernel, bootloader and FireX runtime dependencies"
chroot "$MNT" /bin/bash -eu <<CHROOT
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# The kernel goes in by its versioned package names rather than through the
# linux-image-generic metapackage. That metapackage Depends on linux-firmware
# plus the microcode packages - well over a gigabyte - which a virtual
# appliance never loads. Set FIREX_WITH_FIRMWARE=1 for real hardware whose
# NICs or wireless need firmware blobs.
KPKG="\$(apt-cache depends linux-image-generic | awk '/Depends: linux-image-[0-9]/{print \$2; exit}')"
MPKG="\$(apt-cache depends linux-image-generic | awk '/Depends: linux-modules-[0-9]/{print \$2; exit}')"
[ -n "\$KPKG" ] && [ -n "\$MPKG" ] || { echo "could not resolve kernel package names" >&2; exit 1; }
echo "kernel packages: \$KPKG \$MPKG"

# initramfs-tools is only a Recommends of the kernel, so with
# --no-install-recommends no initrd is ever built and the kernel panics with
# "Unable to mount root fs on unknown-block(0,0)". It has to be explicit.
apt-get install -y --no-install-recommends initramfs-tools "\$KPKG" "\$MPKG" ${WITH_FW}
apt-get clean

apt-get install -y --no-install-recommends \
    grub-efi-amd64 grub-pc-bin grub2-common os-prober \
    iproute2 iputils-ping netbase ifupdown isc-dhcp-client \
    iptables ipset dnsmasq conntrack \
    libnetfilter-queue1 libnfnetlink0 libbpf1 \
    ca-certificates less nano openssh-server sudo \
    plymouth plymouth-themes plymouth-label \
    > /dev/null
apt-get clean

# The desktop console. No desktop environment and no display manager --
# one X server, one window, and the drivers a virtual machine or a plain
# PC actually offers: modesetting needs a DRM device, fbdev takes the
# framebuffer GRUB hands over, vesa is the last resort, vmware is what
# VirtualBox's VMSVGA adapter answers to.
if [ "${FIREX_DESKTOP:-1}" = 1 ]; then
    apt-get install -y --no-install-recommends \
        xserver-xorg-core xserver-xorg-video-fbdev xserver-xorg-video-vesa \
        xserver-xorg-video-vmware xserver-xorg-input-libinput \
        xinit x11-xserver-utils \
        libgtk-4-1 adwaita-icon-theme fonts-dejavu-core \
        > /dev/null
fi
apt-get clean
# apt-get clean empties the .deb cache but not the package index, which is
# the larger of the two and useless on an appliance.
rm -rf /var/lib/apt/lists/*
CHROOT

# The apt stage is where a bad suite name or a DNS problem shows up. Catch it
# here rather than three steps later with a confusing error.
FREE_MB="$(df -m "$MNT" | awk 'NR==2{print $4}')"
if [ "${FREE_MB:-0}" -lt 150 ]; then
    err "only ${FREE_MB}MB left on the image filesystem."
    err "dpkg needs headroom to configure packages; raise the size:"
    err "    sudo env FIREX_IMAGE_SIZE=12G tools/build-image.sh"
    exit 1
fi
log "Free space after install: ${FREE_MB}MB"

if ! ls "$MNT"/boot/vmlinuz-* >/dev/null 2>&1; then
    err "no kernel was installed - the apt stage failed."
    err "Usual causes: the suite ('$SUITE') is wrong, the chroot had no DNS,"
    err "or the filesystem filled up."
    exit 1
fi

# Everything unpacked but nothing configured is the signature of a failure
# part-way through dpkg; the image would be unusable.
UNCONF="$(chroot "$MNT" dpkg -l 2>/dev/null | awk '$1 ~ /^i[^i]/ {n++} END{print n+0}')"
if [ "$UNCONF" -gt 0 ]; then
    err "$UNCONF package(s) are unpacked but not configured."
    chroot "$MNT" dpkg -l 2>/dev/null | awk '$1 ~ /^i[^i]/ {print "    " $2}' | head -10 >&2
    exit 1
fi
log "Kernel installed: $(basename "$(ls "$MNT"/boot/vmlinuz-* | head -1)")"

# MODULES=dep would build an initramfs holding only drivers for the device the
# root fs sits on right now - the build host's loop device - which boots
# nowhere else. "most" ships the usual storage/controller drivers.
log "Configuring initramfs for portable boot"
mkdir -p "$MNT/etc/initramfs-tools"
cat > "$MNT/etc/initramfs-tools/initramfs.conf" <<'EOF'
MODULES=most
BUSYBOX=auto
KEYMAP=n
COMPRESS=zstd
DEVICE=
NFSROOT=auto
RUNSIZE=10%
EOF

# Belt and braces for the controllers this image is most likely to meet.
cat > "$MNT/etc/initramfs-tools/modules" <<'EOF'
ext4
sd_mod
ahci
virtio_blk
virtio_pci
virtio_scsi
nvme
xhci_pci
usb_storage
EOF

# ---- boot splash ------------------------------------------------------------
# Installed before the initramfs is built: initramfs-tools copies whichever
# Plymouth theme is the default at that moment, so setting it afterwards
# would leave the initrd with the stock one and the splash would only
# appear halfway through boot.
if [ "$BOOT_SPLASH" = 1 ]; then
    log "Installing the boot splash"

    for f in background logo title tagline byline bar track grub; do
        if [ ! -f "$PROJ/board/splash/$f.png" ]; then
            err "board/splash/$f.png is missing."
            err "Regenerate the artwork with: make splash"
            exit 1
        fi
    done

    # Plymouth finds a theme by convention: <dir>/<name>/<name>.plymouth,
    # whose ScriptFile points at <name>.script beside it. Both are renamed
    # and rewritten here so a re-skin through BRAND_HOSTNAME keeps working
    # instead of leaving plymouth-set-default-theme looking for a file that
    # is not there.
    PTH="$MNT/usr/share/plymouth/themes/$THEME_NAME"
    mkdir -p "$PTH"
    install -m 644 "$PROJ/board/plymouth/firex/firex.plymouth" \
                   "$PTH/$THEME_NAME.plymouth"
    install -m 644 "$PROJ/board/plymouth/firex/firex.script" \
                   "$PTH/$THEME_NAME.script"
    sed -i "s|themes/firex|themes/$THEME_NAME|g; \
            s|firex\.script|$THEME_NAME.script|g" \
           "$PTH/$THEME_NAME.plymouth"
    for f in background logo title tagline byline bar track; do
        install -m 644 "$PROJ/board/splash/$f.png" "$PTH/$f.png"
    done

    # update-alternatives, not plymouth-set-default-theme: that helper is
    # not shipped on every release (Ubuntu dropped it, and the build fails
    # with "command not found" halfway through a ten-minute debootstrap).
    # The alternative is what the helper drove anyway, and it is also
    # exactly what the initramfs hook reads back, so this drives the real
    # mechanism rather than a wrapper around it.
    chroot "$MNT" /bin/bash -eu <<CHROOT
# The script plugin is what the theme asks for by ModuleName. Without it
# Plymouth falls back to text and the screen stays blank, so say so here
# rather than leaving someone to work it out from a dark monitor.
PLUGINS="\$(plymouth --get-splash-plugin-path 2>/dev/null || true)"
if [ -z "\$PLUGINS" ] || [ ! -f "\$PLUGINS/script.so" ]; then
    echo "plymouth has no script plugin in '\${PLUGINS:-unknown}'" >&2
    exit 1
fi

THEME_FILE=/usr/share/plymouth/themes/$THEME_NAME/$THEME_NAME.plymouth
# Priority 200 outranks the stock themes (bgrt is 110) so auto mode would
# pick it too; --set pins it regardless.
update-alternatives --install /usr/share/plymouth/themes/default.plymouth \\
                    default.plymouth "\$THEME_FILE" 200
update-alternatives --set default.plymouth "\$THEME_FILE"
CHROOT

    # Read it back the way initramfs-tools will: it takes the theme from
    # `update-alternatives --query`, not from the symlink or a config file.
    DEFAULT_THEME="$(chroot "$MNT" update-alternatives --query default.plymouth \
                     2>/dev/null | sed -n 's/^Value: //p' || true)"
    if [ "$DEFAULT_THEME" != \
         "/usr/share/plymouth/themes/$THEME_NAME/$THEME_NAME.plymouth" ]; then
        err "the default Plymouth theme is '${DEFAULT_THEME:-unset}',"
        err "not the one just installed for $THEME_NAME"
        exit 1
    fi
    log "  Plymouth theme '$THEME_NAME' is the default"

    # GRUB's menu, behind the same artwork. unicode.pf2 is the only font
    # the image has, and theme.txt names it, so a missing one means a menu
    # with no text at all -- worth catching here rather than on the screen.
    GTH="$MNT/boot/grub/themes/$THEME_NAME"
    mkdir -p "$GTH" "$MNT/boot/grub/fonts"
    install -m 644 "$PROJ/board/grub/themes/firex/theme.txt" "$GTH/theme.txt"
    install -m 644 "$PROJ/board/splash/grub.png" "$GTH/background.png"

    FONT=""
    for cand in "$MNT/usr/share/grub/unicode.pf2" \
                "$MNT/usr/share/grub/ascii.pf2"; do
        if [ -f "$cand" ]; then FONT="$cand"; break; fi
    done
    if [ -z "$FONT" ]; then
        err "no .pf2 font in the image; the graphical GRUB menu needs one"
        exit 1
    fi
    install -m 644 "$FONT" "$MNT/boot/grub/fonts/unicode.pf2"

    # GRUB matches a theme font by the name stored INSIDE the .pf2, not by
    # the file name. Get it wrong and the menu renders with no text and no
    # error. Read the name out of the font and check theme.txt asks for it.
    # grep -a rather than strings(1): binutils is not among this script's
    # requirements and should not become one for a cosmetic check.
    FONT_NAME="$(grep -ao '[A-Za-z][A-Za-z0-9 ]* Regular [0-9][0-9]*' \
                 "$FONT" 2>/dev/null | head -1 || true)"
    if [ -z "$FONT_NAME" ]; then
        log "  WARNING: could not read the font name out of $(basename "$FONT")"
    elif ! grep -qF "\"$FONT_NAME\"" "$GTH/theme.txt"; then
        err "theme.txt does not name the font that is being installed."
        err "  the font calls itself: $FONT_NAME"
        err "  theme.txt asks for:    $(grep -m1 -oP 'terminal-font: *"\K[^"]+' "$GTH/theme.txt")"
        err "Fix board/grub/themes/firex/theme.txt."
        exit 1
    fi
    log "  GRUB theme installed with $(basename "$FONT") (\"$FONT_NAME\")"
else
    log "Boot splash disabled (FIREX_BOOT_SPLASH=0)"
fi

log "Building initramfs"
mount -t tmpfs tmpfs "$MNT/run"
chroot "$MNT" /bin/bash -eu <<'CHROOT'
KVER="$(ls /lib/modules | head -1)"
update-initramfs -c -k "$KVER"
CHROOT
umount -lf "$MNT/run" 2>/dev/null || true

# The splash is only real if it reached the initramfs. initramfs-tools
# resolves the alternative, reads ModuleName out of the theme and copies
# the directory in; listing the result checks all of that at once, and
# checks it here rather than on a monitor that stays dark.
if [ "$BOOT_SPLASH" = 1 ]; then
    INITRD_LIST="$(chroot "$MNT" /bin/bash -c \
        'lsinitramfs "/boot/initrd.img-$(ls /lib/modules | head -1)"' \
        2>/dev/null || true)"
    if [ -z "$INITRD_LIST" ]; then
        log "  WARNING: could not list the initramfs; splash not verified"
    else
        SPLASH_OK=1
        printf '%s\n' "$INITRD_LIST" | grep -q "themes/$THEME_NAME/" || {
            err "the initramfs has no $THEME_NAME theme"; SPLASH_OK=0; }
        printf '%s\n' "$INITRD_LIST" | grep -q 'plymouth/script\.so' || {
            err "the initramfs has no plymouth script plugin"; SPLASH_OK=0; }
        printf '%s\n' "$INITRD_LIST" | grep -q "themes/$THEME_NAME/logo\.png" || {
            err "the initramfs has the theme but not its artwork"; SPLASH_OK=0; }
        if [ "$SPLASH_OK" != 1 ]; then
            err "the boot screen would not appear. Build with"
            err "FIREX_BOOT_SPLASH=0 to skip it, or fix the theme."
            exit 1
        fi
        log "  the initramfs carries the theme, its artwork and script.so"
    fi
fi

# ---- FireX ------------------------------------------------------------------
log "Installing FireX"
install -m 755 "$PROJ/firexd" "$MNT/usr/local/bin/firexd"
[ -x "$PROJ/flamewall" ] && install -m 755 "$PROJ/flamewall" "$MNT/usr/local/bin/flamewall" || true

# Built as ordinary directories and moved onto the data partition at the end
# (see "Moving configuration onto the data partition" below). They cannot be
# symlinks yet: /data/firex-config is an absolute path, and while the image
# is being assembled it resolves against the build host's root, not $MNT.
mkdir -p "$MNT/etc/firex" "$MNT/var/lib/firex/packages" \
         "$MNT/var/log/firex" "$MNT/usr/local/share/firex"

install -m 644 "$PROJ/config/firex.conf" "$MNT/etc/firex/firex.conf"
install -m 644 "$PROJ/config/rules.conf" "$MNT/etc/firex/rules.conf"
install -m 644 "$PROJ/config/rules.ids"      "$MNT/etc/firex/rules.ids"
install -m 644 "$PROJ/config/blocklist.txt"  "$MNT/etc/firex/blocklist.txt"
# The malware hash database. Ships empty: hashes are specific to whatever
# threat intelligence a site subscribes to, and a stale handful of them
# would suggest coverage that is not there. The built-in byte patterns
# run regardless, so the scanner is testable out of the box.
install -m 644 "$PROJ/config/malware.db"     "$MNT/etc/firex/malware.db"

# Seed the FireX console accounts. The host binary only writes a crypt(3)
# hash into a text file, so it does not need the chroot.
#
# root is enrolled here as well as in /etc/shadow so that the credential an
# operator was given for SSH also opens the web console. Without it, signing
# in at http://<appliance>:8080/ui as root fails with no explanation -- the
# two databases are invisible from the outside.
log "Seeding console accounts (admin, root)"
seed_console_account() {
    # shellcheck disable=SC2086  # $3 is one optional flag or nothing
    if ! printf '%s\n' "$2" | "$PROJ/firexd" --passwd "$1" --role admin \
            $3 --users "$MNT/etc/firex/users"; then
        err "could not create the '$1' console account"
        exit 1
    fi
}
seed_console_account admin "$ADMIN_PW" "$WEAK_ADMIN"
seed_console_account root  "$ROOT_PW"  "$WEAK_ROOT"
chmod 600 "$MNT/etc/firex/users"

if [ "$(grep -c '^admin:' "$MNT/etc/firex/users")" != 1 ] ||
   [ "$(grep -c '^root:'  "$MNT/etc/firex/users")" != 1 ]; then
    err "the console user file is not what was asked for:"
    cut -d: -f1,3 "$MNT/etc/firex/users" >&2
    exit 1
fi
[ -f "$PROJ/xdp/xdp_firewall.bpf.o" ] && \
    install -m 644 "$PROJ/xdp/xdp_firewall.bpf.o" "$MNT/usr/local/share/firex/" || true

# Overlay ships the units and the segmentation scripts
rsync -a "$PROJ/board/rootfs_overlay/" "$MNT/"

# Brand placeholders in the overlay, filled from include/brand.h. The unit
# descriptions and the sysvinit banner used to carry the vendor name
# literally, so a re-skin left the old name showing in `systemctl status`
# -- visible on every appliance, and nothing in the build complained.
log "Branding the overlay as $BRAND_FULL_"

# Documentation= with no documentation site is a line pointing nowhere,
# so when BRAND_DOC_URL is empty the line is removed rather than left
# blank. Nine units carried a previous vendor's docs URL literally; now
# they carry a placeholder that this fills or deletes.
if [ -z "${BRAND_DOC_:-}" ]; then
    find "$MNT/etc/systemd/system" -name '*.service' -exec \
        sed -i '/^Documentation=@BRAND_DOC@$/d' {} + 2>/dev/null || true
else
    find "$MNT/etc/systemd/system" -name '*.service' -exec \
        sed -i "s|@BRAND_DOC@|$BRAND_DOC_|" {} + 2>/dev/null || true
fi
while IFS= read -r f; do
    sed -i -e "s|@BRAND_FULL@|$BRAND_FULL_|g" \
           -e "s|@BRAND_PRODUCT@|$BRAND_PRODUCT_|g" \
           -e "s|@BRAND_VENDOR@|$BRAND_VENDOR_|g" \
           -e "s|@BRAND_TAGLINE@|$BRAND_TAGLINE_|g" \
           -e "s|@BRAND_SUPPORT@|$BRAND_SUPPORT_|g" "$f"
done < <(grep -rlE '@BRAND_(FULL|PRODUCT|VENDOR|TAGLINE|SUPPORT)@' \
            "$MNT/etc" "$MNT/usr/local/bin" 2>/dev/null || true)

# Nothing may reach the image still holding a placeholder.
if grep -rlE '@BRAND_[A-Z]+@' "$MNT/etc" "$MNT/usr/local/bin" 2>/dev/null \
     | grep -q .; then
    err "a @BRAND_...@ placeholder survived into the image"
    grep -rlE '@BRAND_[A-Z]+@' "$MNT/etc" "$MNT/usr/local/bin" 2>/dev/null >&2
    exit 1
fi
chmod +x "$MNT/etc/firex/segmentation-up.sh" "$MNT/etc/firex/segmentation-down.sh"
# The sysvinit copies are for Buildroot targets; systemd ignores them.
chmod +x "$MNT/etc/init.d/S15segmentation" "$MNT/etc/init.d/S20firex" 2>/dev/null || true

# ---- A/B update machinery ---------------------------------------------------
log "Setting up A/B slots"

# Trusted update keys. FIREX_UPDATE_KEY names a keyring line produced by
# "firex-bundle keygen"; without one the appliance still boots, and
# refuses every update it is offered, which is the safe default.
if [ -n "${FIREX_UPDATE_KEY:-}" ] && [ -f "$FIREX_UPDATE_KEY" ]; then
    install -m 644 "$FIREX_UPDATE_KEY" "$MNT/etc/firex/update-keys"
    UPDATE_KEY_STATE="trusted ($(basename "$FIREX_UPDATE_KEY"))"
    log "  trusted update key installed from $FIREX_UPDATE_KEY"
else
    cat > "$MNT/etc/firex/update-keys" <<'EOF'
# Trusted FireX update signing keys, one per line:
#
#   <base64 Ed25519 public key> <comment>
#
# Generate a pair on a build host with:
#
#   firex-bundle keygen --out firex-signing
#
# and copy the contents of firex-signing.pub here. Until a key is listed,
# every update bundle is refused: an appliance that trusts no key cannot
# be updated, but it also cannot be updated by someone else.
EOF
    chmod 644 "$MNT/etc/firex/update-keys"
    UPDATE_KEY_STATE="none -- every update bundle will be refused"
    log "  no FIREX_UPDATE_KEY given; updates will be refused until a key is added"
fi

# Initial slot state: this build is slot A and it is known good; slot B is
# formatted but empty, so the first update has somewhere to land.
cat > "$MNT/var/lib/firex/slots.conf" <<EOF
# FireX A/B slot state -- written by firexd, do not hand-edit
running = a
next = a

a.state = good
a.version = $(grep -oP '#define BRAND_VERSION\s+"\K[^"]+' "$PROJ/include/brand.h")
a.label = firex-root-a
a.tries = 0
a.installed = $(date +%s)

b.state = unused
b.version =
b.label = firex-root-b
b.tries = 0
b.installed = 0
EOF

# grub.cfg addresses the kernel through these stable names, so a slot can
# ship a different kernel version without the bootloader being rewritten.
KREL="$(ls "$MNT/boot" | grep -oP '^vmlinuz-\K.*' | sort -V | tail -1)"
if [ -z "$KREL" ]; then
    err "no kernel found in /boot; cannot set up A/B boot"
    exit 1
fi
ln -sfn "vmlinuz-$KREL"    "$MNT/boot/vmlinuz"
ln -sfn "initrd.img-$KREL" "$MNT/boot/initrd.img"
log "  kernel $KREL, /boot/vmlinuz and /boot/initrd.img point at it"

# Integrity hash the init script optionally checks
sha256sum "$MNT/usr/local/bin/firexd" | awk '{print $1}' > "$MNT/etc/firex/firexd.sha256"

# ---- desktop console --------------------------------------------------------
if [ "$DESKTOP" = 1 ]; then
    log "Installing the desktop console ($SCREEN)"

    if [ ! -x "$PROJ/flamewall" ]; then
        err "flamewall is not built. Run: make"
        err "Or build without the desktop console: FIREX_DESKTOP=0"
        exit 1
    fi
    install -m 755 "$PROJ/flamewall" "$MNT/usr/local/bin/flamewall"

    # The login screen shows this; without it the panel is just text.
    install -m 644 "$PROJ/board/splash/logo.png" \
                   "$MNT/usr/local/share/firex/logo.png"

    # Written where the console looks for it, not into whatever directory
    # it happens to be started from.
    #
    # This has to happen BEFORE /etc/firex is moved to the data partition
    # and replaced by an absolute symlink: after that, writing here
    # follows /data/firex-config, which during the build resolves against
    # the BUILD HOST's root rather than the image's.
    if [ -L "$MNT/etc/firex" ]; then
        err "/etc/firex is already a symlink; this step must run before"
        err "the move to the data partition, or it writes to the host."
        exit 1
    fi
    mkdir -p "$MNT/etc/firex"
    cat > "$MNT/etc/firex/console.conf" <<EOF
# Desktop console settings. Read by firex-gui and firex-session.
screen = $SCREEN
EOF

    # Xorg: one screen, at the size the rest of the image was built for.
    # Without the Display subsection the server takes the largest mode the
    # adapter claims, which under VirtualBox is not the one GRUB set.
    mkdir -p "$MNT/etc/X11/xorg.conf.d"
    cat > "$MNT/etc/X11/xorg.conf.d/10-firex.conf" <<EOF
# Generated by tools/build-image.sh -- rebuild the image to change it,
# or edit screen= in /etc/firex/console.conf for the window only.
Section "Monitor"
    Identifier  "firex-monitor"
    # A conservative mode line for $SCREEN, used when the adapter offers
    # no EDID at all -- which is the normal case in a virtual machine.
    Option      "PreferredMode" "${SCREEN}"
EndSection

Section "Device"
    Identifier  "firex-video"
    # Driver deliberately unset: X picks modesetting when there is a DRM
    # device and falls back to fbdev or vesa when there is not. Naming one
    # here would break the other half of the machines this image runs on.
EndSection

Section "Screen"
    Identifier  "firex-screen"
    Device      "firex-video"
    Monitor     "firex-monitor"
    DefaultDepth 24
    SubSection "Display"
        Depth   24
        Modes   "${SCREEN}" "1024x768" "800x600"
    EndSubSection
EndSection

Section "ServerFlags"
    Option      "BlankTime"   "0"
    Option      "StandbyTime" "0"
    Option      "SuspendTime" "0"
    Option      "OffTime"     "0"
    Option      "DontVTSwitch" "false"
EndSection
EOF

    chroot "$MNT" /bin/bash -eu <<'CHROOT'
if [ ! -x /usr/bin/startx ]; then
    echo "xinit did not install; the desktop console cannot start" >&2
    exit 1
fi
if ! ldconfig -p | grep -q libgtk-4; then
    echo "GTK4 did not install; flamewall will not run" >&2
    exit 1
fi
systemctl enable firex-gui.service
CHROOT

    # The binary has to actually run in THIS rootfs, not just on the build
    # host. --help needs no display, so it is the cheap half of the check.
    if ! chroot "$MNT" /usr/local/bin/flamewall --help >/dev/null 2>&1; then
        err "flamewall will not run inside the image:"
        chroot "$MNT" /usr/local/bin/flamewall --help 2>&1 | head -5 >&2
        err "Almost certainly a GTK version mismatch between this host and"
        err "the '$SUITE' rootfs. Build without it: FIREX_DESKTOP=0"
        exit 1
    fi
    log "  flamewall runs inside the image; firex-gui.service enabled"
else
    log "Desktop console left out (FIREX_DESKTOP=0)"
fi

# ---- Moving configuration onto the data partition ---------------------------
# Everything above wrote to /etc/firex and /var/lib/firex as real directories
# in the root slot. Move them to the data partition now and leave symlinks
# behind, so both slots read the same configuration and an update or rollback
# of either slot never moves it.
#
# This has to happen after the last writer and before anything reads these
# paths through the chroot, which is why it sits here rather than earlier.
log "Moving configuration onto the data partition"
for pair in "etc/firex:data/firex-config" "var/lib/firex:data/firex-state"; do
    src="$MNT/${pair%%:*}"
    dst="$MNT/${pair##*:}"
    [ -L "$src" ] && { err "$src is already a symlink; refusing to move it"; exit 1; }
    [ -d "$src" ] || { err "$src is missing; the build did not populate it"; exit 1; }

    mkdir -p "$dst"
    cp -a "$src/." "$dst/"
    rm -rf "$src"
    ln -sfn "/${pair##*:}" "$src"
done

# The symlinks are only correct from inside the image. Check them there,
# where /data is the mounted partition rather than a path on the build host.
chroot "$MNT" /bin/sh -c '
    [ -f /etc/firex/firex.conf ] || { echo "firex.conf unreachable"; exit 1; }
    [ -f /var/lib/firex/slots.conf ] || { echo "slots.conf unreachable"; exit 1; }
' || { err "the configuration symlinks do not resolve inside the image"; exit 1; }
log "  /etc/firex and /var/lib/firex now live on the data partition"

# ---- system identity --------------------------------------------------------
echo "$HOSTNAME_" > "$MNT/etc/hostname"
cat > "$MNT/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   $HOSTNAME_
EOF

# No entry for "/": its label is firex-root-a or firex-root-b depending on
# which slot booted, and the kernel already knows which from root=LABEL=...
# on its command line. Naming one of them here would mount the wrong root
# after an update.
#
# The catch is that systemd-remount-fs is what turns the root read-write
# again, and it does that from this file -- so with no entry the root
# stayed read-only for good. firex-rootfs-rw.service remounts it by
# mount point instead, which needs no label and so survives a slot swap.
cat > "$MNT/etc/fstab" <<EOF
LABEL=FIREX-ESP    /boot/efi  vfat  umask=0077         0 1
LABEL=firex-data   /data      ext4  defaults           0 2
EOF

cat > "$MNT/etc/motd" <<EOF

  ###### #  #####  ###### #    #
  #      #  #    # #       #  #
  #####  #  #####  #####    ##
  #      #  #  #   #        ##
  #      #  #   #  #       #  #
  #      #  #    # ###### #    #
        by $BRAND_VENDOR_ - $BRAND_TAGLINE_

  Config   : /etc/firex/firex.conf
  History  : /etc/firex/config.d/  (versioned, rollback from the console)
  Review   : firexd --dump  -c /etc/firex/firex.conf
  Validate : firexd --check -c /etc/firex/firex.conf
  Console  : http://<gateway>:8080/ui
  Desktop  : firex-gui          (the console on this machine's own screen)
             firex-gui --check  (says why it would not start)
  Service  : systemctl status firexd
  Logs     : journalctl -u firexd -f

  Shipped credentials -- root / root  and  admin / admin.
  Both sign in over SSH and at the web console. Change them under
  System in the web console, or here with:
      passwd root
      firexd --passwd admin --users /etc/firex/users

EOF

# OpenSSH defaults to PermitRootLogin prohibit-password, which would make
# the root password documented on the last page of this build work on the
# console and nowhere else. The appliance ships reachable, so this is on by
# default; FIREX_SSH_ROOT_PASSWORD=0 keeps root to the console and leaves
# admin as the SSH account.
mkdir -p "$MNT/etc/ssh/sshd_config.d"
if [ "${FIREX_SSH_ROOT_PASSWORD:-1}" = 1 ]; then
    log "Enabling password login over SSH for root and admin"
    cat > "$MNT/etc/ssh/sshd_config.d/10-firex.conf" <<'EOF'
# FireX ships reachable. Both shipped accounts sign in with a password:
#     root  / root     admin / admin
# Change them in the web console under System, or with passwd(1), before
# this appliance faces a network you do not control. On anything exposed,
# install a key and set PasswordAuthentication no here.
PermitRootLogin yes
PasswordAuthentication yes
EOF
else
    log "SSH root password login disabled (FIREX_SSH_ROOT_PASSWORD=0)"
    cat > "$MNT/etc/ssh/sshd_config.d/10-firex.conf" <<'EOF'
# root is console-only in this build; admin is the SSH account.
PermitRootLogin prohibit-password
PasswordAuthentication yes
EOF
fi

# The passwords travel in the environment, and the heredoc below is
# QUOTED so they are expanded by the shell inside the chroot rather than
# pasted into the script text. Interpolated, a password holding a '$' or
# a backtick would be mangled on its way in -- or run as a command.
ROOT_PW="$ROOT_PW" ADMIN_PW="$ADMIN_PW" chroot "$MNT" /bin/bash -eu <<'CHROOT'
echo "root:$ROOT_PW" | chpasswd

# admin is a real Linux account too, so the pair handed out for the web
# console also works over SSH. In sudo rather than given uid 0: a shared
# login that is already root logs nothing about who did what.
if ! id -u admin >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash --groups sudo admin
fi
echo "admin:$ADMIN_PW" | chpasswd
systemctl enable firex-segmentation.service
systemctl enable firexd.service
systemctl enable ssh
# Without this the root filesystem stays read-only for the whole life of
# the appliance: the kernel is handed "ro" so it can be checked, and
# there is no "/" line in fstab to turn it back. sshd then cannot write
# its host keys, logind cannot write its state and the X server cannot
# open its log, so the desktop console fails five times and gives up.
systemctl enable firex-rootfs-rw.service
# The image ships no SSH host keys on purpose -- see the unit.
systemctl enable firex-sshd-keygen.service
# Nothing in /etc/network/interfaces brings a port up, so without this
# the appliance boots with every link down and nothing can reach it.
systemctl enable firex-mgmt-link.service
# A/B accounting: one unit spends a boot attempt before firexd starts, the
# other clears it once firexd is actually running.
systemctl enable firex-boot-check.service
systemctl enable firex-confirm.service
# dnsmasq is driven by firexd, not by its own unit
systemctl disable dnsmasq 2>/dev/null || true
CHROOT

# The serial console menu replaces the login prompt on ttyS0. It asks for a
# console password of its own before showing anything, so this is not a way
# past authentication -- but it does mean the serial port leads to the menu
# rather than to a shell. Set FIREX_CONSOLE_MENU=0 to keep the plain getty.
if [ "${FIREX_CONSOLE_MENU:-1}" = 1 ]; then
    log "Enabling the serial console menu on ttyS0"
    chroot "$MNT" /bin/bash -eu <<'CHROOT'
systemctl disable serial-getty@ttyS0.service 2>/dev/null || true
systemctl mask    serial-getty@ttyS0.service 2>/dev/null || true
systemctl enable  firex-console.service
CHROOT
else
    log "Serial console menu left disabled (FIREX_CONSOLE_MENU=0)"
fi

# ---- verify the binary actually runs in this rootfs -------------------------
log "Checking firexd runs inside the image"
if chroot "$MNT" /usr/local/bin/firexd --help >/dev/null 2>&1; then
    log "  firexd executes cleanly"
else
    err "firexd will not run inside the image - almost certainly a library"
    err "mismatch between the build host and the '$SUITE' rootfs."
    chroot "$MNT" /usr/local/bin/firexd --help 2>&1 | head -5 >&2
    exit 1
fi

if ! chroot "$MNT" /usr/local/bin/firexd --dump -c /etc/firex/firex.conf \
        >/dev/null 2>&1; then
    err "firexd could not parse /etc/firex/firex.conf inside the image"
    exit 1
fi
log "  config parses inside the image"

# ---- bootloader -------------------------------------------------------------
log "Installing GRUB (BIOS + UEFI)"

# eth0/eth1 naming keeps firex.conf's interface names meaningful, and the
# serial console makes the appliance usable headless and under QEMU.
cat > "$MNT/etc/default/grub" <<'EOF'
GRUB_DEFAULT=0
GRUB_TIMEOUT=3
GRUB_DISTRIBUTOR="FireX"
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
# tty0 last: the kernel points /dev/console at the final console=, and
# Plymouth follows /dev/console. With ttyS0 last the splash renders as text
# down the serial line and the screen stays blank.
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 console=ttyS0,115200n8 console=tty0"
GRUB_TERMINAL_INPUT="console serial"
GRUB_TERMINAL_OUTPUT="gfxterm serial"
GRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"
GRUB_GFXMODE=SCREENMODE,1024x768,800x600,auto
GRUB_GFXPAYLOAD_LINUX=keep
GRUB_THEME=/boot/grub/themes/THEMENAME/theme.txt
GRUB_BACKGROUND=/boot/grub/themes/THEMENAME/background.png
EOF
sed -i "s|THEMENAME|$THEME_NAME|g; s|SCREENMODE|$SCREEN|g" "$MNT/etc/default/grub"
# firexd --write-grub produces the grub.cfg this image actually boots, so
# the file above only matters if somebody runs update-grub on the appliance
# -- at which point the A/B entries would be replaced by single-root ones.
# Keeping the two in step means that mistake costs the slots, not the splash.
if [ "$BOOT_SPLASH" != 1 ]; then
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=""/' \
        "$MNT/etc/default/grub"
fi

# $LOOP is expanded by this shell, not inside the chroot, so re-assert it
# immediately before the command that writes a boot sector.
case "$LOOP" in
    /dev/loop[0-9]*) ;;
    *) err "refusing to run grub-install against '$LOOP'"; exit 1 ;;
esac

chroot "$MNT" /bin/bash -eu <<CHROOT
grub-install --target=x86_64-efi --efi-directory=/boot/efi \
             --bootloader-id=FireX --removable --no-nvram >/dev/null 2>&1
grub-install --target=i386-pc --boot-directory=/boot "$LOOP" >/dev/null 2>&1
CHROOT

# update-grub is deliberately not used. It generates entries for the root it
# probes, which is the build host's loop device, and it knows nothing about
# the second slot. The A/B grub.cfg comes from firexd instead, so the entries
# the bootloader offers and the slot state the appliance acts on are rendered
# by one piece of code and cannot drift apart.
log "Generating the A/B grub.cfg"
SPLASH_ARG=""
if [ "$BOOT_SPLASH" != 1 ]; then SPLASH_ARG="--no-splash"; fi
# shellcheck disable=SC2086  # one optional flag or nothing
"$PROJ/firexd" --write-grub "$MNT/boot/grub/grub.cfg" $SPLASH_ARG \
               --gfxmode "$SCREEN" \
               --slots-file "$MNT/data/firex-state/slots.conf"

# The screen size has to be the same in all three places or the console
# comes up letterboxed on a framebuffer of a different shape.
if ! grep -q "set gfxmode=$SCREEN," "$MNT/boot/grub/grub.cfg"; then
    err "grub.cfg does not set the video mode to $SCREEN"
    exit 1
fi
if [ "$DESKTOP" = 1 ] &&
   ! grep -q "\"$SCREEN\"" "$MNT/etc/X11/xorg.conf.d/10-firex.conf"; then
    err "the Xorg config does not pin $SCREEN"
    exit 1
fi

# The splash is two halves that have to agree: a theme on disk and "splash"
# on the kernel line. Either one alone is a black screen with no clue why.
if [ "$BOOT_SPLASH" = 1 ]; then
    if ! grep -q ' splash' "$MNT/boot/grub/grub.cfg"; then
        err "the splash was installed but grub.cfg does not ask for it"
        exit 1
    fi
    if ! grep -q "set theme=.*themes/$THEME_NAME/theme.txt" \
            "$MNT/boot/grub/grub.cfg"; then
        err "grub.cfg does not reference the GRUB theme"
        exit 1
    fi
    for f in "$MNT/boot/grub/themes/$THEME_NAME/theme.txt" \
             "$MNT/boot/grub/themes/$THEME_NAME/background.png" \
             "$MNT/boot/grub/fonts/unicode.pf2"; do
        [ -f "$f" ] || { err "grub.cfg points at a theme but $f is missing"; exit 1; }
    done
    log "  splash: Plymouth theme, GRUB theme and kernel argument all present"
elif grep -q ' splash' "$MNT/boot/grub/grub.cfg"; then
    err "the splash is disabled but grub.cfg still asks for it"
    exit 1
fi

# Both slots boot by filesystem label, so there is no UUID to substitute and
# no loop device that can leak into the config. Prove it rather than assume.
if grep -qE '/dev/loop|root=UUID=' "$MNT/boot/grub/grub.cfg"; then
    err "grub.cfg names a device instead of a slot label"
    grep -nE '/dev/loop|root=UUID=' "$MNT/boot/grub/grub.cfg" | head -3 >&2
    exit 1
fi
for lbl in firex-root-a firex-root-b; do
    grep -q "root=LABEL=$lbl" "$MNT/boot/grub/grub.cfg" || {
        err "grub.cfg has no entry for $lbl"; exit 1; }
done
log "  both slots have boot entries"

# ---- verify the image can actually boot ------------------------------------
log "Verifying boot configuration"
BOOT_OK=1

INITRD="$(ls "$MNT"/boot/initrd.img-* 2>/dev/null | head -1)"
if [ -z "$INITRD" ]; then
    err "no /boot/initrd.img-* was produced"
    BOOT_OK=0
elif [ "$(stat -c %s "$INITRD")" -lt 5000000 ]; then
    err "initramfs is suspiciously small: $(stat -c %s "$INITRD") bytes"
    BOOT_OK=0
else
    log "  initramfs: $(basename "$INITRD") ($(du -h "$INITRD" | cut -f1))"
fi

if ! grep -qE '^[[:space:]]*initrd[[:space:]]' "$MNT/boot/grub/grub.cfg"; then
    err "grub.cfg has no initrd line - the kernel will panic on boot"
    BOOT_OK=0
else
    log "  grub.cfg references the initramfs"
fi

if grep -q '/dev/loop' "$MNT/boot/grub/grub.cfg"; then
    err "grub.cfg still points at a loop device; it will not boot elsewhere"
    grep -n '/dev/loop' "$MNT/boot/grub/grub.cfg" | head -3 >&2
    BOOT_OK=0
else
    # A/B boots by filesystem label, not by UUID: the label is the only
    # thing that stays put when a slot is rewritten by an update. Check
    # that grub names both slots AND that the filesystems really carry
    # those labels -- a mismatch between the two is a kernel panic on a
    # machine that is no longer in front of you.
    for lbl in firex-root-a firex-root-b; do
        if ! grep -q "root=LABEL=$lbl" "$MNT/boot/grub/grub.cfg"; then
            err "grub.cfg has no boot entry for $lbl"
            BOOT_OK=0
        fi
    done
    for part in 3:firex-root-a 4:firex-root-b 5:firex-data; do
        n="${part%%:*}"; want="${part##*:}"
        got="$(blkid -s LABEL -o value "${LOOP}p${n}" 2>/dev/null || true)"
        if [ "$got" != "$want" ]; then
            err "partition $n is labelled '${got:-none}', expected '$want'"
            BOOT_OK=0
        fi
    done
    if [ "$BOOT_OK" = 1 ]; then
        log "  both slots boot by label, and the labels match the filesystems"
    fi
fi

[ -f "$MNT/boot/efi/EFI/BOOT/BOOTX64.EFI" ] \
    && log "  UEFI loader present" \
    || { err "no EFI loader at /boot/efi/EFI/BOOT/BOOTX64.EFI"; BOOT_OK=0; }

if [ "$BOOT_OK" != 1 ]; then
    err "image would not boot - refusing to finish"
    exit 1
fi

# ---- trim and sparsify ------------------------------------------------------
log "Trimming the image"
rm -rf "$MNT"/usr/share/doc/* "$MNT"/usr/share/man/* \
       "$MNT"/usr/share/info/* "$MNT"/usr/share/groff/* 2>/dev/null || true
if [ -d "$MNT/usr/share/locale" ]; then
    find "$MNT/usr/share/locale" -mindepth 1 -maxdepth 1 -type d \
         ! -name 'en*' ! -name 'C*' -exec rm -rf {} + 2>/dev/null || true
fi
find "$MNT/var/log" -type f -exec truncate -s 0 {} + 2>/dev/null || true

# firexd rewrites this for a static WAN and dhclient rewrites it for DHCP;
# this is only a sane value for the window before either has run.
cat > "$MNT/etc/resolv.conf" <<'RESOLV'
nameserver 1.1.1.1
nameserver 9.9.9.9
RESOLV

# Every machine flashed from this image would otherwise share one identity.
# Both regenerate on first boot.
: > "$MNT/etc/machine-id" 2>/dev/null || true
rm -f "$MNT"/var/lib/systemd/random-seed "$MNT"/etc/ssh/ssh_host_*_key* 2>/dev/null || true

log "Filesystem used: $(df -h "$MNT" | awk 'NR==2{print $3}')"

# Deleted blocks keep their old contents, so the host file still has them
# allocated. Zero the free space, then punch those blocks out below.
log "Zero-filling free space"
dd if=/dev/zero of="$MNT/.zerofill" bs=4M status=none 2>/dev/null || true
sync
rm -f "$MNT/.zerofill"
sync

# ---- finish -----------------------------------------------------------------
sync
cleanup
trap - EXIT

log "Punching holes in the image file"
fallocate --dig-holes "$OUT" 2>/dev/null || true

SZ="$(du -h --apparent-size "$OUT" | cut -f1)"
USED="$(du -h "$OUT" | cut -f1)"

cat <<EOF

=============================================================
  FireX appliance image ready
=============================================================
  Image     : $OUT
  Virtual   : $SZ   (on disk: $USED, sparse)
  Boot      : BIOS + UEFI (GPT)
  Interfaces: eth0, eth1, ... (predictable naming disabled)

  Test in QEMU:
      tools/run-qemu.sh

  Write to a USB stick or SSD (DESTROYS the target):
      sudo dd if=$OUT of=/dev/sdX bs=4M status=progress conv=fsync

EOF

cat <<EOF
  Credentials
  -----------
    root  / $ROOT_PW
    admin / $ADMIN_PW

    Each pair works in both places: SSH and the shell (the Linux account),
    and the web console at http://<appliance>:8080/ui plus the serial menu
    (the FireX account). admin is in the sudo group, not uid 0.

EOF
if [ "$DEFAULT_ROOT_PW" = 1 ] || [ "$DEFAULT_ADMIN_PW" = 1 ]; then
    cat <<EOF
  !! This image ships with its default passwords. Anyone who can reach
     port 22 or port 8080 knows them. The web console says so on every
     page until they are changed -- System -> Accounts changes both.

     Build with your own instead:
         sudo env FIREX_ROOT_PASSWORD=... FIREX_ADMIN_PASSWORD=... \\
              tools/build-image.sh

EOF
fi

# ---- completion marker ------------------------------------------------------
# Written only here, after every step has succeeded. run-qemu.sh,
# to-virtualbox.sh and shrink-image.sh refuse to touch an image without it.
cat > "$OUT.manifest" <<EOF
# FireX image manifest -- written when the build completed.
image = $OUT
version = $(grep -oP '#define BRAND_VERSION\s+"\K[^"]+' "$PROJ/include/brand.h")
built = $(date -u +%Y-%m-%dT%H:%M:%SZ)
size = $SIZE
suite = $SUITE
kernel = $KREL
layout = ab
slots = firex-root-a firex-root-b
data = firex-data
console_menu = ${FIREX_CONSOLE_MENU:-1}
update_keys = $UPDATE_KEY_STATE
splash = $BOOT_SPLASH
desktop = $DESKTOP
screen = $SCREEN
default_passwords = $(( DEFAULT_ROOT_PW + DEFAULT_ADMIN_PW ))
EOF
chown "$(stat -c '%u:%g' "$OUT")" "$OUT.manifest" 2>/dev/null || true

echo "  Edit /etc/firex/firex.conf on the appliance for your real interfaces."
echo
