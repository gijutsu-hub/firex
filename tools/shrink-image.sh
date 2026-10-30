#!/bin/bash
# =============================================================================
#  Shrink a built FireX appliance image.
#
#  Two separate wins:
#
#    1. Content   - apt package metadata, docs, man pages and translations are
#                   dead weight on an appliance. A dpkg exclude rule is left
#                   behind so later apt installs do not put them back.
#    2. Sparsity  - deleted files leave their old blocks allocated in the host
#                   file. Zero-filling the free space and then punching holes
#                   collapses the image to roughly what it actually holds.
#
#  Run on an image that is NOT currently being built, as root:
#      sudo tools/shrink-image.sh
# =============================================================================
set -euo pipefail

RESIZE=0
SLACK_MB="${FIREX_SLACK_MB:-400}"
for a in "$@"; do
    case "$a" in
        --resize) RESIZE=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 1 ;;
    esac
done

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${FIREX_IMAGE:-$PROJ/build/firex.img}"
MNT="$PROJ/build/shrinkroot"

# An image file exists as soon as the builder calls truncate, long before it
# is bootable. The manifest is written only when the build finished, so it is
# the one way to tell a finished image from a partial one -- the partition
# table and filesystems of a half-built image look entirely normal.
if [ ! -f "$IMG.manifest" ]; then
    echo "" >&2
    echo "$IMG has no build manifest." >&2
    echo "" >&2
    echo "  That means the build did not finish. A partial image still has a" >&2
    echo "  partition table and a real filesystem in it, so nothing else here" >&2
    echo "  can tell it apart from a working one -- it simply will not boot." >&2
    echo "" >&2
    echo "  Build it again:" >&2
    echo "      sudo env FIREX_UPDATE_KEY=\"\$PWD/firex-signing.pub\" tools/build-image.sh" >&2
    echo "" >&2
    echo "  If you really meant to use this image, set FIREX_ALLOW_UNVERIFIED=1." >&2
    echo "" >&2
    [ "${FIREX_ALLOW_UNVERIFIED:-0}" = 1 ] || exit 1
    echo "  FIREX_ALLOW_UNVERIFIED=1 -- continuing with an unverified image." >&2
fi

LOOP=""
MOUNTED=0

log() { printf '\033[1;36m[shrink]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[shrink] ERROR:\033[0m %s\n' "$*" >&2; }

cleanup() {
    set +e
    [ "$MOUNTED" = 1 ] && umount -lf "$MNT" 2>/dev/null
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    set -e
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { err "must run as root (sudo tools/shrink-image.sh)"; exit 1; }
[ -f "$IMG" ] || { err "no image at $IMG"; exit 1; }

# Refuse to touch an image a build is still writing.
if pgrep -f 'build-image\.sh' >/dev/null 2>&1; then
    err "build-image.sh is still running - wait for it to finish"
    exit 1
fi
if losetup -a 2>/dev/null | grep -q "$(basename "$IMG")"; then
    err "$IMG is still attached to a loop device:"
    losetup -a | grep "$(basename "$IMG")" >&2
    err "unmount and detach it first"
    exit 1
fi

BEFORE_ALLOC="$(du -h "$IMG" | cut -f1)"
BEFORE_BYTES="$(du -B1 "$IMG" | cut -f1)"
log "Before: $BEFORE_ALLOC allocated ($(du -h --apparent-size "$IMG" | cut -f1) apparent)"

mkdir -p "$MNT"
LOOP="$(losetup --find --show --partscan "$IMG")"
sleep 1
mount "${LOOP}p3" "$MNT"
MOUNTED=1

USED_BEFORE="$(df -h "$MNT" | awk 'NR==2{print $3}')"

# ---- content -----------------------------------------------------------------
log "Removing apt package metadata"
rm -rf "$MNT"/var/lib/apt/lists/* 2>/dev/null || true
rm -rf "$MNT"/var/cache/apt/archives/*.deb 2>/dev/null || true
rm -rf "$MNT"/var/cache/apt/*.bin 2>/dev/null || true

log "Removing documentation and man pages"
rm -rf "$MNT"/usr/share/doc/* "$MNT"/usr/share/man/* \
       "$MNT"/usr/share/info/* "$MNT"/usr/share/groff/* \
       "$MNT"/usr/share/lintian/* "$MNT"/usr/share/linda/* 2>/dev/null || true

log "Removing translations (keeping C and en)"
if [ -d "$MNT/usr/share/locale" ]; then
    find "$MNT/usr/share/locale" -mindepth 1 -maxdepth 1 -type d \
         ! -name 'en*' ! -name 'C*' -exec rm -rf {} + 2>/dev/null || true
fi

# Keep it off for anything installed later on the appliance itself.
log "Installing dpkg exclude rules so this does not come back"
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

log "Clearing logs and machine identity"
find "$MNT/var/log" -type f -exec truncate -s 0 {} + 2>/dev/null || true
# A cloned appliance must not reuse one machine-id across every install.
: > "$MNT/etc/machine-id" 2>/dev/null || true
rm -f "$MNT"/var/lib/systemd/random-seed 2>/dev/null || true
rm -f "$MNT"/etc/ssh/ssh_host_*_key* 2>/dev/null || true

USED_AFTER="$(df -h "$MNT" | awk 'NR==2{print $3}')"
log "Filesystem used: $USED_BEFORE -> $USED_AFTER"

# ---- sparsity ----------------------------------------------------------------
# Deleted blocks keep their old contents, so the host file still has them
# allocated. Write zeros across the free space, then punch those out.
log "Zero-filling free space (this takes a minute)"
dd if=/dev/zero of="$MNT/.zerofill" bs=4M status=none 2>/dev/null || true
sync
rm -f "$MNT/.zerofill"
sync

umount "$MNT"
MOUNTED=0

# ---- shrink to fit (opt-in) --------------------------------------------------
# Trimming frees space inside the filesystem but the image file stays its
# original size. This shrinks the filesystem, the partition and the file so
# the image is actually small - which matters when writing it with dd.
if [ "$RESIZE" = 1 ]; then
    log "Shrinking filesystem to its minimum"
    e2fsck -fy "${LOOP}p3" >/dev/null 2>&1 || true
    resize2fs -M "${LOOP}p3" >/dev/null

    BS="$(dumpe2fs -h "${LOOP}p3" 2>/dev/null | awk -F': *' '/Block size/{print $2}')"
    MINBLK="$(dumpe2fs -h "${LOOP}p3" 2>/dev/null | awk -F': *' '/Block count/{print $2}')"
    [ -n "$BS" ] && [ -n "$MINBLK" ] || { err "could not read filesystem geometry"; exit 1; }

    SLACKBLK=$(( SLACK_MB * 1024 * 1024 / BS ))
    TARGET=$(( MINBLK + SLACKBLK ))
    log "Growing back to leave ${SLACK_MB}MB free for the running appliance"
    resize2fs "${LOOP}p3" "$TARGET" >/dev/null
    e2fsck -fy "${LOOP}p3" >/dev/null 2>&1 || true

    FSBYTES=$(( TARGET * BS ))
    START="$(sgdisk -i 3 "$IMG" 2>/dev/null | awk '/First sector/{print $3}')"
    [ -n "$START" ] || { err "could not read partition 3 start sector"; exit 1; }
    NEWEND=$(( START + FSBYTES / 512 - 1 ))

    losetup -d "$LOOP"; LOOP=""

    log "Resizing partition 3 -> sectors $START..$NEWEND"
    sgdisk -d 3 -n "3:${START}:${NEWEND}" -t 3:8300 -c 3:root "$IMG" >/dev/null

    # Leave room for the backup GPT (33 sectors) plus a little alignment.
    truncate -s $(( (NEWEND + 1 + 40) * 512 )) "$IMG"
    sgdisk -e "$IMG" >/dev/null 2>&1 || true

    if ! sgdisk -v "$IMG" >/dev/null 2>&1; then
        err "partition table verification failed after resize"
        sgdisk -v "$IMG" >&2
        exit 1
    fi
    log "Partition table verified"
else
    losetup -d "$LOOP"; LOOP=""
fi

log "Punching holes in the image file"
fallocate --dig-holes "$IMG"

trap - EXIT
rmdir "$MNT" 2>/dev/null || true

AFTER_ALLOC="$(du -h "$IMG" | cut -f1)"
AFTER_BYTES="$(du -B1 "$IMG" | cut -f1)"
SAVED=$(( (BEFORE_BYTES - AFTER_BYTES) / 1024 / 1024 ))

cat <<EOF

=============================================================
  Image shrunk
=============================================================
  Allocated : $BEFORE_ALLOC  ->  $AFTER_ALLOC   (saved ${SAVED} MB)
  Apparent  : $(du -h --apparent-size "$IMG" | cut -f1)  (unchanged - it is sparse)
  FS used   : $USED_BEFORE  ->  $USED_AFTER

  SSH host keys and machine-id were cleared: both regenerate on
  first boot, so cloned appliances do not share an identity.

  If you already made a VirtualBox VM, rebuild the VDI:
      tools/to-virtualbox.sh --recreate

  Pass --resize to also shrink the filesystem, partition and file so the
  image is genuinely small on disk (leaves ${SLACK_MB}MB free inside):
      sudo tools/shrink-image.sh --resize

EOF
