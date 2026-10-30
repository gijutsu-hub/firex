#!/bin/bash
# =============================================================================
#  Boot the FireX appliance image under QEMU.
#
#  Two NICs so the config has something to work with:
#    eth0  WAN  user-mode networking, gets DHCP and reaches the internet
#    eth1  LAN  isolated user-mode network
#
#  Host port forwards:
#    127.0.0.1:18080 -> appliance :8080   (block portal + /ui console)
#    127.0.0.1:12222 -> appliance :22     (ssh)
#
#  Serial console is attached to this terminal; Ctrl-A X quits QEMU.
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${FIREX_IMAGE:-$PROJ/build/firex.img}"
MEM="${FIREX_QEMU_MEM:-1536}"
CPUS="${FIREX_QEMU_CPUS:-2}"
MODE="${1:-bios}"          # bios | uefi

[ -f "$IMG" ] || {
    echo "No image at $IMG" >&2
    echo "Build one first:  sudo tools/build-image.sh" >&2
    exit 1
}

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

ARGS=(
    -machine q35
    -m "$MEM"
    -smp "$CPUS"
    -drive "file=$IMG,format=raw,if=virtio,cache=writeback"
    -netdev "user,id=wan,hostfwd=tcp:127.0.0.1:18080-:8080,hostfwd=tcp:127.0.0.1:12222-:22"
    -device "e1000,netdev=wan"
    -netdev "user,id=lan,net=10.10.30.0/24,dhcpstart=10.10.30.50"
    -device "e1000,netdev=lan"
    -nographic
    -serial mon:stdio
)

if [ -r /dev/kvm ]; then
    ARGS+=(-enable-kvm -cpu host)
    echo "[qemu] KVM acceleration enabled"
else
    echo "[qemu] /dev/kvm not available - running emulated (slow)"
fi

if [ "$MODE" = uefi ]; then
    OVMF=""
    for c in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
             /usr/share/qemu/OVMF.fd; do
        [ -f "$c" ] && { OVMF="$c"; break; }
    done
    if [ -z "$OVMF" ]; then
        echo "[qemu] OVMF firmware not found; install it with:" >&2
        echo "         sudo apt-get install -y ovmf" >&2
        exit 1
    fi
    VARS="$PROJ/build/OVMF_VARS.fd"
    if [ ! -f "$VARS" ]; then
        for v in /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do
            [ -f "$v" ] && { cp "$v" "$VARS"; break; }
        done
    fi
    ARGS+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF")
    [ -f "$VARS" ] && ARGS+=(-drive "if=pflash,format=raw,unit=1,file=$VARS")
    echo "[qemu] UEFI boot via $OVMF"
else
    echo "[qemu] Legacy BIOS boot"
fi

cat <<EOF

  Booting FireX appliance...
    console  : this terminal (Ctrl-A X to quit)
    portal   : http://127.0.0.1:18080/ui
    ssh      : ssh -p 12222 root@127.0.0.1

EOF

exec qemu-system-x86_64 "${ARGS[@]}"
