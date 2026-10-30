#!/bin/bash
# =============================================================================
#  Import the FireX appliance image into VirtualBox.
#
#  VirtualBox cannot boot a raw .img, so this converts it to a VDI and builds
#  a VM around it with networking a firewall can actually work with:
#
#    NIC1  NAT        -> WAN (eth0), with host port forwards
#    NIC2  intnet     -> LAN (eth1), promiscuous so tagged VLAN frames arrive
#
#  Host port forwards:
#    127.0.0.1:18080 -> :8080   block page portal (untrusted-facing)
#    127.0.0.1:18443 -> :8443   administration console
#    127.0.0.1:12222 -> :22     ssh
#
#  Usage:   tools/to-virtualbox.sh [--efi] [--recreate]
# =============================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"

# The VM description, from include/brand.h rather than written out here:
# a re-skin should not have to remember this file.
VM_DESC="$(grep -oP '#define BRAND_PRODUCT\s+"\K[^"]+' "$PROJ/include/brand.h") by \
$(grep -oP '#define BRAND_VENDOR\s+"\K[^"]+' "$PROJ/include/brand.h") - \
$(grep -oP '#define BRAND_TAGLINE\s+"\K[^"]+' "$PROJ/include/brand.h")"
IMG="${FIREX_IMAGE:-$PROJ/build/firex.img}"
VDI="${FIREX_VDI:-$PROJ/build/firex.vdi}"
VM="${FIREX_VM_NAME:-FireX}"
MEM="${FIREX_VM_MEM:-1536}"
CPUS="${FIREX_VM_CPUS:-2}"
LANNET="${FIREX_VM_LANNET:-firex-lan}"
FIRMWARE=bios
RECREATE=0

for a in "$@"; do
    case "$a" in
        --efi)      FIRMWARE=efi ;;
        --recreate) RECREATE=1 ;;
        -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown option: $a" >&2; exit 1 ;;
    esac
done

# The boot splash needs a framebuffer the kernel can inherit from GRUB,
# which means the adapter has to answer the firmware's mode queries:
# VBoxVGA carries the legacy VBE that BIOS GRUB asks, VMSVGA is the one
# that works under EFI. 32MB is more than a 1024x768x32 mode needs and
# costs nothing; at 16MB a larger mode falls back to text.
case "$FIRMWARE" in
    efi) GFX=vmsvga ;;
    *)   GFX=vboxvga ;;
esac

# The image pins one screen size across GRUB, Plymouth and Xorg, and
# records it in the manifest. Offering the guest that exact mode is what
# stops the desktop console coming up letterboxed inside a larger frame.
SCREEN="${FIREX_SCREEN:-}"
if [ -z "$SCREEN" ] && [ -f "${FIREX_IMAGE:-$PROJ/build/firex.img}.manifest" ]; then
    SCREEN="$(sed -n 's/^screen *= *//p' \
              "${FIREX_IMAGE:-$PROJ/build/firex.img}.manifest" | head -1)"
fi
: "${SCREEN:=1024x768}"


log() { printf '\033[1;36m[vbox]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[vbox] ERROR:\033[0m %s\n' "$*" >&2; }

command -v VBoxManage >/dev/null 2>&1 || {
    err "VBoxManage not found."
    echo "    sudo apt-get install -y virtualbox"
    echo "  then log out and back in (your user needs the vboxusers group)."
    exit 1
}
[ -f "$IMG" ] || { err "no image at $IMG - run: sudo tools/build-image.sh"; exit 1; }

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

# The builder runs as root, so the image usually ends up root-owned.
if [ ! -r "$IMG" ]; then
    log "Image is not readable by $USER; taking ownership"
    sudo chown "$(id -u):$(id -g)" "$IMG"
fi

# ---- remove the old VM FIRST -------------------------------------------------
# "unregistervm --delete" deletes the media registered to that VM, and the old
# VM points at the same VDI path we are about to write. Converting first would
# create the new VDI and then have it deleted out from under us.
if VBoxManage showvminfo "$VM" >/dev/null 2>&1; then
    if [ "$RECREATE" = 1 ]; then
        log "Removing existing VM '$VM'"
        VBoxManage controlvm "$VM" poweroff 2>/dev/null || true
        VBoxManage unregistervm "$VM" --delete 2>/dev/null || true
    else
        err "VM '$VM' already exists. Re-run with --recreate, or set FIREX_VM_NAME."
        exit 1
    fi
fi

# Drop any stale registration of the VDI left behind by an earlier run.
VBoxManage closemedium disk "$VDI" 2>/dev/null || true

# ---- convert ----------------------------------------------------------------
if [ -f "$VDI" ] && [ "$RECREATE" = 0 ]; then
    log "Reusing existing $VDI  (pass --recreate to rebuild it)"
else
    [ -f "$VDI" ] && { log "Removing old VDI"; rm -f "$VDI"; }
    log "Converting raw image -> VDI (dynamically sized)"
    VBoxManage convertfromraw "$IMG" "$VDI" --format VDI
fi

[ -f "$VDI" ] || { err "VDI was not created at $VDI"; exit 1; }

log "Creating VM '$VM'"
VBoxManage createvm --name "$VM" --ostype Ubuntu_64 --register >/dev/null

VBoxManage modifyvm "$VM" \
    --memory "$MEM" --cpus "$CPUS" \
    --firmware "$FIRMWARE" \
    --ioapic on --rtcuseutc on --pae off \
    --graphicscontroller "$GFX" --vram 32 \
    --boot1 disk --boot2 none --boot3 none --boot4 none \
    --audio-enabled off \
    --description "$VM_DESC"

# ---- storage ----------------------------------------------------------------
log "Attaching disk"
VBoxManage storagectl "$VM" --name SATA --add sata --controller IntelAhci --portcount 2
if ! VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 \
        --type hdd --medium "$VDI"; then
    err "could not attach $VDI"
    err "If it says the file is missing, an old VM registration deleted it;"
    err "re-run with --recreate."
    exit 1
fi

# ---- network ----------------------------------------------------------------
# NIC1 = WAN. NAT gives the appliance DHCP and outbound internet.
log "NIC1 -> NAT (WAN / eth0)"
VBoxManage modifyvm "$VM" --nic1 nat --nictype1 82540EM --cableconnected1 on
VBoxManage modifyvm "$VM" --natpf1 "portal,tcp,127.0.0.1,18080,,8080"
# The console is a second listener on a port of its own -- see [console]
# in firex.conf. Without this forward the VM boots with a console nobody
# can reach, which looks exactly like a console that is broken.
VBoxManage modifyvm "$VM" --natpf1 "console,tcp,127.0.0.1,18443,,8443"
VBoxManage modifyvm "$VM" --natpf1 "ssh,tcp,127.0.0.1,12222,,22"

# NIC2 = LAN. An internal network keeps lab traffic off your real LAN.
# Promiscuous mode matters: without allow-all the adapter drops frames that
# are not addressed to it, and a firewall on a trunk needs to see all of them,
# VLAN tags included.
log "NIC2 -> internal network '$LANNET' (LAN / eth1), promiscuous"
VBoxManage modifyvm "$VM" --nic2 intnet --intnet2 "$LANNET" \
    --nictype2 82540EM --nicpromisc2 allow-all --cableconnected2 on

# ---- serial console ---------------------------------------------------------
# The image puts a console on ttyS0; pipe it to a host socket so you can watch
# boot and log in without the GUI window.
SOCK="$PROJ/build/${VM}-console.sock"
rm -f "$SOCK"
VBoxManage modifyvm "$VM" --uart1 0x3F8 4 --uartmode1 server "$SOCK"

# CustomVideoMode1 is how the VirtualBox BIOS/EFI is told about a mode it
# does not already offer. Without it a non-standard FIREX_SCREEN simply is
# not in the list and GRUB silently falls back to 1024x768.
VBoxManage setextradata "$VM" "CustomVideoMode1" "${SCREEN}x32" >/dev/null
VBoxManage setextradata "$VM" \
    "VBoxInternal2/EfiGraphicsResolution" "$SCREEN" >/dev/null 2>&1 || true
log "Serial console -> $SOCK"

cat <<EOF

=============================================================
  VirtualBox VM '$VM' ready
=============================================================
  Disk      : $VDI
  Firmware  : $FIRMWARE  (graphics: $GFX, 32MB VRAM, $SCREEN)
  Memory    : ${MEM}MB, ${CPUS} vCPU
  NIC1      : NAT          -> eth0 (WAN)
  NIC2      : intnet '$LANNET' -> eth1 (LAN, promiscuous)

  Start it (headless, console on the socket):
      VBoxManage startvm $VM --type headless
      socat - UNIX-CONNECT:$SOCK        # or: minicom -D unix#$SOCK

  Start it with the normal VirtualBox window:
      VBoxManage startvm $VM

  Once it is up:
      Portal   http://127.0.0.1:18080/        (block page)
      Console  http://127.0.0.1:18443/ui     (administration)
      SSH      ssh -p 12222 root@127.0.0.1

  Stop it:
      VBoxManage controlvm $VM acpipowerbutton

  Attach another VM to the LAN side by giving it an internal network
  adapter on '$LANNET'.

EOF
