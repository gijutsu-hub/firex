CC      = gcc
CLANG  ?= clang
CFLAGS  = -Wall -Wextra -g -O2 -Iinclude -Wno-deprecated-declarations
GTK_FLAGS = $(shell pkg-config --cflags gtk4)
GTK_LIBS  = $(shell pkg-config --libs gtk4)
NFQ_LIBS  = $(shell pkg-config --libs libnetfilter_queue 2>/dev/null || echo -lnetfilter_queue -lnfnetlink)

# XDP needs libbpf at build time. When it is absent we compile a stub backend
# instead, so the GUI still builds and simply reports XDP as unavailable.
HAVE_LIBBPF := $(shell test -f /usr/include/bpf/libbpf.h && echo yes)
ifeq ($(HAVE_LIBBPF),yes)
  XDP_SRC  = $(SRCDIR)/xdp_filter.c
  BPF_LIBS = $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)
else
  XDP_SRC  = $(SRCDIR)/xdp_stub.c
  BPF_LIBS =
endif

LDFLAGS   = -lpthread -lm -lcrypt -lcrypto -lssl $(GTK_LIBS) $(NFQ_LIBS) $(BPF_LIBS)

SRCDIR = src
GUIDIR = src/gui
XDPDIR = xdp
TESTDIR = tests
TOOLSDIR = tools
WEBDIR = src/webui/static
OBJDIR = build

# Architecture define and header path the BPF target needs for linux/types.h
BPF_ARCH   = $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/')
BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
             -I$(XDPDIR) -I/usr/include/$(shell uname -m)-linux-gnu

SOURCES = $(SRCDIR)/firewall.c \
          $(SRCDIR)/dpi.c \
          $(SRCDIR)/netutil.c \
          $(SRCDIR)/shellcmd.c \
          $(SRCDIR)/vlan.c \
          $(SRCDIR)/policy.c \
          $(SRCDIR)/netconf.c \
          $(SRCDIR)/gwmon.c \
          $(SRCDIR)/vpn.c \
          $(SRCDIR)/conntrack.c \
          $(SRCDIR)/histstats.c \
          $(SRCDIR)/capture.c \
          $(SRCDIR)/telemetry.c \
          $(SRCDIR)/shaper.c \
          $(SRCDIR)/portal.c \
          $(SRCDIR)/ha.c \
          $(SRCDIR)/ids.c \
          $(SRCDIR)/feeds.c \
          $(SRCDIR)/malware.c \
          $(SRCDIR)/airgap.c \
          $(SRCDIR)/egress.c \
          $(SRCDIR)/audit.c \
          $(SRCDIR)/netif.c \
          $(SRCDIR)/response.c \
          $(SRCDIR)/update.c \
          $(SRCDIR)/slots.c \
          $(SRCDIR)/pkg.c \
          $(SRCDIR)/console.c \
          $(SRCDIR)/blockpage.c \
          $(SRCDIR)/enterprise_config.c \
          $(SRCDIR)/config_write.c \
          $(SRCDIR)/configstore.c \
          $(SRCDIR)/reload.c \
          $(SRCDIR)/auth.c \
          $(SRCDIR)/inspect.c \
          $(SRCDIR)/webui.c \
          $(SRCDIR)/webui_assets.c \
          $(SRCDIR)/ratelimit.c \
          $(SRCDIR)/config_loader.c \
          $(SRCDIR)/logger.c \
          $(SRCDIR)/nfqueue.c \
          $(XDP_SRC) \
          $(SRCDIR)/engine.c \
          $(GUIDIR)/gui_main.c \
          $(GUIDIR)/gui_security.c \
          $(GUIDIR)/gui_rules.c \
          $(GUIDIR)/gui_monitor.c \
          $(GUIDIR)/gui_stats.c \
          $(GUIDIR)/gui_settings.c \
          $(GUIDIR)/gui_login.c \
          $(GUIDIR)/gui_dashboard.c \
          $(GUIDIR)/gui_api.c \
          $(GUIDIR)/gui_theme.c

OBJECTS = $(patsubst %.c, $(OBJDIR)/%.o, $(notdir $(SOURCES)))
DEPS    = $(OBJECTS:.o=.d)
TARGET  = flamewall
DAEMON  = firexd
BPF_OBJ = $(XDPDIR)/xdp_firewall.bpf.o

.PHONY: all clean distclean install uninstall deps deps-image run console test-list check-deps xdp xdp-status \
        bundle-tool \
        test test-seg test-config test-phase2 test-phase3 test-phase4 test-phase5 test-phase6 test-phase7 test-phase8 test-phase9 test-gui test-xdp test-all image image-check shrink shrink-fit qemu qemu-uefi vbox vbox-efi splash

all: check-deps dirs $(TARGET) $(DAEMON) xdp-status

check-deps:
	@pkg-config --exists gtk4 || { \
	  echo "ERROR: gtk4 development files not found. Run: make deps"; exit 1; }
	@test -f /usr/include/libnetfilter_queue/libnetfilter_queue.h || { \
	  echo "ERROR: libnetfilter_queue headers not found. Run: make deps"; exit 1; }

dirs:
	@mkdir -p $(OBJDIR) config

# Derived from the GUI sources, not hand-listed. The hand-written version
# fell behind the moment a file was added to $(GUIDIR): the new object was
# missing from GUI_OBJECTS, so filter-out left it in CORE_OBJECTS and the
# daemon -- which links no GTK -- failed at the link step with a page of
# undefined gtk_* symbols that said nothing about the actual cause.
GUI_OBJECTS  = $(patsubst $(GUIDIR)/%.c,$(OBJDIR)/%.o,$(wildcard $(GUIDIR)/*.c))
CORE_OBJECTS = $(filter-out $(GUI_OBJECTS),$(OBJECTS))

# The console's static files are embedded so the appliance binary is
# self-contained; edit them under $(WEBDIR) and this regenerates.
$(SRCDIR)/webui_assets.c: $(WEBDIR)/index.html $(WEBDIR)/vlan.js $(WEBDIR)/style.css \
                          $(TOOLSDIR)/embed_assets.py
	@python3 $(TOOLSDIR)/embed_assets.py $(WEBDIR) $@

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Headless appliance daemon: same engine, no GTK.
$(DAEMON): $(CORE_OBJECTS) $(OBJDIR)/firexd.o
	$(CC) -o $@ $^ -lpthread -lm -lcrypt -lcrypto -lssl $(NFQ_LIBS) $(BPF_LIBS)

$(OBJDIR)/firexd.o: $(SRCDIR)/firexd.c | dirs
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

$(OBJDIR)/%.o: $(SRCDIR)/%.c | dirs
	$(CC) $(CFLAGS) $(GTK_FLAGS) -MMD -MP -c -o $@ $<

$(OBJDIR)/%.o: $(GUIDIR)/%.c | dirs
	$(CC) $(CFLAGS) $(GTK_FLAGS) -MMD -MP -c -o $@ $<

# Every .d in the build directory, not just the ones derived from
# SOURCES. firexd.c has a rule of its own and is NOT in SOURCES, so
# $(DEPS) never named build/firexd.d and firexd.o was never rebuilt when
# a header changed -- it only rebuilt when firexd.c itself was edited.
#
# That is not merely a stale string. firexd.c includes blockpage.h,
# netconf.h, malware.h and airgap.h, so adding a field to any of those
# structs left the daemon's main compiled against the OLD layout and
# linked against objects using the new one: the two then disagree about
# member offsets, which is silent memory corruption rather than a build
# error. A wildcard cannot miss an object the way an enumerated list can.
-include $(wildcard $(OBJDIR)/*.d)

# ---- XDP / eBPF kernel program -------------------------------------------
# Built separately: it needs clang (gcc cannot target BPF). The main binary
# links and runs without it; the XDP engine simply reports it is missing.
xdp: $(BPF_OBJ)

$(BPF_OBJ): $(XDPDIR)/xdp_firewall.bpf.c $(XDPDIR)/xdp_shared.h
	@command -v $(CLANG) >/dev/null || { \
	  echo "ERROR: clang not found - it is required to compile BPF. Run: make deps"; exit 1; }
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "Built $@"
	@command -v bpftool >/dev/null && bpftool prog load $@ /sys/fs/bpf/__fwtest 2>/dev/null \
	  && { echo "verifier: accepted"; rm -f /sys/fs/bpf/__fwtest; } || true

# Build the BPF object alongside the GUI when clang is available, otherwise
# say so once instead of failing the whole build.
xdp-status:
	@test "$(HAVE_LIBBPF)" = yes || { \
	  echo "NOTE: libbpf-dev not installed - built with the XDP stub backend."; \
	  echo "      Install it with: make deps   then: make clean && make"; }
	@if command -v $(CLANG) >/dev/null && test "$(HAVE_LIBBPF)" = yes; then \
	  $(MAKE) --no-print-directory $(BPF_OBJ); \
	else \
	  echo "NOTE: clang not installed - skipping the XDP program."; \
	  echo "      The GUI builds fine; the XDP engine will report it is unavailable."; \
	  echo "      Install it with: make deps   then: make xdp"; \
	fi


# ---- Tests ----------------------------------------------------------------
# The engine objects the tests link against (everything except the GUI).
TEST_CORE = $(OBJDIR)/firewall.o $(OBJDIR)/dpi.o $(OBJDIR)/ratelimit.o \
            $(OBJDIR)/config_loader.o $(OBJDIR)/logger.o \
            $(OBJDIR)/netutil.o $(OBJDIR)/shellcmd.o $(OBJDIR)/vlan.o \
            $(OBJDIR)/netconf.o $(OBJDIR)/blockpage.o \
            $(OBJDIR)/policy.o $(OBJDIR)/gwmon.o $(OBJDIR)/vpn.o \
            $(OBJDIR)/conntrack.o $(OBJDIR)/histstats.o \
            $(OBJDIR)/capture.o $(OBJDIR)/telemetry.o \
            $(OBJDIR)/shaper.o $(OBJDIR)/portal.o $(OBJDIR)/ha.o \
            $(OBJDIR)/ids.o $(OBJDIR)/feeds.o $(OBJDIR)/response.o \
            $(OBJDIR)/malware.o $(OBJDIR)/airgap.o $(OBJDIR)/netif.o \
            $(OBJDIR)/egress.o $(OBJDIR)/audit.o \
            $(OBJDIR)/enterprise_config.o $(OBJDIR)/inspect.o

# Config spine: serialiser, versioned store, reload pipeline, console auth.
TEST_CONFIG = $(TEST_CORE) $(OBJDIR)/config_write.o $(OBJDIR)/configstore.o \
              $(OBJDIR)/reload.o $(OBJDIR)/auth.o

# Rule-engine tests: no root, no network.
test: dirs $(OBJDIR)/test_engine
	@echo "== rule engine =="
	@./$(OBJDIR)/test_engine

$(OBJDIR)/test_engine: $(TESTDIR)/test_engine.c $(TEST_CORE) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypto -lssl

# XDP integration test: loads the BPF program, builds a veth pair in its own
# namespace, and checks that packets are really dropped. Needs root, so only
# the test itself is elevated - the build stays under your own user.
test-xdp: dirs $(OBJDIR)/test_xdp $(BPF_OBJ)
	@sudo $(TESTDIR)/run_xdp_test.sh

ifeq ($(HAVE_LIBBPF),yes)
$(OBJDIR)/test_xdp: $(TESTDIR)/test_xdp.c $(TEST_CORE) $(OBJDIR)/xdp_filter.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypto -lssl $(BPF_LIBS)
else
$(OBJDIR)/test_xdp:
	@echo "ERROR: this build has no XDP support (libbpf-dev was missing)."
	@echo "       Install it with: make deps   then: make clean && make"
	@exit 1
endif

# Segmentation / zone policy tests: no root, no network.
test-seg: dirs $(OBJDIR)/test_segmentation
	@echo "== segmentation =="
	@./$(OBJDIR)/test_segmentation

$(OBJDIR)/test_segmentation: $(TESTDIR)/test_segmentation.c $(TEST_CORE) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypto -lssl

# Config spine tests: round-trip, validation, revision store, auth. No root.
test-config: dirs $(OBJDIR)/test_config
	@echo "== config spine =="
	@./$(OBJDIR)/test_config

$(OBJDIR)/test_config: $(TESTDIR)/test_config.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Desktop console plumbing: the JSON reader, interfaces, the HTTP client.
# gui_api.c pulls in no GTK, so this links without it. Point
# FIREX_TEST_PORT at a running daemon to exercise the live round trip.
test-gui: dirs $(OBJDIR)/test_gui
	@echo "== desktop console =="
	@./$(OBJDIR)/test_gui

$(OBJDIR)/test_gui: $(TESTDIR)/test_gui.c $(OBJDIR)/gui_api.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 2: aliases, schedules, routes, gateway monitoring, failover. No root.
test-phase2: dirs $(OBJDIR)/test_phase2
	@echo "== phase 2 =="
	@./$(OBJDIR)/test_phase2

$(OBJDIR)/test_phase2: $(TESTDIR)/test_phase2.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 3: WireGuard keys, peers, zone mapping, IPsec. No root.
test-phase3: dirs $(OBJDIR)/test_phase3
	@echo "== phase 3 =="
	@./$(OBJDIR)/test_phase3

$(OBJDIR)/test_phase3: $(TESTDIR)/test_phase3.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 4: connection table, history ring, capture bounds, wire formats.
test-phase4: dirs $(OBJDIR)/test_phase4
	@echo "== phase 4 =="
	@./$(OBJDIR)/test_phase4

$(OBJDIR)/test_phase4: $(TESTDIR)/test_phase4.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 5: tc plan, portal sessions, vouchers, RADIUS. No root.
test-phase5: dirs $(OBJDIR)/test_phase5
	@echo "== phase 5 =="
	@./$(OBJDIR)/test_phase5

$(OBJDIR)/test_phase5: $(TESTDIR)/test_phase5.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 6: VRRP and conntrackd config, signed config replication. No root.
test-phase6: dirs $(OBJDIR)/test_phase6
	@echo "== phase 6 =="
	@./$(OBJDIR)/test_phase6

$(OBJDIR)/test_phase6: $(TESTDIR)/test_phase6.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 7: pattern matcher, signatures, blocklists, response. No root.
test-phase7: dirs $(OBJDIR)/test_phase7
	@echo "== phase 7 =="
	@./$(OBJDIR)/test_phase7

$(OBJDIR)/test_phase7: $(TESTDIR)/test_phase7.c $(TEST_CONFIG) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# Phase 8: bundle signing and verification, A/B slots, package paths,
# console dispatch. No root -- it signs with a throwaway key in a temp dir.
test-phase8: dirs $(OBJDIR)/test_phase8
	@echo "== phase 8 =="
	@./$(OBJDIR)/test_phase8

# The suite list, read out of this file rather than written down anywhere
# else. A count in prose drifts the moment a suite is added; this cannot.
test-list:
	@printf 'FireX test suites\n\n'
	@{ printf 'test\n'; \
	   grep -hoE '^test-[a-z0-9]+:' $(MAKEFILE_LIST) | tr -d ':' \
	     | grep -vxE 'test-all|test-list'; } | sort -u | sed 's/^/  make /'
	@printf '\n%s suites. "make test-all" runs every one.\n' \
	  "$$({ printf 'test\n'; \
	        grep -hoE '^test-[a-z0-9]+:' $(MAKEFILE_LIST) | tr -d ':' \
	          | grep -vxE 'test-all|test-list'; } | sort -u | wc -l)"

# Phase 9: live malware protection, air gap, interface inventory. No root
# and no network -- packets are synthesised in memory.
test-phase9: dirs $(OBJDIR)/test_phase9
	@echo "== phase 9 =="
	@./$(OBJDIR)/test_phase9

# egress.o: airgap.c binds itself to the egress gate, so the two no longer
# link apart.
$(OBJDIR)/test_phase9: $(TESTDIR)/test_phase9.c $(OBJDIR)/malware.o \
                       $(OBJDIR)/airgap.o $(OBJDIR)/netif.o \
                       $(OBJDIR)/egress.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

# Audit trail: recording, log injection, and tamper evidence.
test-audit: dirs $(OBJDIR)/test_audit
	@echo "== audit trail =="
	@./$(OBJDIR)/test_audit

$(OBJDIR)/test_audit: $(TESTDIR)/test_audit.c $(OBJDIR)/audit.o \
                      $(OBJDIR)/malware.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

# Console TLS: generates a certificate, starts the real console listener and
# speaks real TLS to it. Loopback only, on a port the daemon does not use.
test-tls: dirs $(OBJDIR)/test_tls
	@echo "== console TLS =="
	@./$(OBJDIR)/test_tls

$(OBJDIR)/test_tls: $(TESTDIR)/test_tls.c $(TEST_CORE) $(OBJDIR)/gui_api.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypto -lssl

# Egress gate: does the appliance's OWN outbound traffic pass the air gap?
# Links the real feeds/ha/gwmon/telemetry objects on purpose -- the point of
# the suite is that those translation units call the gate, which a test
# against a stub could not show.
test-egress: dirs $(OBJDIR)/test_egress
	@echo "== egress gate =="
	@./$(OBJDIR)/test_egress

$(OBJDIR)/test_egress: $(TESTDIR)/test_egress.c $(TEST_CORE) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypto -lssl

TEST_PLATFORM = $(OBJDIR)/update.o $(OBJDIR)/slots.o $(OBJDIR)/pkg.o \
                $(OBJDIR)/console.o

$(OBJDIR)/test_phase8: $(TESTDIR)/test_phase8.c $(TEST_CONFIG) $(TEST_PLATFORM) | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lpthread -lcrypt -lcrypto -lssl

# ---- Update signing tool --------------------------------------------------
# Builds bundles. This belongs on a build host that holds the signing key,
# never on an appliance, so it is a separate binary and is not installed.
bundle-tool: firex-bundle

firex-bundle: $(TOOLSDIR)/firex-bundle.c $(OBJDIR)/update.o $(OBJDIR)/slots.o | dirs
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto -lssl

test-all: test test-seg test-config test-phase2 test-phase3 test-phase4 test-phase5 test-phase6 test-phase7 test-phase8 test-phase9 test-egress test-tls test-audit test-gui test-xdp

# ---- Bootable appliance image ---------------------------------------------
# Builds a hybrid BIOS+UEFI raw disk image: dd it to a USB stick or boot it
# under QEMU. Needs root (loop mounts and a chroot) and ~200MB of downloads.
# Check everything that can be checked before spending ten minutes building.
image-check: $(DAEMON)
	@$(TOOLSDIR)/preflight.sh

# sudo resets the environment, so the build settings are handed to env(1)
# to set as root instead. Each is empty when unset, and the script's own
# ${VAR:-default} handles that.
image: $(DAEMON)
	@$(TOOLSDIR)/preflight.sh
	@sudo env FIREX_UPDATE_KEY="$(FIREX_UPDATE_KEY)" \
	          FIREX_IMAGE_SIZE="$(FIREX_IMAGE_SIZE)" \
	          FIREX_CONSOLE_MENU="$(FIREX_CONSOLE_MENU)" \
	          FIREX_BOOT_SPLASH="$(FIREX_BOOT_SPLASH)" \
	          FIREX_ROOT_PASSWORD="$(FIREX_ROOT_PASSWORD)" \
	          FIREX_ADMIN_PASSWORD="$(FIREX_ADMIN_PASSWORD)" \
	          FIREX_DESKTOP="$(FIREX_DESKTOP)" \
	          FIREX_SCREEN="$(FIREX_SCREEN)" \
	          $(TOOLSDIR)/build-image.sh

# Boot artwork. The PNGs under board/splash/ are committed, so the image
# build needs neither Pillow nor a font stack -- run this only after
# changing include/brand.h or tools/make-splash.py.
splash:
	@python3 $(TOOLSDIR)/make-splash.py

# Trim an already-built image: drops apt metadata, docs and translations,
# then collapses the sparse file. Safe to run more than once.
shrink:
	@sudo $(TOOLSDIR)/shrink-image.sh

# Also shrink the filesystem, partition and file so the image is small on
# disk, not just sparse. Do this when you are about to dd it somewhere.
shrink-fit:
	@sudo $(TOOLSDIR)/shrink-image.sh --resize

qemu:
	@$(TOOLSDIR)/run-qemu.sh bios

qemu-uefi:
	@$(TOOLSDIR)/run-qemu.sh uefi

# Convert the image to a VDI and build a VirtualBox VM around it.
vbox:
	@$(TOOLSDIR)/to-virtualbox.sh

vbox-efi:
	@$(TOOLSDIR)/to-virtualbox.sh --efi

deps-image:
	sudo apt-get update
	sudo apt-get install -y \
		debootstrap parted dosfstools rsync \
		grub-pc-bin grub-efi-amd64-bin \
		qemu-system-x86 ovmf

# Removes what the compiler made, and NOTHING else.
#
# This used to be "rm -rf $(OBJDIR)", and $(OBJDIR) is also where the
# appliance image and the VirtualBox disk are written -- so a routine
# "make clean" silently destroyed an 8 GB image that takes root and ten
# minutes to rebuild, and left the VM pointing at a disk that no longer
# existed. Object files are cheap to recreate; those are not, and the
# command that removes them should have to say so.
clean:
	@find $(OBJDIR) -maxdepth 1 -type f \
	      \( -name '*.o' -o -name '*.d' -o -name 'test_*' \) -delete 2>/dev/null || true
	@rm -f $(TARGET) $(DAEMON) $(BPF_OBJ)
	@echo "cleaned build artifacts; images in $(OBJDIR)/ were kept (make distclean removes those)"
	@# webui_assets.c is generated but kept in-tree for builds without python

# Everything, images included. Prints what it is about to destroy first,
# because this is the one that costs ten minutes and a sudo to undo.
distclean: clean
	@if ls $(OBJDIR)/*.img $(OBJDIR)/*.vdi $(OBJDIR)/*.manifest >/dev/null 2>&1; then \
	    echo "about to remove:"; \
	    ls -lh $(OBJDIR)/*.img $(OBJDIR)/*.vdi $(OBJDIR)/*.manifest 2>/dev/null \
	      | awk '{print "  "$$5"\t"$$9}'; \
	fi
	rm -rf $(OBJDIR)

# Install build dependencies (Ubuntu/Debian)
deps:
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		clang \
		llvm \
		libgtk-4-dev \
		libnetfilter-queue-dev \
		libnfnetlink-dev \
		libbpf-dev \
		linux-tools-common \
		iptables \
		pkg-config

install: $(TARGET) $(DAEMON)
	sudo install -m 755 $(TARGET) /usr/local/bin/
	sudo install -m 755 $(DAEMON) /usr/local/bin/
	sudo mkdir -p /etc/flamewall /usr/local/share/flamewall
	sudo cp -n config/rules.conf /etc/flamewall/ || true
	@test -f $(BPF_OBJ) && sudo install -m 644 $(BPF_OBJ) /usr/local/share/flamewall/ || true

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET) /usr/local/bin/$(DAEMON)
	sudo rm -f /usr/local/share/flamewall/xdp_firewall.bpf.o

run: $(TARGET)
	sudo ./$(TARGET)

# The console the appliance shows on its own screen, running here instead.
# It signs in against a throwaway daemon started with --no-apply, so it
# reads and serves the configuration without touching this machine's
# interfaces or firewall rules -- and so it needs no root. Pass --kiosk to
# see it the way the appliance does.
console: $(TARGET) $(DAEMON)
	@$(TOOLSDIR)/run-console.sh $(CONSOLE_ARGS)
