#!/usr/bin/env bash
# Build the in-tree userspace tooling that ships alongside the kernel.
#
# These are NOT part of the kernel image — they're userspace ELF programs that
# happen to live under tools/ in the kernel source (perf, bpftool, cpupower,
# turbostat, rtla, rv). They build from the same staged source as the kernel
# (build.source), so they live in this pipeline rather than a separate one; only
# their userspace lib deps are extra (provided by the image, unused by
# build.kernel, so kernel reproducibility is untouched).
#
# Each tool is built and `install`ed into the stage output ($dest) as a DESTDIR
# image rooted at usr/. Install-time path vars are set to PSD-009-compliant
# locations (arch-specific helper dirs and libs under the triplet) because the
# tools bake those paths into their binaries — the package [files] maps then pass
# them through 1:1.
#
# usage: build-tools.sh <staged-source> <dest>
set -euo pipefail

src=${1:?usage: build-tools.sh <staged-source> <dest>}
dest=${2:?usage: build-tools.sh <staged-source> <dest>}
triplet=x86_64-linux-peios
jobs=$(nproc)

# Reproducible man-page dates. perf/bpftool doc builds derive the doc date from
# KBUILD_BUILD_TIMESTAMP when set, else `git log` on the source tree — but
# build.source strips .git (for the clean 7.0.9 release), so the git path floods
# the log with "fatal: not a git repository" per man page. Default the stamp to
# the source's commit date (pekit's PEKIT_SOURCE_TIMESTAMP, unix seconds; 0 when
# not a git tree) — the same value compile-kernel.sh uses — so it silences the
# noise and tracks the release; fall back to a fixed epoch otherwise.
src_ts=${PEKIT_SOURCE_TIMESTAMP:-0}
[ "$src_ts" -gt 0 ] 2>/dev/null || src_ts=1735689600   # fallback: 2025-01-01T00:00:00Z
: "${KBUILD_BUILD_TIMESTAMP:=@${src_ts}}"
export KBUILD_BUILD_TIMESTAMP

# DocBook catalog for the doc builds (xmlto/a2x resolve the DocBook 4.5 DTD and
# stylesheets through it). The path differs by environment and MUST be one that
# exists: setting XML_CATALOG_FILES to a missing file does not fall back to the
# default, it gives libxml2 an empty catalog, which then tries to fetch the DTD
# over HTTP and fails every man page in a network-less build (PEI-552).
#
#   /usr/etc/xml/catalog  — a peipkg build root, which has no /etc merge to find
#                           the catalog through, so it must be named explicitly.
#   /etc/xml/catalog      — the Debian pkm-build container, where libxml2 would
#                           find it unaided.
#
# Resolve to the first that exists rather than hardcoding either; leave unset if
# neither is present, so libxml2 keeps its own default rather than being handed
# a path we know is wrong. Exported, not passed per-make: it is an environment
# variable libxml2 reads, and the doc builds inherit it like any other. Passing
# it as a make override would also mean passing an empty value when unset, which
# libxml2 reads as "no catalogs at all" rather than as "use your default".
if [ -z "${XML_CATALOG_FILES:-}" ]; then
	for _cat in /usr/etc/xml/catalog /etc/xml/catalog; do
		if [ -f "$_cat" ]; then
			XML_CATALOG_FILES=$_cat
			export XML_CATALOG_FILES
			break
		fi
	done
	unset _cat
fi

# The tools' Makefiles write objects into the tree (not all honour O=), so build
# in a throwaway copy to keep the cached source stage pristine.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -aT "$src" "$work"
cd "$work"

log() { printf 'build-tools: %s\n' "$*"; }

# --- perf: profiling / tracing (PERF_EVENTS, kprobes, uprobes) ---
# perfexecdir holds the perf-core helpers + scripts; relocate it under the triplet
# (the default libexec/ is not a PSD-009 destination), and put completion under
# /etc. BPF skeletons + libpfm4 (auto-detected) are on, and the perf binary embeds
# libpython for `perf script -s *.py` (NO_LIBPYTHON unset).
#
# Man pages ARE built by `install`, with asciidoc and xmlto (both in the pool
# since PEI-535). Note: do NOT add an explicit `install-man` goal alongside
# `install` under -j — the two race on the same .xml temp files and fail;
# `install` builds the man set on its own.
#
# The importable python module (python3-perf) is the perf.so that `install` builds
# under python/ (the install-python_ext setup.py path is broken — missing libperf
# includes/link env — so it is NOT used; the already-built .so is copied directly
# below). That perf.so is ABI-bound to THIS image's CPython (cpython-3xx in its
# name) and will not load on a Peios machine until rebuilt against the Peios
# interpreter — but the artifact and package are real.
log "perf"
# Invoke Makefile.perf directly (the wrapper Makefile does `unexport MAKEFLAGS`,
# which drops command-line vars like perfexecdir; the wrapper itself documents
# `-f Makefile.perf` as the way to build non-standardly). perfexecdir is baked
# into the binary as PERF_EXEC_PATH, so it must point at the final install
# location — under the triplet, since libexec/ is not a PSD-009 destination.
make -C tools/perf -f Makefile.perf -j"$jobs" \
	prefix=/usr libdir=/usr/lib/$triplet sysconfdir=/etc \
	perfexecdir=lib/$triplet/perf-core \
	PYTHON=python3 BUILD_BPF_SKEL=1 WERROR=0 \
	NO_JVMTI=1 \
	DESTDIR="$dest" install
# NO_JVMTI: the JVMTI agent (Java/JVM symbol support) is permanently off per
# the PEI-158 feature policy — no JDK in the Peios pool. Doc builds
# (asciidoc/xmlto) and the setup.py python module are likewise absent in
# composed roots; perf feature-detection skips what it cannot find.

# python3-perf: the importable `perf` module. perf's Makefile builds it with
# util/setup.py, which needs setuptools -- absent from composed roots until
# PEI-535, which is why this used to copy a prebuilt .so instead. It is now
# built here against OUR interpreter, so the extension carries the Peios ABI
# tag (cpython-314-x86_64-linux-peios) and actually imports on a Peios
# machine; the copied Debian-tagged one never could.
#
# Installed to the interpreter's one site-packages, asked for rather than
# assumed -- the same rule every Python package in the pool follows.
perf_pyso=$(find tools/perf/python -maxdepth 1 -name 'perf*.so' 2>/dev/null | head -1)
if [ -n "$perf_pyso" ]; then
	site=$(python3 -c 'import sysconfig; print(sysconfig.get_path("platlib"))')
	install -D -m755 "$perf_pyso" "$dest$site/$(basename "$perf_pyso")"
else
	echo "build-tools: perf python module NOT built (no perf*.so under tools/perf/python)" >&2
fi

# --- libperf: the perf sampling/eventing library + headers (shipped as libperf
#     and libperf-devel) ---
# Granular targets, NOT the umbrella `install`, because it drags
# install_doc (asciidoc), and docs are off per the PEI-158 policy.
log "libperf"
make -C tools/lib/perf -j"$jobs" \
	prefix=/usr libdir=/usr/lib/$triplet \
	DESTDIR="$dest" install_lib install_headers install_pkgconfig
# The man pages come from the Documentation makefile directly, not through
# libperf's install_doc: that target also runs install-html and
# install-examples, and Peios ships no /usr/share/doc.
make -C tools/lib/perf/Documentation -j"$jobs" \
	prefix=/usr mandir=/usr/share/man DESTDIR="$dest" install-man

# --- bpftool: BPF program / map / tracing introspection ---
# doc-install renders the RST man pages with rst2man (python3-docutils, in
# the pool since PEI-535). mandir is passed explicitly: the Documentation
# Makefile defaults it under /usr/local.
log "bpftool"
make -C tools/bpf/bpftool -j"$jobs" \
	prefix=/usr mandir=/usr/share/man DESTDIR="$dest" install doc-install

# --- cpupower (+ libcpupower): CPU frequency / idle control ---
# libcpupower.so* lands under the triplet; skip the optional cpufreq-bench.
# Build first, install serially: cpupower's install-gmo does not depend on
# the .gmo generation, so a combined parallel `install` races msgfmt.
log "cpupower"
make -C tools/power/cpupower -j"$jobs" \
	prefix=/usr bindir=/usr/bin sbindir=/usr/sbin \
	libdir=/usr/lib/$triplet mandir=/usr/share/man \
	CPUFREQ_BENCH=false
make -C tools/power/cpupower \
	DESTDIR="$dest" prefix=/usr bindir=/usr/bin sbindir=/usr/sbin \
	libdir=/usr/lib/$triplet mandir=/usr/share/man \
	CPUFREQ_BENCH=false \
	install

# --- turbostat: CPU power / frequency telemetry ---
log "turbostat"
make -C tools/power/x86/turbostat -j"$jobs" \
	DESTDIR="$dest" prefix=/usr install

# --- rtla: real-time latency analysis (osnoise, timerlat, ...) ---
# rtla and rv hardcode -flto=auto for gcc builds. That used to fail -- the
# pool's gcc had no lto1, because its configure matched x86_64-linux-peios
# against the *-*-pe* Windows-PE pattern and silently disabled LTO -- and
# carried an FOPTS override here to strip the flag. pkgs c422f88 fixed the
# match, so the override is gone and these link with LTO as upstream intends.
#
# Its `install` target strips the binary; install the binary and the
# osnoise/hwnoise/timerlat tool symlinks manually, mirroring Makefile.rtla's
# install rule, and take the man pages through doc_install (rst2man from
# python3-docutils; Documentation/tools/rtla defaults MANDIR to
# /usr/share/man).
log "rtla"
make -C tools/tracing/rtla -j"$jobs"
install -D -m755 tools/tracing/rtla/rtla "$dest/usr/bin/rtla"
for t in osnoise hwnoise timerlat; do ln -sfn rtla "$dest/usr/bin/$t"; done
make -C tools/tracing/rtla DESTDIR="$dest" doc_install

# --- rv: runtime verification (in-kernel monitors' userspace front-end) ---
# Same shape as rtla: manual unstripped install, man pages via doc_install.
log "rv"
make -C tools/verification/rv -j"$jobs"
install -D -m755 tools/verification/rv/rv "$dest/usr/bin/rv"
make -C tools/verification/rv DESTDIR="$dest" doc_install

# =========================================================================
# Phase 2 — power/x86 sibling tools
# =========================================================================

# x86_energy_perf_policy (uses PREFIX; installs bin + man8)
log "x86_energy_perf_policy"
make -C tools/power/x86/x86_energy_perf_policy -j"$jobs" \
	DESTDIR="$dest" PREFIX=/usr install

# intel-speed-select (links libnl-genl-3); install honours bindir
log "intel-speed-select"
make -C tools/power/x86/intel-speed-select -j"$jobs"
make -C tools/power/x86/intel-speed-select \
	DESTDIR="$dest" prefix=/usr bindir=/usr/bin install

# pstate tracers are standalone python scripts (no build); install under bin
# without the .py suffix (matches Fedora's naming).
log "pstate-tracers"
install -D -m755 tools/power/x86/amd_pstate_tracer/amd_pstate_trace.py \
	"$dest/usr/bin/amd_pstate_tracer"
install -D -m755 tools/power/x86/intel_pstate_tracer/intel_pstate_tracer.py \
	"$dest/usr/bin/intel_pstate_tracer"

# =========================================================================
# Phase 3 — broad sweep. PSD-009 is bin-only, so daemons/tools that default to
# sbin are redirected with sbindir=/usr/bin; helper scripts are installed
# explicitly (stripped of extension).
# =========================================================================

log "gpio-utils"
make -C tools/gpio -j"$jobs"
make -C tools/gpio DESTDIR="$dest" prefix=/usr bindir=/usr/bin install
install -m755 tools/gpio/gpio-sloppy-logic-analyzer.sh \
	"$dest/usr/bin/gpio-sloppy-logic-analyzer"

log "iio-utils"
make -C tools/iio -j"$jobs"
make -C tools/iio DESTDIR="$dest" prefix=/usr bindir=/usr/bin install

log "spi-utils"
make -C tools/spi -j"$jobs"
make -C tools/spi DESTDIR="$dest" prefix=/usr bindir=/usr/bin install

log "bootconfig"
make -C tools/bootconfig -j"$jobs"
make -C tools/bootconfig DESTDIR="$dest" prefix=/usr bindir=/usr/bin install

# tmon uses INSTALL_ROOT (not DESTDIR) + BINDIR=usr/bin
log "tmon"
make -C tools/thermal/tmon -j"$jobs"
make -C tools/thermal/tmon INSTALL_ROOT="$dest" install

log "latency-collector"
make -C tools/tracing/latency -j"$jobs"
make -C tools/tracing/latency DESTDIR="$dest" prefix=/usr bindir=/usr/bin install

log "mm-tools"
make -C tools/mm -j"$jobs"
make -C tools/mm DESTDIR="$dest" prefix=/usr bindir=/usr/bin sbindir=/usr/bin install
install -m755 tools/mm/slabinfo-gnuplot.sh "$dest/usr/bin/slabinfo-gnuplot"
install -m755 tools/mm/show_page_info.py  "$dest/usr/bin/show_page_info"

log "freefall"
make -C tools/laptop/freefall -j"$jobs"
make -C tools/laptop/freefall DESTDIR="$dest" prefix=/usr sbindir=/usr/bin install

# cgroup: drgn-based python diagnostic scripts (no build/install)
log "cgroup-tools"
for s in tools/cgroup/*.py; do
	install -D -m755 "$s" "$dest/usr/bin/$(basename "${s%.py}")"
done

# usbip: autotools (autogen -> configure -> make -> install); lib under triplet,
# usbipd daemon redirected to bin (--sbindir)
log "usbip"
( cd tools/usb/usbip && ./autogen.sh >/dev/null 2>&1 && \
  ./configure --prefix=/usr --libdir=/usr/lib/$triplet --sbindir=/usr/bin \
    --with-tcp-wrappers=no >/dev/null )
make -C tools/usb/usbip -j"$jobs"
make -C tools/usb/usbip DESTDIR="$dest" install

# getdelays (taskstats delay-accounting demo): references taskstats fields
# (cpu_delay_max) and __kernel_timespec from THIS kernel's UAPI, which the build
# image's (older Debian) /usr/include/linux/taskstats.h lacks. Build it against the
# kernel's own exported UAPI headers (headers_install into a scratch dir, -I first).
log "getdelays"
uapi="$work/.uapi-hdrs"
make -C "$work" ARCH=x86 headers_install INSTALL_HDR_PATH="$uapi" >/dev/null 2>&1
make -C tools/accounting -j"$jobs" CFLAGS="-I$uapi/include"
install -D -m755 tools/accounting/getdelays "$dest/usr/bin/getdelays"

# hv: Linux Hyper-V guest integration daemons (kvp/vss/fcopy) + lsvmbus. The kvp
# daemon hardcodes its helper-script dir as #define KVP_SCRIPTS_PATH; rewrite it to
# a triplet path (libexec/ is not a PSD-009 destination) and install the helpers
# there to match. Daemons default to sbin -> redirected to bin. Only useful on a
# Hyper-V host; shipped for completeness.
log "hv"
hvdir="usr/lib/$triplet/hypervkvpd"
sed -i "s#/usr/libexec/hypervkvpd/#/$hvdir/#" tools/hv/hv_kvp_daemon.c
make -C tools/hv -j"$jobs"
make -C tools/hv DESTDIR="$dest" prefix=/usr sbindir=/usr/bin libexecdir="/usr/lib/$triplet" install

# kvm_stat — KVM event monitor (python). Its install target renders the man
# page with a2x, which is in the pool since PEI-535; XML_CATALOG_FILES carries
# the DocBook catalog resolved at the top of this script. (The bundled kvm_stat.service
# systemd unit is not installed/packaged.)
log "kvm_stat"
make -C tools/kvm/kvm_stat \
	INSTALL_ROOT="$dest" BINDIR=usr/bin MANDIR=usr/share/man install

# thermal stack: libthermal (public API) + libthermal_tools (private helper) +
# thermal-engine (daemon) + thermometer (logger). Both libs install via DESTDIR;
# the engine/thermometer have no install target, so their binaries are copied.
# Note: the libs' SONAME is unversioned (libthermal.so / libthermal_tools.so), so
# the unversioned .so must ship in the *runtime* lib packages, not just -devel.
log "libthermal + thermal-engine + thermometer"
make -C tools/lib/thermal -j"$jobs"
make -C tools/lib/thermal install DESTDIR="$dest" prefix=/usr libdir=/usr/lib/$triplet
make -C tools/thermal/lib -j"$jobs"
# install_lib only: libthermal_tools is a private helper with no public header, so
# its install_headers step (install/thermal.h) is broken — we just need the .so.
make -C tools/thermal/lib install_lib DESTDIR="$dest" prefix=/usr libdir=/usr/lib/$triplet
make -C tools/thermal/thermal-engine -j"$jobs"
install -D -m755 tools/thermal/thermal-engine/thermal-engine "$dest/usr/bin/thermal-engine"
make -C tools/thermal/thermometer -j"$jobs"
install -D -m755 tools/thermal/thermometer/thermometer "$dest/usr/bin/thermometer"

log "installed $(cd "$dest" && find . -type f | wc -l) files under $dest"
