#!/usr/bin/env bash
# Prepare boot-test fixtures. Pekit adds PIP signatures after this exits.
set -euo pipefail
[[ $# -eq 3 ]] || { echo "usage: $0 <kernel-tree> <module-root> <output>" >&2; exit 2; }
tree=$(cd "$1" && pwd)
root=$(cd "$2" && pwd)
work=$(cd "$3" && pwd)
moddir=$(find "$root/lib/modules" -maxdepth 1 -mindepth 1 -type d | head -1)
testmod=$(find "$moddir" -name 'test_firmware.ko.zst' | head -1)
[[ -n "$testmod" ]] || { echo "test_firmware module missing" >&2; exit 1; }
mkdir -p "$work/root/lib/firmware" "$work/root/sys"
gcc -static -O2 -Wall -Wextra -Werror -o "$work/root/init" build/fwsig-smoke.c
cp "$testmod" "$work/root/test_firmware.ko.zst"

fw="$work/root/lib/firmware"
head -c 4096 /dev/urandom >"$fw/fwsig-good.bin"
head -c 4096 /dev/urandom >"$fw/fwsig-unsigned.bin"
# From a file, not a pipe: the kernel's zstd path needs the frame to carry
# its content size, which zstd only writes when it knows the input length.
head -c 8192 /dev/urandom >"$work/goodz.bin"
zstd -q -19 "$work/goodz.bin" -o "$fw/fwsig-goodz.bin.zst"
# Same signature as the good blob, different bytes.
cp "$fw/fwsig-good.bin" "$fw/fwsig-bad.bin"
printf '\xff' | dd of="$fw/fwsig-bad.bin" bs=1 seek=2048 count=1 conv=notrunc status=none
