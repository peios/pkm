#!/usr/bin/env bash
# Verify the PKM UAPI headers are userspace-clean.
#
# The headers must compile with an ordinary, non-kernel C compiler — the
# precondition for the cgo -godefs binding generator and for any userspace
# consumer of the PKM ABI. <linux/types.h> / <linux/ioctl.h> resolve to the
# host's /usr/include (the same userspace sysroot cgo builds against), NOT
# the kernel tree; no -D__KERNEL__, no kernel include paths.
#
# Two checks:
#   1. each header compiles standalone — catches a header that only works
#      because some other header was included before it;
#   2. the umbrella <pkm/pkm.h> compiles as a full translation unit, with
#      its internal-consistency assertions (see smoke_test.c).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc="${CC:-cc}"
cflags=(-std=c11 -Wall -Wextra -Werror -I "$here")

echo "check-userspace-clean: cc=$cc -I $here"

# 1. Each header compiles standalone.
for h in "$here"/pkm/*.h; do
	rel="pkm/$(basename "$h")"
	echo "#include <$rel>" | "$cc" "${cflags[@]}" -fsyntax-only -x c -
	echo "  ok  $rel"
done

# 2. The umbrella header compiles as a translation unit.
"$cc" "${cflags[@]}" -c "$here/smoke_test.c" -o /dev/null
echo "  ok  smoke_test.c (<pkm/pkm.h>)"

echo "check-userspace-clean: PASS"
