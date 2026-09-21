#!/usr/bin/env bash
# Split the debug data out of the host programs kernel-devel ships, then strip
# them.
#
# kernel-devel carries the configured build kit for out-of-tree modules, and
# with it the Kbuild host programs the kit runs: everything built under
# scripts/ (fixdep, modpost, kallsyms, ...) and objtool. Like every other
# program in the family they ship stripped, with their debug data in
# kernel-tools-debuginfo, split by build ID. Run at the end of build.kernel,
# once nothing in the stage needs the unstripped programs.
#
# usage: split-host-debug.sh <kernel-tree> <debug-root>
#   <debug-root> receives usr/lib/debug/.build-id/xx/yyyy.debug
set -euo pipefail

tree=${1:?usage: split-host-debug.sh <kernel-tree> <debug-root>}
debug_root=${2:?usage: split-host-debug.sh <kernel-tree> <debug-root>}
cd "$tree"

split=0
while IFS= read -r -d '' f; do
	type=$(readelf -h "$f" 2>/dev/null | sed -n 's/^ *Type: *\([A-Z]*\).*/\1/p' || true)
	case $type in EXEC | DYN) ;; *) continue ;; esac
	id=$(readelf -n "$f" | sed -n 's/^[[:space:]]*Build ID: //p')
	if [ -z "$id" ]; then
		echo "split-host-debug: $f has no build ID" >&2
		exit 1
	fi
	debug="$debug_root/usr/lib/debug/.build-id/${id:0:2}/${id:2}.debug"
	# A hard link shares its build ID with the file already split.
	[ -e "$debug" ] && continue
	mkdir -p "${debug%/*}"
	objcopy --only-keep-debug "$f" "$debug"
	chmod 0644 "$debug"
	strip "$f"
	split=$((split + 1))
done < <(find scripts tools/objtool/objtool -type f ! -name '*.o' -print0)

echo "split-host-debug: split and stripped $split host programs"
