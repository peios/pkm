#!/usr/bin/env bash
# Point every installed script's #! line at the root-level runtime views.
#
# A Peios root reaches its interpreters through /bin, the StrataFS runtime
# view, rather than through /usr package storage or a PATH search. Upstream
# Linux names them every other way: /usr/bin/perl, /usr/bin/env python3, a
# bare `python` Peios does not ship. This rewrites the #! line of each file
# under the given trees to /bin/sh, /bin/bash, /bin/python3 or /bin/perl,
# keeping the interpreter's arguments. A line naming anything else is left
# as it is: such scripts (awk, sed and make programs under the kernel's
# scripts/) are excluded from every package, and the payload lint rejects
# one that is not.
#
# Nothing the kernel family installs runs before the StrataFS views exist,
# so no script here needs a /usr path.
#
# usage: runtime-shebangs.sh <tree>...
#   Files under a tree's usr/src/debug/ (debug sources, kept byte-identical to
#   the source they describe) and usr/lib/debug/ are left alone.
set -euo pipefail

[ "$#" -gt 0 ] || { echo "usage: runtime-shebangs.sh <tree>..." >&2; exit 2; }

view_path() {
	case $1 in
	sh) echo /bin/sh ;;
	bash) echo /bin/bash ;;
	python | python3) echo /bin/python3 ;;
	perl) echo /bin/perl ;;
	esac
}

rewritten=0
for tree in "$@"; do
	while IFS= read -r -d '' f; do
		[ "$(head -c 2 "$f")" = '#!' ] || continue
		first=$(head -n 1 "$f")
		line=${first#\#!}
		read -r interp args <<<"$line" || true
		case $interp in
		/usr/bin/env | /bin/env)
			read -r prog args <<<"$args" || true
			new=$(view_path "$prog")
			;;
		/bin/sh | /usr/bin/sh | /bin/bash | /usr/bin/bash | \
			/bin/python | /bin/python3 | /usr/bin/python | /usr/bin/python3 | \
			/bin/perl | /usr/bin/perl)
			new=$(view_path "${interp##*/}")
			;;
		*) new= ;;
		esac
		[ -n "$new" ] || continue
		replacement="#!$new${args:+ $args}"
		[ "$replacement" != "$first" ] || continue
		# Rewrite in place so the file keeps its inode and mode.
		tmp=$(mktemp)
		{ printf '%s\n' "$replacement"; tail -n +2 "$f"; } >"$tmp"
		cat "$tmp" >"$f"
		rm -f "$tmp"
		rewritten=$((rewritten + 1))
	done < <(find "$tree" \( -path "$tree/usr/src/debug" -o -path "$tree/usr/lib/debug" \) -prune \
		-o -type f -print0)
done

echo "runtime-shebangs: rewrote $rewritten #! lines"
