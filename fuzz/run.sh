#!/usr/bin/env bash
# Run fuzz targets in the nix environment.
# Usage: ./run.sh <target> [libfuzzer-args...]
# Example: ./run.sh fuzz_sid -max_total_time=60
# List targets: ./run.sh --list
set -euo pipefail

cd "$(dirname "$0")"

TARGETS=(fuzz_sid fuzz_ace fuzz_acl fuzz_sd fuzz_token_spec fuzz_conditional)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${TARGETS[@]}"
    exit 0
fi

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <target> [libfuzzer-args...]" >&2
    echo "targets: ${TARGETS[*]}" >&2
    exit 1
fi

TARGET="$1"
shift

# Nix puts stable cargo first in PATH. Prepend nightly so cargo-fuzz
# can invoke cargo with -Z flags.
NIGHTLY_BIN="$(dirname "$(rustup which cargo --toolchain nightly)")"
export PATH="$NIGHTLY_BIN:$PATH"

exec cargo fuzz run "$TARGET" -- "$@"
