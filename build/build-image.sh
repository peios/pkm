#!/usr/bin/env bash
# Build the PKM kernel-build environment image from the pinned toolchain.
#
# usage: build-image.sh [image-tag]   (default tag: pkm-build)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
image=${1:-pkm-build}

# pins are the single source of truth
set -a
# shellcheck disable=SC1091
source "$here/toolchain.lock"
set +a

echo "build-image: $image  (debian $DEBIAN_SUITE @ $DEBIAN_SNAPSHOT, llvm $LLVM_VERSION, rust $RUST_VERSION, bindgen $BINDGEN_VERSION)"

docker build \
	--build-arg BASE_IMAGE="$BASE_IMAGE" \
	--build-arg DEBIAN_SNAPSHOT="$DEBIAN_SNAPSHOT" \
	--build-arg DEBIAN_SUITE="$DEBIAN_SUITE" \
	--build-arg LLVM_VERSION="$LLVM_VERSION" \
	--build-arg RUST_VERSION="$RUST_VERSION" \
	--build-arg BINDGEN_VERSION="$BINDGEN_VERSION" \
	-t "$image" \
	-f "$here/Containerfile" \
	"$here"

echo "build-image: built $image"
