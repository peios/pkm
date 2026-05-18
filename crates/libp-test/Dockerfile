# Static-musl build of libp-test for injection into Provium guests.
#
# Why Docker: the Nix-managed rustc on host doesn't expose the musl
# target std cleanly (rustup target add writes to a toolchain dir the
# Nix rustc never looks at). Following the same pattern as peinit.
#
# Build (from pkm/ root):
#   docker build -f crates/libp-test/Dockerfile \
#                -o type=local,dest=crates/libp-test/dist .
# Output:
#   crates/libp-test/dist/libp-test

FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release --target x86_64-unknown-linux-musl -p libp-test

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/libp-test /libp-test
