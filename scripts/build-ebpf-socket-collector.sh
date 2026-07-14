#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/target/ebpf"}
CLANG=${CLANG:-clang}

case "${PACKRAT_BPF_ARCH:-$(uname -m)}" in
    x86_64|amd64|x86) TARGET_ARCH=x86 ;;
    aarch64|arm64) TARGET_ARCH=arm64 ;;
    *)
        echo "unsupported eBPF collector architecture; set PACKRAT_BPF_ARCH to x86 or arm64" >&2
        exit 1
        ;;
esac

mkdir -p "$OUT"
"$CLANG" -O2 -g -target bpfel \
  -D"__TARGET_ARCH_$TARGET_ARCH" \
  -Wall -Werror \
  -I "$ROOT/ebpf" \
  -c "$ROOT/ebpf/packrat_socket.bpf.c" \
  -o "$OUT/packrat_socket.bpf.o"

llvm-strip -g "$OUT/packrat_socket.bpf.o"
cargo build --manifest-path "$ROOT/Cargo.toml" --release \
  --features ebpf-sockets --bin packrat-socket-collector

printf 'eBPF object: %s\n' "$OUT/packrat_socket.bpf.o"
printf 'collector: %s\n' "$ROOT/target/release/packrat-socket-collector"
