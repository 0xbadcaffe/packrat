#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${1:-"$ROOT/target/ebpf"}
CLANG=${CLANG:-clang}

mkdir -p "$OUT"
"$CLANG" -O2 -g -target bpfel \
  -Wall -Werror \
  -I "$ROOT/ebpf" \
  -c "$ROOT/ebpf/packrat_socket.bpf.c" \
  -o "$OUT/packrat_socket.bpf.o"

llvm-strip -g "$OUT/packrat_socket.bpf.o"
cargo build --manifest-path "$ROOT/Cargo.toml" --release \
  --features ebpf-sockets --bin packrat-socket-collector

printf 'eBPF object: %s\n' "$OUT/packrat_socket.bpf.o"
printf 'collector: %s\n' "$ROOT/target/release/packrat-socket-collector"
