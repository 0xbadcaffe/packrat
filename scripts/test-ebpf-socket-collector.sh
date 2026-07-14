#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
collector="$root/target/release/packrat-socket-collector"
probe="$root/target/release/packrat-socket-probe"
object="$root/target/ebpf/packrat_socket.bpf.o"
work=$(mktemp -d)
events="$work/socket-events.csv"
log="$work/collector.log"
collector_pid=""

cleanup() {
    if [[ -n "$collector_pid" ]]; then
        kill "$collector_pid" 2>/dev/null || true
        wait "$collector_pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

for artifact in "$collector" "$probe" "$object"; do
    if [[ ! -e "$artifact" ]]; then
        echo "missing $artifact; run scripts/build-ebpf-socket-collector.sh first" >&2
        exit 1
    fi
done

"$collector" --object "$object" --output "$events" --stats-seconds 1 \
    >"$log" 2>&1 &
collector_pid=$!
sleep 1
if ! kill -0 "$collector_pid" 2>/dev/null; then
    cat "$log" >&2
    echo "collector failed to attach; run this test with CAP_BPF and CAP_PERFMON" >&2
    exit 1
fi

"$probe"
sleep 1

grep -q '^TCP,.*packrat-socket-' "$events"
grep -q '^UDP,.*packrat-socket-' "$events"
echo "verified TCP accept/connect and UDP send/receive attribution"
