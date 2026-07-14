#!/usr/bin/env bash
set -euo pipefail

root="${DESTDIR:-}"
libexec="${root}/usr/libexec/packrat"
unit_dir="${root}/usr/lib/systemd/system"
tmpfiles_dir="${root}/usr/lib/tmpfiles.d"
logrotate_dir="${root}/etc/logrotate.d"
doc_dir="${root}/usr/share/doc/packrat"

binary="target/release/packrat-socket-collector"
object="target/ebpf/packrat_socket.bpf.o"

if [[ ! -x "$binary" || ! -f "$object" ]]; then
    echo "collector artifacts are missing; run scripts/build-ebpf-socket-collector.sh first" >&2
    exit 1
fi

install -d "$libexec" "$unit_dir" "$tmpfiles_dir" "$logrotate_dir" "$doc_dir"
install -m 0755 "$binary" "$libexec/packrat-socket-collector"
install -m 0644 "$object" "$libexec/packrat_socket.bpf.o"
install -m 0644 packaging/systemd/packrat-socket-collector.service "$unit_dir/"
install -m 0644 packaging/tmpfiles.d/packrat-socket-collector.conf "$tmpfiles_dir/"
install -m 0644 packaging/logrotate/packrat-socket-collector "$logrotate_dir/"
install -m 0644 docs/USER_MANUAL.md "$doc_dir/"

echo "installed Packrat socket collector under ${root:-/}"
