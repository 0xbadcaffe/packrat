#!/usr/bin/env bash
set -euo pipefail

kernel=${1:-$(uname -r)}
library_root=${2:-/usr/lib}
standalone=${3:-}
if [[ $# -lt 2 ]]; then
    standalone=$(command -v perf || true)
fi

# Ubuntu packages can place perf in a versioned directory without the flavour.
for candidate in \
    "$standalone" \
    "$library_root/linux-tools/$kernel/perf" \
    "$library_root/linux-tools/${kernel%-*}/perf" \
    "$library_root/linux-tools-$kernel/perf" \
    "$library_root/linux-tools-${kernel%-*}/perf"; do
    if [[ -f "$candidate" && -x "$candidate" ]] && "$candidate" --version >&2; then
        printf '%s\n' "$candidate"
        exit 0
    fi
done

printf 'No executable perf for kernel %s under %s\n' "$kernel" "$library_root" >&2
exit 1
