#!/usr/bin/env bash
set -euo pipefail

tool="$(dirname "$0")/../scripts/packrat-watch-baseline.sh"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
before=$tmp/before.json after=$tmp/after.json fixture=$tmp/fixture.json

jq -nc '{
    record_type:"capture_build_baseline",
    build:{record_type:"verified_capture_build",interface:"wlan1",sha256:("a"*64),
           scope:{capture_id:"a",session_id:"one"},capture_run_id:"run-a",
           packets:2500,observed_at:"2026-11-23T11:02:00Z"},
    coverage:{record_type:"capture_coverage_report",status:"sampled",
              scope:{capture_id:"a",session_id:"one"},
              first_record_at:"2026-11-23T11:00:00Z",last_record_at:"2026-11-23T11:01:00Z",
              scoped_records:2,healthy_intervals:1,excluded_intervals:0,healthy_seconds:60,
              healthy_packets:2000,alert_comparable_intervals:1,alert_comparable_packets:2000,
              observed_openings:1,observed_openings_per_10000_packets:999}
}' > "$before"
jq '.build.scope = {capture_id:"b",session_id:"two"} | .coverage.scope = .build.scope
    | .build.capture_run_id = "run-b" | .build.sha256 = ("b"*64)
    | .coverage.first_record_at = "2026-11-23T11:01:00Z"
    | .coverage.last_record_at = "2026-11-23T11:02:00Z"
    | .coverage.observed_openings = 0' "$before" > "$after"

bash "$tool" "$before" "$after" | jq -e '
    .status == "separate_capture_windows" and .same_build == false
    and .before.openings_per_10000_packets == 5 and .after.openings_per_10000_packets == 0
    and .observed_rate_delta_per_10000_packets == -5' >/dev/null
bash "$tool" "$before" "$before" | jq -e '
    .status == "same_capture" and .same_build == true
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
bash "$tool" "$after" "$before" | jq -e '
    .status == "overlapping_or_reversed_windows"
    and .observed_rate_delta_per_10000_packets == null' >/dev/null

jq '.build.interface = "eth0"' "$after" > "$fixture"
bash "$tool" "$before" "$fixture" | jq -e '
    .status == "different_interfaces" and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.alert_comparable_intervals = 0 | .coverage.alert_comparable_packets = 0
    | .coverage.observed_openings = null' "$after" > "$fixture"
bash "$tool" "$before" "$fixture" | jq -e '
    .status == "insufficient_alert_coverage" and .after.openings_per_10000_packets == null
    and .observed_rate_delta_per_10000_packets == null' >/dev/null

reject() {
    if bash "$tool" "$before" "$fixture" > "$tmp/result" 2>/dev/null; then
        printf '%s\n' 'Expected invalid baseline to fail' >&2; exit 1
    fi
    [[ ! -s $tmp/result ]]
}
jq '.coverage.scope.session_id = "other"' "$after" > "$fixture"
reject
jq '.build.sha256 = ("b"*64)' "$before" > "$fixture"
reject
jq '.coverage.observed_openings = 1.5' "$after" > "$fixture"
reject
jq '.coverage.healthy_seconds = 61' "$after" > "$fixture"
reject
jq '.build.observed_at = "2026-11-23T11:01:59Z"' "$after" > "$fixture"
reject
jq '.coverage.first_record_at = "not-a-date"' "$after" > "$fixture"
reject
cp -- "$after" "$fixture"
printf '%65537s' '' >> "$fixture"
reject
rm -- "$fixture"
mkfifo -- "$fixture"
reject

printf '%s\n' 'watcher baseline comparison tests passed'
