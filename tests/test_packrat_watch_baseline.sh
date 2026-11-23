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
    coverage:{record_type:"capture_coverage_report",status:"sampled",coverage_policy:"continuous_journal_v2",
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

unset PACKRAT_BASELINE_MIN_SECONDS PACKRAT_BASELINE_MIN_PACKETS
bash "$tool" "$before" "$after" | jq -e '
    .status == "thin_alert_coverage" and .observed_rate_delta_per_10000_packets == null
    and .before.openings_per_10000_packets == 5 and .after.openings_per_10000_packets == 0
    and .comparison_minimums == {seconds:300,packets:1000}' >/dev/null
PACKRAT_BASELINE_MIN_SECONDS=60 PACKRAT_BASELINE_MIN_PACKETS=2000 bash "$tool" "$before" "$after" | jq -e '
    .status == "separate_capture_windows" and .same_build == false
    and .before.openings_per_10000_packets == 5 and .after.openings_per_10000_packets == 0
    and .before.comparable_seconds == 60 and .after.comparable_seconds == 60
    and .observed_rate_delta_per_10000_packets == -5' >/dev/null
PACKRAT_BASELINE_MIN_SECONDS=60 PACKRAT_BASELINE_MIN_PACKETS=2001 bash "$tool" "$before" "$after" | jq -e '
    .status == "thin_alert_coverage" and .observed_rate_delta_per_10000_packets == null' >/dev/null
for invalid in 0 01 -1 '3.5'; do
    if PACKRAT_BASELINE_MIN_SECONDS="$invalid" bash "$tool" "$before" "$after" >/dev/null 2>&1; then exit 1; fi
done
bash "$tool" "$before" "$before" | jq -e '
    .status == "same_capture" and .same_build == true
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
bash "$tool" "$after" "$before" | jq -e '
    .status == "overlapping_or_reversed_windows"
    and .observed_rate_delta_per_10000_packets == null' >/dev/null

jq '.build.interface = "eth0"' "$after" > "$fixture"
bash "$tool" "$before" "$fixture" | jq -e '
    .status == "different_interfaces" and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq 'del(.coverage.coverage_policy)' "$before" > "$fixture"
bash "$tool" "$fixture" "$after" | jq -e '
    .status == "coverage_policy_unverified" and .before.coverage_policy == null
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.alert_comparable_intervals = 0 | .coverage.alert_comparable_packets = 0
    | .coverage.observed_openings = null' "$after" > "$fixture"
bash "$tool" "$before" "$fixture" | jq -e '
    .status == "insufficient_alert_coverage" and .after.openings_per_10000_packets == null
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.healthy_intervals = 2 | .coverage.scoped_records = 3' "$after" > "$fixture"
PACKRAT_BASELINE_MIN_SECONDS=30 bash "$tool" "$before" "$fixture" | jq -e '
    .status == "comparable_duration_unverified" and .after.comparable_seconds == null
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.alert_comparable_seconds = 30' "$fixture" > "$tmp/partial.json"
PACKRAT_BASELINE_MIN_SECONDS=30 bash "$tool" "$before" "$tmp/partial.json" | jq -e '
    .status == "separate_capture_windows" and .after.comparable_seconds == 30
    and .observed_rate_delta_per_10000_packets == -5' >/dev/null

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
jq '.coverage.alert_comparable_seconds = 30' "$after" > "$fixture"
reject
jq '.coverage.healthy_intervals = 2 | .coverage.scoped_records = 3 | .coverage.alert_comparable_seconds = 60' "$after" > "$fixture"
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

bin=$tmp/bin
mkdir "$bin"
cp -- "$tool" "$bin/packrat-watch-baseline"
cp -- "$(dirname "$tool")/packrat-watch-coverage.sh" "$bin/packrat-watch-coverage"
export TEST_DIR=$tmp
cat > "$bin/packrat-rollout" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $* == "--identify wlan1" && $PACKRAT_ROLLOUT_TRIAGE_STATE == "$TEST_DIR/journal" &&
   $PACKRAT_ROLLOUT_REQUIRE_TRIAGE_JOURNAL == 1 && -x $PACKRAT_ROLLOUT_TRIAGE_CHECK ]]
if [[ -f $TEST_DIR/observed ]]; then
    cat "$TEST_DIR/build-after"
else
    touch "$TEST_DIR/observed"
    cat "$TEST_DIR/build-before"
fi
STUB
cat > "$bin/packrat-watch-triage" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == --history && $2 == "$TEST_DIR/journal" ]]
cat -- "$2"
STUB
chmod +x "$bin/packrat-watch-triage"
jq -c '.build' "$before" > "$tmp/build-before"
jq '.packets += 15 | .observed_at = "2026-11-23T11:02:01Z"' "$tmp/build-before" > "$tmp/build-after"
jq -nc '
    {record_type:"capture_triage_watch",status:"current",capture_id:"a",session_id:"one",
     updated_at:"2026-11-23T11:00:00Z",buffer_drops:0,packets:100,capture_queue_full_packets:0,truncated_frames:0,
     packet_counter_gap:false,healthy_capture_since:1,alert_sample_gap:false,
     highest_observed_alert_id:0,checkpoint:true,journal_writer:"one",journal_sequence:1} as $initial
    | $initial, ($initial | .updated_at = "2026-11-23T11:01:00Z" | .packets = 2100
      | .journal_sequence = 2 | .highest_observed_alert_id = 1 | .alert_changes.newly_observed = [1])
' > "$tmp/journal"
record() {
    rm -f -- "$tmp/observed"
    "$bin/packrat-watch-baseline" --record wlan1 "$tmp/journal" "$1"
}
record "$tmp/recorded"
[[ $(stat -c %a -- "$tmp/recorded") == 600 ]]
jq -e '.build.packets == 2515 and .coverage.observed_openings == 1
    and .coverage.coverage_policy == "continuous_journal_v2"
    and .coverage.alert_comparable_packets == 2000 and .coverage.alert_comparable_seconds == 60' "$tmp/recorded" >/dev/null
bash "$tool" "$before" "$tmp/recorded" | jq -e '.status == "same_capture"' >/dev/null

saved=$(sha256sum -- "$tmp/recorded")
! record "$tmp/recorded" 2>/dev/null || exit 1
[[ $(sha256sum -- "$tmp/recorded") == "$saved" ]]
ln -s -- "$tmp/recorded" "$tmp/output-link"
! record "$tmp/output-link" 2>/dev/null || exit 1
[[ -L $tmp/output-link && $(sha256sum -- "$tmp/recorded") == "$saved" ]]

jq '.capture_run_id = "changed"' "$tmp/build-before" > "$tmp/build-after"
! record "$tmp/unstable" 2>/dev/null || exit 1
[[ ! -e $tmp/unstable ]]
jq '.packets -= 1' "$tmp/build-before" > "$tmp/build-after"
! record "$tmp/regressed" 2>/dev/null || exit 1
[[ ! -e $tmp/regressed ]]
cp -- "$tmp/build-before" "$tmp/build-after"
jq -sc '.[0]' "$tmp/journal" > "$tmp/single"
cp -- "$tmp/journal" "$tmp/journal-original"
mv -- "$tmp/single" "$tmp/journal"
record "$tmp/insufficient"
jq '.coverage.coverage_policy = "capture_loss_counters_v1"' "$after" > "$tmp/after-v1.json"
bash "$tool" "$before" "$tmp/after-v1.json" | jq -e '
    .status == "coverage_policy_unverified" and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.coverage_policy = "capture_loss_counters_v1"' "$before" > "$tmp/before-v1.json"
bash "$tool" "$tmp/before-v1.json" "$tmp/after-v1.json" | jq -e '
    .status == "coverage_policy_unverified" and .before.openings_per_10000_packets == null
    and .after.openings_per_10000_packets == null' >/dev/null
bash "$tool" "$tmp/insufficient" "$after" | jq -e '
    .status == "insufficient_alert_coverage" and .before.openings == null
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq -c '.status = "stale"' "$tmp/journal-original" > "$tmp/journal"
! record "$tmp/stale" 2>/dev/null || exit 1
[[ ! -e $tmp/stale ]]
jq -c '.capture_id = "wrong-capture"' "$tmp/journal-original" > "$tmp/journal"
! record "$tmp/wrong" 2>/dev/null || exit 1
[[ ! -e $tmp/wrong ]]

printf '%s\n' 'watcher baseline recording tests passed'
