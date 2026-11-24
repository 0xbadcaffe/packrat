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
    coverage:{record_type:"capture_coverage_report",status:"sampled",coverage_policy:"continuous_journal_v7",
              scope:{capture_id:"a",session_id:"one"},
              first_record_at:"2026-11-23T11:00:00Z",last_record_at:"2026-11-23T11:01:00Z",
              scoped_records:2,healthy_intervals:1,excluded_intervals:0,healthy_seconds:60,
              healthy_packets:2000,alert_comparable_intervals:1,alert_comparable_packets:2000,
              alert_save_failure_intervals:0,alert_save_counter_unverified_intervals:0,
              alert_save_backlog_drop_intervals:0,alert_save_backlog_unverified_intervals:0,
              alert_journal_counter_unverified_intervals:0,journal_tail_unconfirmed_events:0,
              alert_log_snapshot_unverified_intervals:0,
              observed_openings:1,observed_openings_per_10000_packets:999}
}' > "$before"
jq '.build.scope = {capture_id:"b",session_id:"two"} | .coverage.scope = .build.scope
    | .build.capture_run_id = "run-b" | .build.sha256 = ("b"*64)
    | .coverage.first_record_at = "2026-11-23T11:01:00Z"
    | .coverage.last_record_at = "2026-11-23T11:02:00Z"
    | .coverage.observed_openings = 0' "$before" > "$after"

unset PACKRAT_BASELINE_MIN_SECONDS PACKRAT_BASELINE_MIN_PACKETS
dns_coverage='{"no_decline_intervals":0,"decline_intervals":1,"unverified_intervals":0,"no_decline_packets":0,"no_decline_seconds":0,"observed_declines":{"query_key_declines":2,"query_candidate_declines":1,"nxdomain_client_declines":0,"external_resolver_pair_declines":0}}'
jq --argjson dns "$dns_coverage" '.coverage.dns_capacity_coverage=$dns | .coverage.dns_capacity_coverage.note="private"' \
    "$after" > "$tmp/dns-after.json"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$before" "$tmp/dns-after.json" | jq -e --argjson dns "$dns_coverage" '
    .status=="separate_capture_windows" and .before.dns_capacity_coverage==null
    and .after.dns_capacity_coverage==$dns and .observed_rate_delta_per_10000_packets==-5' >/dev/null
for patch in '.no_decline_packets=1' '.unverified_intervals=1' '.observed_declines.query_key_declines=-1'; do
    jq ".coverage.dns_capacity_coverage |= ($patch)" "$tmp/dns-after.json" > "$fixture"
    PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$before" "$fixture" | jq -e '
        .status=="separate_capture_windows" and .after.dns_capacity_coverage==null' >/dev/null
done
tcp_coverage='{"no_eviction_intervals":1,"eviction_intervals":0,"unverified_intervals":0,"no_eviction_packets":2000,"no_eviction_seconds":60,"observed_evictions":0}'
jq --argjson tcp "$tcp_coverage" '.coverage.tcp_stream_cache_coverage=($tcp + {note:"private"})' \
    "$after" > "$tmp/tcp-after.json"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$before" "$tmp/tcp-after.json" | jq -e --argjson tcp "$tcp_coverage" '
    .status=="separate_capture_windows" and .before.tcp_stream_cache_coverage==null
    and .after.tcp_stream_cache_coverage==$tcp and .observed_rate_delta_per_10000_packets==-5' >/dev/null
for patch in '.no_eviction_packets=2001' '.no_eviction_seconds=59' '.unverified_intervals=1' \
    '.observed_evictions=null' '.observed_evictions=1' '.observed_evictions=-1'; do
    jq ".coverage.tcp_stream_cache_coverage |= ($patch)" "$tmp/tcp-after.json" > "$fixture"
    PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$before" "$fixture" | jq -e '
        .status=="separate_capture_windows" and .after.tcp_stream_cache_coverage==null' >/dev/null
done
bash "$tool" "$before" "$after" | jq -e '
    .status == "thin_alert_coverage" and .observed_rate_delta_per_10000_packets == null
    and .before.openings_per_10000_packets == 5 and .after.openings_per_10000_packets == 0
    and .comparison_minimums == {seconds:300,packets:1000}' >/dev/null
PACKRAT_BASELINE_MIN_SECONDS=60 PACKRAT_BASELINE_MIN_PACKETS=2000 bash "$tool" "$before" "$after" | jq -e '
    .status == "separate_capture_windows" and .same_build == false
    and .before.openings_per_10000_packets == 5 and .after.openings_per_10000_packets == 0
    and .before.comparable_seconds == 60 and .after.comparable_seconds == 60
    and .observed_rate_delta_per_10000_packets == -5' >/dev/null
jq '.coverage |= (.coverage_policy="continuous_journal_v8" | .alert_reverified_intervals=1 | .alert_sample_gap_reported=true)' \
    "$before" >"$tmp/v8-before"
jq '.coverage |= (.coverage_policy="continuous_journal_v8" | .alert_reverified_intervals=0)' "$after" >"$tmp/v8-after"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/v8-before" "$tmp/v8-after" | jq -e '
    .status=="separate_capture_windows" and .before.alert_reverified_intervals==1 and .after.alert_reverified_intervals==0
    and .observed_rate_delta_per_10000_packets==-5' >/dev/null
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$before" "$tmp/v8-after" | jq -e '
    .status=="coverage_policy_unverified" and .observed_rate_delta_per_10000_packets==null' >/dev/null
for patch in 'del(.coverage.alert_reverified_intervals)' '.coverage.alert_reverified_intervals=2' \
    '.coverage.alert_sample_gap_reported=false'; do
    jq "$patch" "$tmp/v8-before" >"$fixture"
    if bash "$tool" "$fixture" "$tmp/v8-after" >/dev/null 2>&1; then exit 1; fi
done
jq '.coverage.opening_rule_breakdown = {rules:[{rule_id:"dns.changed_answers",revision:9,openings:1}],unattributed_openings:0,omitted_rule_openings:0}' \
    "$before" > "$tmp/rule-before.json"
jq '.coverage.observed_openings = 2 | .coverage.opening_rule_breakdown =
    {rules:[{rule_id:"dns.changed_answers",revision:10,openings:2}],unattributed_openings:0,omitted_rule_openings:0}' \
    "$after" > "$tmp/rule-after.json"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/rule-before.json" "$tmp/rule-after.json" | jq -e '
    .rule_rate_status == "rule_revisions_unverified" and .rule_rate_deltas == []
    and .rule_rate_unpaired == [{rule_id:"dns.changed_answers",reason:"different_revisions",
        before:[{revision:9,openings:1}],after:[{revision:10,openings:2}]}]
    and .observed_rate_delta_per_10000_packets == 5' >/dev/null
jq '.coverage.opening_rule_breakdown.rules[0].revision=9' "$tmp/rule-after.json" > "$tmp/rule-same.json"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/rule-before.json" "$tmp/rule-same.json" | jq -e '
    .rule_rate_status == "comparable" and .rule_rate_unpaired == []
    and .rule_rate_deltas == [{rule_id:"dns.changed_answers",revision:9,before_openings:1,
        after_openings:2,delta_per_10000_packets:5}]' >/dev/null
jq '.coverage.observed_openings=5 | .coverage.opening_rule_breakdown.rules +=
    [{rule_id:"scan.horizontal",revision:5,openings:1},{rule_id:"scan.horizontal",revision:6,openings:1},
     {rule_id:"dns.unmatched_response",revision:1,openings:1}]' "$tmp/rule-same.json" > "$tmp/rule-mixed.json"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/rule-before.json" "$tmp/rule-mixed.json" | jq -e '
    .rule_rate_status == "partially_comparable" and [.rule_rate_deltas[].rule_id] == ["dns.changed_answers"]
    and .rule_rate_unpaired == [
        {rule_id:"dns.unmatched_response",reason:"not_observed_in_both_windows",before:[],after:[{revision:1,openings:1}]},
        {rule_id:"scan.horizontal",reason:"mixed_revisions",before:[],after:[{revision:5,openings:1},{revision:6,openings:1}]}]
    and .observed_rate_delta_per_10000_packets == 20' >/dev/null
jq '.coverage.observed_openings=0 | .coverage.opening_rule_breakdown=
    {rules:[],unattributed_openings:0,omitted_rule_openings:0}' "$before" > "$tmp/quiet-before"
jq '.coverage.observed_openings=0 | .coverage.opening_rule_breakdown=
    {rules:[],unattributed_openings:0,omitted_rule_openings:0}' "$after" > "$tmp/quiet-after"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/quiet-before" "$tmp/quiet-after" | jq -e '
    .rule_rate_status == "no_rule_openings" and .rule_rate_deltas == [] and .rule_rate_unpaired == []
    and .observed_rate_delta_per_10000_packets == 0' >/dev/null
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/rule-before.json" "$after" | jq -e '
    .rule_rate_status == "attribution_incomplete" and .rule_rate_deltas == null and .rule_rate_unpaired == null
    and .observed_rate_delta_per_10000_packets == -5' >/dev/null
jq '.coverage.opening_rule_breakdown = {rules:[],unattributed_openings:2,omitted_rule_openings:0}' \
    "$tmp/rule-after.json" > "$fixture"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$tmp/rule-before.json" "$fixture" | jq -e '
    .rule_rate_status == "attribution_incomplete" and .rule_rate_deltas == null' >/dev/null
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
jq '.coverage.coverage_policy = "continuous_journal_v4"' "$before" > "$fixture"
bash "$tool" "$fixture" "$after" | jq -e '
    .status == "coverage_policy_unverified" and .before.coverage_policy == "continuous_journal_v4"
    and .before.openings_per_10000_packets == null and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.coverage_policy = "continuous_journal_v5"
    | del(.coverage.alert_journal_counter_unverified_intervals,.coverage.journal_tail_unconfirmed_events)' "$before" > "$fixture"
bash "$tool" "$fixture" "$after" | jq -e '
    .status == "coverage_policy_unverified" and .before.coverage_policy == "continuous_journal_v5"
    and .before.journal_tail_unconfirmed_events == null and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq '.coverage.coverage_policy = "continuous_journal_v6"
    | del(.coverage.alert_log_snapshot_unverified_intervals)' "$before" > "$fixture"
PACKRAT_BASELINE_MIN_SECONDS=60 bash "$tool" "$fixture" "$after" | jq -e '
    .status == "coverage_policy_unverified" and .before.coverage_policy == "continuous_journal_v6"
    and .before.alert_log_snapshot_unverified_intervals == null
    and .after.alert_log_snapshot_unverified_intervals == 0
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
jq '.coverage.opening_rule_breakdown.rules[0].openings += 1' "$tmp/rule-after.json" > "$fixture"
reject
jq '.coverage.observed_openings = 4 | .coverage.opening_rule_breakdown.rules |= . + .' "$tmp/rule-after.json" > "$fixture"
reject
jq '.coverage.healthy_seconds = 61' "$after" > "$fixture"
reject
jq '.coverage.alert_save_backlog_drop_intervals = 1' "$after" > "$fixture"
reject
jq '.coverage.alert_journal_counter_unverified_intervals = 1' "$after" > "$fixture"
reject
jq '.coverage.alert_log_snapshot_unverified_intervals = 1' "$after" > "$fixture"
reject
jq 'del(.coverage.alert_log_snapshot_unverified_intervals)' "$after" > "$fixture"
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
     packet_counter_gap:false,healthy_capture_since:1,alert_sample_gap:false,link_decodable:true,alert_saving:true,alert_save_failures:0,alert_save_backlog_dropped:0,
     alert_log_integrity:{invalid_records:0,oversized_records:0,stopped_at_scan_budget:null},
     alert_log_advanced_during_review:false,
     highest_observed_alert_id:0,checkpoint:true,journal_writer:"one",journal_sequence:1,journal_unconfirmed_events:0} as $initial
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
    and .coverage.coverage_policy == "continuous_journal_v8" and .coverage.alert_reverified_intervals == 0
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
bash "$tool" "$tmp/insufficient" "$tmp/v8-after" | jq -e '
    .status == "insufficient_alert_coverage" and .before.openings == null
    and .observed_rate_delta_per_10000_packets == null' >/dev/null
jq -c '.status = "stale"' "$tmp/journal-original" > "$tmp/journal"
! record "$tmp/stale" 2>/dev/null || exit 1
[[ ! -e $tmp/stale ]]
jq -c '.capture_id = "wrong-capture"' "$tmp/journal-original" > "$tmp/journal"
! record "$tmp/wrong" 2>/dev/null || exit 1
[[ ! -e $tmp/wrong ]]

printf '%s\n' 'watcher baseline recording tests passed'
