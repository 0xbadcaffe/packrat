#!/usr/bin/env bash
set -euo pipefail

tool="$(dirname "$0")/../scripts/packrat-review-alert-gaps.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export TEST_DIR=$scratch
export PATH="$scratch:$PATH"
touch -- "$scratch/current.jsonl" "$scratch/old.jsonl"
cat > "$scratch/packrat-archive" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ ${*:1:11} == "--alerts $TEST_DIR/current.jsonl --session session-a --capture-id 00000000000000000000000000000001 --limit 512 --scan-bytes 8388608 --report-integrity" ]]
shift 11
if [[ ${TEST_MODE:-} == range-cap ]]; then
    [[ $# == 130 && $2 == 2..2 && ${128} == 128..128 && ${129} == --previous-log && ${130} == "$TEST_DIR/old.jsonl" ]]
    printf '%s\n' '{"alerts":[],"integrity":{"invalid_records":0,"oversized_records":0,"stopped_at_limit":false}}'
    exit
fi
[[ $* == "--alert-range 5..8 --alert-range 20..20 --previous-log $TEST_DIR/old.jsonl" ||
   $* == "--alert-range 5..9 --alert-range 20..20 --previous-log $TEST_DIR/old.jsonl" ||
   $* == "--alert-range 1..9007199254740991 --previous-log $TEST_DIR/old.jsonl" ]]
touch -- "$TEST_DIR/called"
case ${TEST_MODE:-normal} in
    raced) printf 'late record\n' >> "$TEST_DIR/current.jsonl" ;;
    failed) exit 2 ;;
esac
jq -nc --arg mode "${TEST_MODE:-normal}" --arg ranges "$*" '
    {capture_id:"00000000000000000000000000000001",session_id:"session-a",rule_id:"scan.horizontal",
     revision:13,severity:"WARN",disposition:"New",detail:"private text",packet_refs:[1,2],
     confidence:"correlated",evidence_frame_count:2,evidence_frame_set_sha256:("b"*64)} as $sample
    | {alerts:([$sample + {alert_id:6},
                $sample + {alert_id:8,severity:"CRIT",evidence_frame_count:0,evidence_frame_set_sha256:"private invalid hash"}]
        | if $mode == "out-of-range" or ($ranges | startswith("--alert-range 1..")) then . + [$sample + {alert_id:90}] else . end
        | if $mode == "wrong-scope" then .[0].session_id = "another-session"
          elif $mode == "duplicate" then . + [.[0]]
          elif $mode == "unknown-evidence" then .[1] += {evidence_frame_count:132,confidence:"private label"} else . end),
       integrity:{invalid_records:0,oversized_records:0,stopped_at_limit:false,
                 stopped_at_scan_budget:($mode == "bounded")}}'
STUB
chmod +x "$scratch/packrat-archive"
jq -nc '{
    record_type:"capture_coverage_report",
    scope:{session_id:"session-a",capture_id:"00000000000000000000000000000001",extra:"private metadata"},
    alert_sample_gap_reported:true,unobserved_alert_id_ranges_truncated:false,
    unobserved_alert_id_ranges:[{first_id:5,last_id:7},{first_id:7,last_id:8},{first_id:20,last_id:20}]
}' > "$scratch/report"
run_gap() {
    "$tool" "${1:-$scratch/report}" "$scratch/current.jsonl" "$scratch/old.jsonl"
}
run_gap | jq -e '
    .record_type == "alert_gap_reconciliation" and .saved_log_scan_complete
    and [.recovered_alerts[].alert_id] == [6,8] and .recovered_alerts[0].revision == 13
    and [.recovered_alerts[] | [.severity, .confidence, .evidence_frame_count, .evidence_frame_set_sha256, .next_evidence_step]] ==
        [["MEDIUM","correlated",2,("b"*64),"verify_frame_availability"],
         ["CRITICAL","correlated",0,null,"corroborate_with_host_or_service_logs"]]
    and [.ranges[] | [.first_id,.last_id,.found,.not_found_in_scan,.remaining_status]] ==
        [[5,8,2,2,"not_in_supplied_logs"],[20,20,0,1,"not_in_supplied_logs"]]
    and (tostring | contains("private") | not) and (tostring | contains("packet_refs") | not)' >/dev/null
TEST_MODE=bounded run_gap | jq -e '
    (.saved_log_scan_complete | not) and [.recovered_alerts[].alert_id] == [6,8]
    and all(.ranges[]; .remaining_status == "unverified")' >/dev/null
jq '.missing_previously_observed_alert_ids = [8,9] | .missing_previously_observed_alert_ids_truncated = false' \
    "$scratch/report" > "$scratch/with-disappeared"
run_gap "$scratch/with-disappeared" | jq -e '
    .missing_previously_observed_alert_ids == [8,9] and .request_ranges_truncated == false
    and [.ranges[] | [.first_id,.last_id,.found]] == [[5,9,2],[20,20,0]]' >/dev/null
jq '.unobserved_alert_id_ranges = [range(1;65)*4 | {first_id:.,last_id:.}]
    | .missing_previously_observed_alert_ids = [range(1;65)*4 - 2]' "$scratch/report" >"$scratch/combined-cap"
TEST_MODE=range-cap run_gap "$scratch/combined-cap" | jq -e '
    .request_ranges_truncated and (.ranges | length) == 64
    and .ranges[0].first_id == 2 and .ranges[-1].last_id == 128' >/dev/null
TEST_MODE=unknown-evidence run_gap | jq -e '
    .recovered_alerts[1] | .confidence==null and .evidence_frame_count==null
        and .evidence_frame_set_sha256==null and .next_evidence_step=="inspect_saved_alert"' >/dev/null
jq '.unobserved_alert_id_ranges = [{first_id:1,last_id:9007199254740991}]' "$scratch/report" > "$scratch/wide"
run_gap "$scratch/wide" | jq -e '.ranges[0].not_found_in_scan == 9007199254740988' >/dev/null

for mode in wrong-scope out-of-range duplicate raced failed; do
    if TEST_MODE=$mode run_gap >"$scratch/result" 2>/dev/null; then exit 1; fi
    [[ ! -s $scratch/result ]]
done
rm -- "$scratch/called"
jq '.unobserved_alert_id_ranges = []' "$scratch/report" > "$scratch/unlocated"
run_gap "$scratch/unlocated" | jq -e '.status == "unlocated_gap" and .saved_log_scan_complete == null' >/dev/null
jq '.alert_sample_gap_reported = false' "$scratch/unlocated" > "$scratch/quiet"
run_gap "$scratch/quiet" | jq -e '.status == "no_reported_ranges" and .saved_log_scan_complete == null' >/dev/null
[[ ! -e $scratch/called ]]
jq '.scope.capture_id = "invalid"' "$scratch/report" > "$scratch/invalid"
if run_gap "$scratch/invalid" >"$scratch/result" 2>/dev/null; then exit 1; fi
[[ ! -s $scratch/result && ! -e $scratch/called ]]
jq '.missing_previously_observed_alert_ids = [0]' "$scratch/report" > "$scratch/invalid"
if run_gap "$scratch/invalid" >"$scratch/result" 2>/dev/null; then exit 1; fi
[[ ! -s $scratch/result && ! -e $scratch/called ]]
printf '%s\n' 'alert gap reconciliation tests passed'
