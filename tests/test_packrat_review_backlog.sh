#!/usr/bin/env bash
set -euo pipefail

dir=$(mktemp -d)
trap 'rm -rf -- "$dir"' EXIT
cp -- "$(dirname "$0")/../scripts/packrat-review-backlog.sh" "$dir/packrat-review-backlog"
export TEST_DIR=$dir
touch -- "$dir/alerts.jsonl" "$dir/previous.jsonl"
cat > "$dir/packrat-triage" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $PACKRAT_TRIAGE_READ_TIMEOUT =~ ^[1-9][0-9]*$ && $PACKRAT_TRIAGE_ARCHIVE == "$TEST_DIR" ]]
[[ $PACKRAT_TRIAGE_AUTO_EVIDENCE == 0 && ! -v PACKRAT_TRIAGE_EVIDENCE_ALERT_ID ]]
session=session-a capture=00000000000000000000000000000001
base='{"rule_id":"scan.horizontal","revision":7,"confidence":"heuristic","severity":"HIGH",
       "disposition":"New","last_seen":42,"evidence_frame_count":2,
       "evidence_frame_set_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}'
if [[ $1 == --list-saved ]]; then
    shift
    offset=0
    if [[ $1 == --review-offset ]]; then offset=$2; shift 2; fi
    [[ $# == 2 && $1 == "$TEST_DIR/alerts.jsonl" && $2 == "$TEST_DIR/previous.jsonl" ]]
    jq -nc --arg session "$session" --arg capture "$capture" --argjson base "$base" --arg mode "${TEST_MODE:-normal}" --argjson offset "$offset" '
        (if $mode == "empty" then 0 else 7 end) as $eligible |
        {record_type:"saved_capture_index",status:"saved",sampled_alerts:12,
         sampled_unscoped_open_high_or_critical:3,sample_scan_complete:($mode != "bounded"),
         unscoped_review_queue:[{session_id:$session,alert_id:9,severity:"CRITICAL",disposition:"Reviewing",
           capture_id:"private scope",title:"private title",
           legacy_rule_hint:"dns.competing_responders",next_evidence_step:"private suggestion"}],
         review_eligible_in_sample:$eligible,review_offset:$offset,
         review_shortlist_truncated:($eligible > $offset + 5),
         next_review_offset:(if $eligible > $offset + 5 then $offset + 5 else null end),
         review_shortlist:[range($offset + 1;[($eligible + 1),($offset + (if $mode == "extra" then 7 else 6 end))] | min)
           | $base + {session_id:$session,capture_id:$capture,alert_id:.}]}'
    exit
fi
[[ $1 == --saved-alert && $2 == "$session" && $3 == "$capture" &&
    $5 == "$TEST_DIR/alerts.jsonl" && $6 == "$TEST_DIR/previous.jsonl" ]]
printf '%s\n' "$4" >> "$TEST_DIR/checks"
if [[ ${TEST_MODE:-normal} == timed ]]; then sleep 20; fi
counts=null
case $4 in
    1) status=complete step=inspect_retained_frames counts='{"complete":2}' ;;
    2) status=unavailable step=check_archive_integrity counts='{"missing":1,"unreadable":1}' ;;
    3) status=complete step=inspect_retained_frames counts='{"complete":2}'; base=$(jq '.evidence_frame_set_sha256=("a"*64)' <<< "$base") ;;
    4) printf '%s\n' '{"record_type":"capture_triage","mode":"saved","status":"saved_alert_not_observed"}'; exit 1 ;;
    5) status=check_failed step=retry_evidence_check ;;
    6|7) status=partial step=inspect_retained_and_recover_missing_frames counts='{"truncated":1,"missing":1}' ;;
esac
if [[ ${TEST_MODE:-normal} == invalid_counts && $4 == 1 ]]; then counts='{"complete":1}'; fi
jq -nc --arg session "$2" --arg capture "$3" --argjson id "$4" --arg status "$status" --arg step "$step" \
    --argjson base "$base" --argjson counts "$counts" '
    {record_type:"capture_triage",mode:"saved",status:"saved",alerts:[$base + {session_id:$session,capture_id:$capture,alert_id:$id,
      packet_evidence_status:$status,next_evidence_step:$step,evidence_availability:$counts,detail:"private detail"}],
      evidence_checks:[{frames:[{status:"complete",bytes:[5,7]}],path:"private path"}]}'
if [[ $status == check_failed ]]; then exit 2; fi
STUB
run_review() {
    PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=13 "$dir/packrat-review-backlog" "$@" "$dir" "$dir/alerts.jsonl" "$dir/previous.jsonl"
}
run_review | jq -e '
    .record_type == "saved_alert_evidence_review" and .index_status == "saved"
    and .sampled_unscoped_open_high_or_critical == 3 and .review_shortlist_truncated and .sample_scan_complete
    and .review_offset == 0 and .next_review_offset == 5 and .review_eligible_in_sample == 7
    and .unscoped_review_queue == [{
        session_id:"session-a",alert_id:9,severity:"CRITICAL",disposition:"Reviewing",last_seen:null,
        legacy_rule_hint:"dns.competing_responders",next_evidence_step:"locate_original_capture_or_host_logs"}]
    and [.findings[].packet_evidence_status] ==
        ["complete","unavailable","changed_during_review","changed_during_review","check_failed"]
    and .findings[0].evidence_availability == {complete:2}
    and .findings[1].evidence_availability == {missing:1,unreadable:1}
    and .findings[1].next_evidence_step == "check_archive_integrity"
    and .findings[2].next_evidence_step == "refresh_saved_index"
    and (tostring | contains("private") | not) and all(.findings[]; has("evidence_frame_set_sha256") | not)' >/dev/null
[[ $(wc -l < "$dir/checks") == 5 ]]
TEST_MODE=invalid_counts run_review | jq -e '.findings[0].packet_evidence_status == "check_failed"' >/dev/null
: > "$dir/checks"
TEST_MODE=bounded run_review --review-offset 5 | jq -e '
    .review_offset == 5 and .next_review_offset == null and (.sample_scan_complete | not)
    and [.findings[].alert_id] == [6,7] and all(.findings[]; .packet_evidence_status == "partial")' >/dev/null
[[ $(cat "$dir/checks") == $'6\n7' ]]
: > "$dir/checks"
run_review --review-offset 10 | jq -e '.sample_scan_complete and .findings == []' >/dev/null
[[ ! -s $dir/checks ]]
: > "$dir/checks"
TEST_MODE=empty run_review | jq -e '.findings == []' >/dev/null
[[ ! -s $dir/checks ]]
if TEST_MODE=extra run_review >"$dir/output" 2>/dev/null; then exit 1; fi
[[ ! -s $dir/output && ! -s $dir/checks ]]
PACKRAT_BACKLOG_TIMEOUT=2 TEST_MODE=timed run_review | jq -e '
    [.findings[].packet_evidence_status] ==
        ["check_timed_out","check_deferred","check_deferred","check_deferred","check_deferred"]' >/dev/null
[[ $(wc -l < "$dir/checks") == 1 ]]
printf '%s\n' 'saved alert backlog evidence tests passed'
