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
    [[ $# == 3 && $2 == "$TEST_DIR/alerts.jsonl" && $3 == "$TEST_DIR/previous.jsonl" ]]
    jq -nc --arg session "$session" --arg capture "$capture" --argjson base "$base" --arg mode "${TEST_MODE:-normal}" '
        {record_type:"saved_capture_index",status:"saved",sampled_alerts:12,
         sampled_unscoped_open_high_or_critical:3,review_shortlist_truncated:true,
         review_shortlist:[range(1;(if $mode == "extra" then 7 else 6 end))
           | $base + {session_id:$session,capture_id:$capture,alert_id:.}]}
        | if $mode == "empty" then .review_shortlist = [] else . end'
    exit
fi
[[ $1 == --saved-alert && $2 == "$session" && $3 == "$capture" &&
    $5 == "$TEST_DIR/alerts.jsonl" && $6 == "$TEST_DIR/previous.jsonl" ]]
printf '%s\n' "$4" >> "$TEST_DIR/checks"
if [[ ${TEST_MODE:-normal} == timed ]]; then sleep 20; fi
case $4 in
    1) status=complete step=inspect_retained_frames ;;
    2) status=unavailable step=locate_original_capture ;;
    3) status=complete step=inspect_retained_frames; base=$(jq '.evidence_frame_set_sha256=("a"*64)' <<< "$base") ;;
    4) printf '%s\n' '{"record_type":"capture_triage","mode":"saved","status":"saved_alert_not_observed"}'; exit 1 ;;
    5) status=check_failed step=retry_evidence_check ;;
esac
jq -nc --arg session "$2" --arg capture "$3" --argjson id "$4" --arg status "$status" --arg step "$step" --argjson base "$base" '
    {record_type:"capture_triage",mode:"saved",status:"saved",alerts:[$base + {session_id:$session,capture_id:$capture,alert_id:$id,
      packet_evidence_status:$status,next_evidence_step:$step,detail:"private detail"}],
      evidence_checks:[{frames:[{status:"complete",bytes:[5,7]}],path:"private path"}]}'
if [[ $status == check_failed ]]; then exit 2; fi
STUB
run_review() {
    PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=13 "$dir/packrat-review-backlog" "$dir" "$dir/alerts.jsonl" "$dir/previous.jsonl"
}
run_review | jq -e '
    .record_type == "saved_alert_evidence_review" and .index_status == "saved"
    and .sampled_unscoped_open_high_or_critical == 3 and .review_shortlist_truncated
    and [.findings[].packet_evidence_status] ==
        ["complete","unavailable","changed_during_review","changed_during_review","check_failed"]
    and .findings[2].next_evidence_step == "refresh_saved_index"
    and (tostring | contains("private") | not) and all(.findings[]; has("evidence_frame_set_sha256") | not)' >/dev/null
[[ $(wc -l < "$dir/checks") == 5 ]]
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
