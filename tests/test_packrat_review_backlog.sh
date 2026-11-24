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
if [[ ${TEST_MODE:-normal} == by_rule || ${TEST_MODE:-normal} == wrong_rule ]]; then
    base=$(jq -c '. + {rule_id:"ipv6.ra_router_link_change",severity:"MEDIUM"}' <<< "$base")
fi
if [[ $1 == --list-saved ]]; then
    [[ ! -v PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE ]]
    shift
    offset=0 rule='' review_session='' review_capture=''
    if [[ $1 == --review-scope ]]; then review_session=$2 review_capture=$3; shift 3; fi
    if [[ $1 == --review-rule ]]; then rule=$2; shift 2; fi
    if [[ $1 == --review-offset ]]; then offset=$2; shift 2; fi
    [[ $# == 2 && $1 == "$TEST_DIR/alerts.jsonl" && $2 == "$TEST_DIR/previous.jsonl" ]]
    jq -nc --arg session "$session" --arg capture "$capture" --argjson base "$base" --arg mode "${TEST_MODE:-normal}" --argjson offset "$offset" --arg rule "$rule" \
        --arg selected_session "$review_session" --arg selected_capture "$review_capture" '
        (if $mode == "empty" then 0 elif $rule != "" then 1 else 7 end) as $eligible |
        {record_type:"saved_capture_index",status:"saved",sampled_alerts:12,
         review_rule:(if $rule == "" then null else $rule end),
         review_scope:(if $selected_capture == "" then null else {session_id:$selected_session,capture_id:$selected_capture} end),
         sampled_unscoped_open_high_or_critical:3,sample_scan_complete:($mode != "bounded"),
         unscoped_review_queue:[{session_id:$session,alert_id:9,severity:"CRITICAL",disposition:"Reviewing",
           capture_id:"private scope",title:"private title",
           legacy_rule_hint:"dns.competing_responders",next_evidence_step:"private suggestion"}],
         review_eligible_in_sample:$eligible,review_offset:$offset,
         review_shortlist_truncated:($eligible > $offset + 5),
         next_review_offset:(if $eligible > $offset + 5 then $offset + 5 else null end),
         review_shortlist:[range($offset + 1;[($eligible + 1),($offset + (if $mode == "extra" then 7 else 6 end))] | min)
           | $base + {session_id:$session,capture_id:$capture,alert_id:.}]}
         | if $selected_capture == "" then . else .sampled_unscoped_open_high_or_critical = 0 | .unscoped_review_queue = [] end'
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
case $4 in
    1|3) base=$(jq -c '.reader_rule_revision=8' <<< "$base") ;;
    2) base=$(jq -c '.reader_rule_revision=7' <<< "$base") ;;
    5) base=$(jq -c '.reader_rule_revision="private revision"' <<< "$base") ;;
esac
if [[ ${TEST_MODE:-normal} == socket ]]; then
    [[ $PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE == "$TEST_DIR/socket context.jsonl" ]]
    marker=latest
    if [[ $4 == 2 ]]; then marker=earlier; fi
    if [[ $4 == 5 ]]; then marker='private invalid marker'; fi
    base=$(jq -c --arg marker "$marker" '. + {socket_evidence:$marker,socket_context:{process:"private process",pid:123}}' <<< "$base")
else
    [[ -z ${PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE:-} ]]
fi
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
    and [.findings[] | [.revision,.reader_rule_revision,.rule_revision_differs_from_reader,.severity]] ==
        [[7,8,true,"HIGH"],[7,7,false,"HIGH"],[7,null,null,"HIGH"],[7,null,null,"HIGH"],[7,null,null,"HIGH"]]
    and .findings[1].next_evidence_step == "check_archive_integrity"
    and .findings[2].next_evidence_step == "refresh_saved_index"
    and (tostring | contains("private") | not) and all(.findings[]; has("evidence_frame_set_sha256") | not)' >/dev/null
[[ $(wc -l < "$dir/checks") == 5 ]]
touch -- "$dir/socket context.jsonl"
TEST_MODE=socket run_review --socket-context "$dir/socket context.jsonl" | jq -e '
    [.findings[].socket_evidence] == ["latest","earlier",null,null,null]
    and .findings[1].packet_evidence_status == "unavailable"
    and (tostring | contains("private") | not)' >/dev/null
ln -s -- "$dir/socket context.jsonl" "$dir/socket-link"
if run_review --socket-context "$dir/socket-link" >/dev/null 2>&1; then exit 1; fi
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
TEST_MODE=by_rule run_review --review-rule ipv6.ra_router_link_change | jq -e '
    .review_rule == "ipv6.ra_router_link_change" and .review_eligible_in_sample == 1
    and [.findings[] | [.rule_id,.severity,.packet_evidence_status]] == [["ipv6.ra_router_link_change","MEDIUM","complete"]]' >/dev/null
[[ $(cat "$dir/checks") == 1 ]]
: > "$dir/checks"
if TEST_MODE=wrong_rule run_review --review-rule other.rule >/dev/null 2>&1; then exit 1; fi
[[ ! -s $dir/checks ]]
TEST_MODE=by_rule run_review --review-scope session-a 00000000000000000000000000000001 \
    --review-rule ipv6.ra_router_link_change | jq -e '
    .review_scope == {session_id:"session-a",capture_id:"00000000000000000000000000000001"}
    and .unscoped_review_queue == [] and [.findings[].packet_evidence_status] == ["complete"]' >/dev/null
[[ $(cat "$dir/checks") == 1 ]]
: > "$dir/checks"
if run_review --review-scope session-b 00000000000000000000000000000001 >/dev/null 2>&1; then exit 1; fi
[[ ! -s $dir/checks ]]
if TEST_MODE=extra run_review >"$dir/output" 2>/dev/null; then exit 1; fi
[[ ! -s $dir/output && ! -s $dir/checks ]]
PACKRAT_BACKLOG_TIMEOUT=2 TEST_MODE=timed run_review | jq -e '
    [.findings[].packet_evidence_status] ==
        ["check_timed_out","check_deferred","check_deferred","check_deferred","check_deferred"]' >/dev/null
[[ $(wc -l < "$dir/checks") == 1 ]]
printf '%s\n' 'saved alert backlog evidence tests passed'
