# shellcheck shell=bash
list_saved() {
    PACKRAT_TEST_INDEX=1 bash "$triage" --list-saved "$@"
}
result=$(list_saved "$PACKRAT_TEST_LOG")
jq -e '.record_type == "saved_capture_index" and .status == "saved"
    and .review_rule == null
    and .review_scope == null
    and .review_latency == null
    and .sampled_alerts == 6 and .sampled_unscoped_alerts == 2
    and .sampled_unscoped_open_high_or_critical == 1
    and .unscoped_review_queue == [{
        session_id:"1700000000-432",alert_id:1,severity:"HIGH",disposition:"New",last_seen:20,
        legacy_rule_hint:"dns.competing_responders",evidence_frame_count:1,next_evidence_step:"locate_original_capture_or_host_logs"}]
    and .alert_sample_limit == 512 and .alert_log_integrity.stopped_at_limit == false
    and .sample_scan_complete and .alert_log_advanced_during_review==false
    and .review_eligible_in_sample == 3 and .review_offset == 0 and .next_review_offset == null
    and (.captures | map(.session_id)) == ["1700000000-123","1700000000-432"]
    and (.captures | map(.sampled_alerts)) == [1,3]
    and (.captures | map(.sampled_high_or_critical)) == [1,3]
    and (.captures | map(.sampled_open_high_or_critical)) == [1,2]
    and (.captures | map(.next_review_alert_id)) == [1,3]
    and .review_shortlist_truncated==false
    and all(.review_shortlist[]; .rule_id == "test.rule" and .revision == 10
        and .evidence_frame_set_sha256 == ("0"*64))
    and [.review_shortlist[] | [.session_id,.alert_id,.severity]] ==
        [["1700000000-123",1,"CRITICAL"],["1700000000-432",3,"CRITICAL"],["1700000000-432",1,"HIGH"]]
    and .captures[1].first_seen == 10 and .captures[1].last_seen == 22
    and (tostring | contains("not in index") | not)' <<< "$result" >/dev/null
PACKRAT_TEST_LOG_RACE=append list_saved "$PACKRAT_TEST_LOG" |
    jq -e '.status=="saved" and .sampled_alerts==6 and .alert_log_advanced_during_review==true
        and .sample_scan_complete==false' >/dev/null
status=0
result=$(PACKRAT_TEST_LOG_RACE=rewrite list_saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status=="alert_log_changed" and .alerts==null and .alert_log_advanced_during_review==null' <<<"$result" >/dev/null
result=$(PACKRAT_TEST_INDEX_EXTRA='[{"alert_id":4,"capture_id":null,"evidence_frame_count":0,"severity":"CRITICAL"}]' list_saved "$PACKRAT_TEST_LOG")
jq -e '.unscoped_review_queue[0] | .evidence_frame_count==0
    and .next_evidence_step=="corroborate_with_host_or_service_logs"' <<< "$result" >/dev/null
timing='{"sampled_alerts":6,"measured_alerts":2,"unmeasured_alerts":4,"min_ms":300,"median_ms":400,"max_ms":500}'
result=$(PACKRAT_TEST_REVIEW_LATENCY=$(jq -c '. + {extra:"not in index"}' <<<"$timing") list_saved "$PACKRAT_TEST_LOG")
jq -e --argjson expected "$timing" '.review_latency == $expected' <<< "$result" >/dev/null
breakdown='{"missing_capture_scope":1,"missing_first_save":1,"missing_first_review":2,"review_before_save":0}'
with_breakdown=$(jq -c --argjson reasons "$breakdown" '.unmeasured_reasons=$reasons' <<<"$timing")
result=$(PACKRAT_TEST_REVIEW_LATENCY=$(jq -c '.unmeasured_reasons.extra="private"' <<<"$with_breakdown") list_saved "$PACKRAT_TEST_LOG")
jq -e --argjson expected "$with_breakdown" '.review_latency == $expected' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_REVIEW_LATENCY=$(jq -c '.unmeasured_reasons.review_before_save=1' <<<"$with_breakdown") list_saved "$PACKRAT_TEST_LOG")
jq -e --argjson expected "$timing" '.review_latency == $expected' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=512 list_saved "$PACKRAT_TEST_LOG")
jq -e '.status == "saved" and .sampled_alerts == 512 and .alert_log_integrity.stopped_at_limit and (.sample_scan_complete | not)
    and .captures[0].last_seen == null' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=7 PACKRAT_TEST_OPEN_PRIORITY=1 list_saved "$PACKRAT_TEST_LOG")
jq -e '.review_shortlist_truncated and .next_review_offset == 5 and .review_eligible_in_sample == 7
    and [.review_shortlist[].alert_id]==[7,6,5,4,3]' <<<"$result" >/dev/null
PACKRAT_TEST_ALERT_COUNT=7 PACKRAT_TEST_OPEN_PRIORITY=1 list_saved --review-offset 5 "$PACKRAT_TEST_LOG" |
    jq -e '.review_offset == 5 and .next_review_offset == null and (.review_shortlist_truncated | not)
        and .unscoped_review_queue == [] and [.review_shortlist[].alert_id] == [2,1]' >/dev/null
PACKRAT_TEST_ALERT_COUNT=7 PACKRAT_TEST_OPEN_PRIORITY=1 list_saved --review-offset 10 "$PACKRAT_TEST_LOG" |
    jq -e '.review_offset == 10 and .review_eligible_in_sample == 7 and .review_shortlist == []' >/dev/null
extra='[{"alert_id":4,"severity":"MEDIUM","last_seen":25}, {"alert_id":5,"severity":"LOW","last_seen":26},
        {"alert_id":6,"severity":"MEDIUM","rule_id":"other.rule"}, {"alert_id":7,"severity":"MEDIUM","capture_id":null},
        {"alert_id":8,"severity":"MEDIUM","disposition":"Benign"}]'
PACKRAT_TEST_INDEX_EXTRA="$extra" list_saved --review-rule test.rule "$PACKRAT_TEST_LOG" | jq -e '
    .review_rule == "test.rule" and .review_eligible_in_sample == 5
    and [.review_shortlist[] | [.alert_id,.severity]] == [[1,"CRITICAL"],[3,"CRITICAL"],[1,"HIGH"],[4,"MEDIUM"],[5,"LOW"]]
    and .sampled_unscoped_open_high_or_critical == 1' >/dev/null
PACKRAT_TEST_INDEX_EXTRA="$extra" list_saved --review-rule other.rule --review-offset 1 "$PACKRAT_TEST_LOG" | jq -e '
    .review_rule == "other.rule" and .review_eligible_in_sample == 1 and .review_shortlist == []' >/dev/null
if list_saved --review-rule 'bad rule' "$PACKRAT_TEST_LOG" >/dev/null 2>&1; then exit 1; fi
info='[{"alert_id":4,"severity":"INFO","rule_id":"vlan.vid_one_observed"}]'
PACKRAT_TEST_INDEX_EXTRA="$info" list_saved --review-rule vlan.vid_one_observed "$PACKRAT_TEST_LOG" | jq -e '
    .review_eligible_in_sample == 1 and [.review_shortlist[] | [.alert_id,.severity]] == [[4,"INFO"]]' >/dev/null
PACKRAT_TEST_INDEX_EXTRA="$info" list_saved "$PACKRAT_TEST_LOG" | jq -e '
    .review_eligible_in_sample == 3 and all(.review_shortlist[]; .severity != "INFO")' >/dev/null
requested=' --session 1700000000-432 --capture-id 00000000000000000000000000000001'
PACKRAT_TEST_INDEX_SCOPE="$requested" PACKRAT_TEST_INDEX_EXTRA="$extra" list_saved \
    --review-scope 1700000000-432 00000000000000000000000000000001 --review-rule test.rule "$PACKRAT_TEST_LOG" | jq -e '
    .review_scope == {session_id:"1700000000-432",capture_id:"00000000000000000000000000000001"}
    and .sampled_alerts == 7 and .sampled_unscoped_alerts == 0 and .unscoped_review_queue == []
    and [.review_shortlist[].alert_id] == [3,1,4,5]' >/dev/null
status=0
result=$(PACKRAT_TEST_INDEX_SCOPE="$requested" PACKRAT_TEST_INDEX_SCOPE_MISMATCH=1 list_saved \
    --review-scope 1700000000-432 00000000000000000000000000000001 "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 2 ]]
jq -e '.status == "alert_log_scope_mismatch"' <<< "$result" >/dev/null
for offset in 512 005 -1 bad; do
    status=0
    list_saved --review-offset "$offset" "$PACKRAT_TEST_LOG" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
status=0
result=$(PACKRAT_TEST_INVALID_RECORDS=1 PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $previous" \
    list_saved "$PACKRAT_TEST_LOG" "$previous") || status=$?
[[ $status == 1 ]]
jq -e '.status == "saved_log_degraded" and .previous_logs == 1 and (.captures | length) == 2' \
    <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_SCAN_STOPPED=true list_saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status=="saved_log_degraded" and .alert_log_integrity.stopped_at_scan_budget
    and (.sample_scan_complete | not) and .sampled_alerts==6 and (.captures | length)==2' <<< "$result" >/dev/null
for query in exact_found exact_missing scope_missing; do
    status=0
    case $query in
        exact_found) result=$(PACKRAT_TEST_LOG_RACE=append saved_alert 42 "$PACKRAT_TEST_LOG") || status=$? ;;
        exact_missing) result=$(PACKRAT_TEST_LOG_RACE=append PACKRAT_TEST_ALERT_COUNT=0 saved_alert 99 "$PACKRAT_TEST_LOG") || status=$? ;;
        scope_missing) result=$(PACKRAT_TEST_LOG_RACE=append PACKRAT_TEST_ALERT_COUNT=0 saved "$PACKRAT_TEST_LOG") || status=$? ;;
    esac
    [[ $status == 1 ]]
    jq -e '.status == "alert_log_changed" and .alert_log_advanced_during_review == true
        and .alerts == null and .evidence_status == null' <<< "$result" >/dev/null
done
