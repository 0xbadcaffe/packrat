# shellcheck shell=bash
list_saved() {
    PACKRAT_TEST_INDEX=1 bash "$triage" --list-saved "$@"
}
result=$(list_saved "$PACKRAT_TEST_LOG")
jq -e '.record_type == "saved_capture_index" and .status == "saved"
    and .review_latency == null
    and .sampled_alerts == 6 and .sampled_unscoped_alerts == 2
    and .sampled_unscoped_open_high_or_critical == 1
    and .alert_sample_limit == 512 and .alert_log_integrity.stopped_at_limit == false
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
timing='{"sampled_alerts":6,"measured_alerts":2,"unmeasured_alerts":4,"min_ms":300,"median_ms":400,"max_ms":500}'
result=$(PACKRAT_TEST_REVIEW_LATENCY=$(jq -c '. + {extra:"not in index"}' <<<"$timing") list_saved "$PACKRAT_TEST_LOG")
jq -e --argjson expected "$timing" '.review_latency == $expected' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=512 list_saved "$PACKRAT_TEST_LOG")
jq -e '.status == "saved" and .sampled_alerts == 512 and .alert_log_integrity.stopped_at_limit
    and .captures[0].last_seen == null' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=7 PACKRAT_TEST_OPEN_PRIORITY=1 list_saved "$PACKRAT_TEST_LOG")
jq -e '.review_shortlist_truncated and [.review_shortlist[].alert_id]==[7,6,5,4,3]' <<<"$result" >/dev/null
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
    and .sampled_alerts==6 and (.captures | length)==2' <<< "$result" >/dev/null
