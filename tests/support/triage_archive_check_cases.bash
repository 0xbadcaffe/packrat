#!/usr/bin/env bash
# shellcheck shell=bash
export PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=42
(
    export PACKRAT_TRIAGE_ARCHIVE="$scratch/archive space"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.status == "current" and .evidence_status == {status:"checked",alert_id:42,in_recent_alerts:true,
        frames:[{frame_number:1,status:"truncated"},{frame_number:2,status:"missing"}]}
        and .alerts[0].packet_evidence_status == "partial"
        and .alerts[0].evidence_availability == {truncated:1,missing:1}' <<< "$result" >/dev/null
    for frame_level in complete partial unavailable; do
        case $frame_level in
            complete) frames='["complete","complete"]' ;;
            partial) frames='["length_unknown","unreadable"]' ;;
            unavailable) frames='["missing","unreadable"]' ;;
        esac
        result=$(PACKRAT_TEST_FRAME_STATUSES="$frames" bash "$triage" "$health" "$PACKRAT_TEST_LOG")
        jq -e --arg level "$frame_level" --argjson frames "$frames" '
            ($frames | group_by(.) | map({key:.[0],value:length}) | from_entries) as $counts
            | .alerts[0] | .packet_evidence_status == $level and .evidence_availability == $counts
                and (.next_evidence_step == "check_archive_integrity") == ($counts.unreadable != null)
        ' <<< "$result" >/dev/null
    done
    result=$(bash "$triage" --saved 1700000000-432 00000000000000000000000000000001 "$PACKRAT_TEST_LOG")
    jq -e '.status == "saved" and .health == null and .evidence_status.status == "checked"
        and [.evidence_status.frames[].status] == ["truncated","missing"]' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_EVIDENCE_DRIFT=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 2 ]]
    jq -e '.status == "current" and .alerts[0].alert_id == 42
        and .alerts[0].packet_evidence_status == "changed_during_review" and .alerts[0].next_evidence_step == "retry_evidence_check"
        and .alerts[0].evidence_availability == null
        and .evidence_status == {status:"alert_evidence_changed",alert_id:42,frames:null}' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_ALERT_COUNT=0 bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 2 ]]
    jq -e '.alerts == [] and .evidence_status.status == "alert_evidence_changed"' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_SCAN_STOPPED=true PACKRAT_TEST_ALERT_COUNT=0 PACKRAT_TEST_EVIDENCE_RESTART=1 \
        bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 1 ]]
    jq -e '.status == "degraded" and .alerts == [] and .alert_log_integrity.stopped_at_scan_budget
        and .evidence_status == {status:"outside_history_scan",alert_id:42,frames:null}' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_SCAN_STOPPED=true bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 1 ]]
    jq -e '.status == "degraded" and .evidence_status.status == "checked"
        and .alerts[0].packet_evidence_status == "partial"' <<< "$result" >/dev/null
    result=$(PACKRAT_TEST_ALERT_COUNT=512 PACKRAT_TEST_ALERT_OFFSET=50 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.has_more_alerts and .evidence_status.status == "checked"
        and .evidence_status.in_recent_alerts == false' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_EVIDENCE_SCOPE=other bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 2 ]]
    jq -e '.status == "current" and .alerts[0].alert_id == 42
        and .alerts[0].packet_evidence_status == "check_failed"
        and .evidence_status == {status:"unavailable",alert_id:42,frames:null}' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_EVIDENCE_RESTART=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 1 ]]
    jq -e '.status == "capture_scope_changed" and .alerts == null and .evidence_status == null' \
        <<< "$result" >/dev/null
)
