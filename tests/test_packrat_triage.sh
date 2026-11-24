#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
triage="$root/scripts/packrat-triage.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
health="$scratch/latest.json"
export PACKRAT_TEST_LOG="$scratch/alerts.jsonl" PACKRAT_TEST_CALL="$scratch/archive-called"
export PACKRAT_TEST_STATE="$health"
touch -- "$PACKRAT_TEST_LOG" "$scratch/other.jsonl"
unset PACKRAT_TRIAGE_MAX_AGE PACKRAT_TRIAGE_READ_TIMEOUT PACKRAT_TRIAGE_ARCHIVE PACKRAT_TRIAGE_EVIDENCE_ALERT_ID
unset PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE PACKRAT_TRIAGE_AUTO_EVIDENCE PACKRAT_TRIAGE_PROJECT
date() {
    [[ $* == '-u +%s' ]] || return 2
    printf '%s\n' 1700000000
}
mock_archive() {
    printf '%s\n' called >"$PACKRAT_TEST_CALL"
    if [[ ${2-} == --alert-status || ${1-} == --project-alert-status ]]; then
        local id=42
        if [[ $1 == --project-alert-status ]]; then
            [[ $2 == "$PACKRAT_TRIAGE_PROJECT" && $3 == "$PACKRAT_TEST_LOG" &&
               $4 == 1700000000-432 && $5 == 00000000000000000000000000000001 && $6 == 42 ]] || return 2
        else
            case ${PACKRAT_TEST_AUTO_QUEUE:-} in yes|many|vlan) id=$5 ;; esac
            [[ $* == "$PACKRAT_TRIAGE_ARCHIVE --alert-status $PACKRAT_TEST_LOG 1700000000-432 $id --capture-id 00000000000000000000000000000001${PACKRAT_TEST_PREVIOUS_ARGS:-}" ]] || return 2
        fi
        [[ $id != "${PACKRAT_TEST_EVIDENCE_FAIL_ID:-}" ]] || return 2
        if [[ ${PACKRAT_TEST_EVIDENCE_RESTART:-0} == 1 ]]; then
            jq -c '.capture_id = "00000000000000000000000000000002"' "$PACKRAT_TEST_STATE" >"$PACKRAT_TEST_STATE.next"
            mv -- "$PACKRAT_TEST_STATE.next" "$PACKRAT_TEST_STATE"
        fi
        jq -cn --arg capture "${PACKRAT_TEST_EVIDENCE_SCOPE:-00000000000000000000000000000001}" \
            --arg drift "${PACKRAT_TEST_EVIDENCE_DRIFT:-0}" --argjson id "$id" \
            --argjson statuses "${PACKRAT_TEST_FRAME_STATUSES:-[\"truncated\",\"missing\"]}" '
            {session_id:"1700000000-432",capture_id:$capture,alert_id:$id,
             evidence_frame_set_sha256:($drift * 64),
             frames:($statuses | to_entries | map({frame_number:(.key + 1),status:.value,bytes:[0,1]}))}'
        return
    fi
    local scope=' --session 1700000000-432 --capture-id 00000000000000000000000000000001' selector='--limit 512'
    if [[ ${PACKRAT_TEST_INDEX:-0} == 1 ]]; then scope=${PACKRAT_TEST_INDEX_SCOPE:-}; fi
    if [[ -n ${PACKRAT_TEST_TARGET:-} ]]; then selector="--alert-id $PACKRAT_TEST_TARGET"; fi
    if [[ ${PACKRAT_TEST_INDEX:-0} == 1 && $* != *" --scan-bytes 8388608 --report-integrity"* ]]; then return 2; fi
    if [[ $* == *" --scan-bytes 8388608 --report-integrity"* ]]; then selector+=' --scan-bytes 8388608'; elif [[ ${PACKRAT_TEST_SCAN_STOPPED:-false} == true ]]; then return 2; fi
    [[ $* == "--alerts $PACKRAT_TEST_LOG$scope $selector --report-integrity${PACKRAT_TEST_PREVIOUS_ARGS:-}" ]] || return 2
    if [[ ${PACKRAT_TEST_LOG_ERROR:-0} == 1 ]]; then return 1; fi
    if [[ ${PACKRAT_TEST_SCOPE_RACE:-0} == 1 ]]; then
        jq -c '.capture_id = "00000000000000000000000000000002"' "$PACKRAT_TEST_STATE" >"$PACKRAT_TEST_STATE.next"
        mv -- "$PACKRAT_TEST_STATE.next" "$PACKRAT_TEST_STATE"
    fi
    if [[ ${PACKRAT_TEST_RUN_RACE:-0} == 1 ]]; then
        jq -c '.capture_run_id = "0000000000000002"' "$PACKRAT_TEST_STATE" >"$PACKRAT_TEST_STATE.next"
        mv -- "$PACKRAT_TEST_STATE.next" "$PACKRAT_TEST_STATE"
    fi
    if [[ -n ${PACKRAT_TEST_WATCH_ID_RACE:-} ]]; then
        jq -c --arg race "$PACKRAT_TEST_WATCH_ID_RACE" '
            .alert_log_identity = null
            | if $race == "downgrade" then .alert_watcher_open_log_required = false else . end
        ' "$PACKRAT_TEST_STATE" >"$PACKRAT_TEST_STATE.next"
        mv -- "$PACKRAT_TEST_STATE.next" "$PACKRAT_TEST_STATE"
    fi
    case ${PACKRAT_TEST_LOG_RACE:-} in
        append) printf '%s\n' snapshot >>"$PACKRAT_TEST_LOG" ;;
        rewrite)
            [[ -s $PACKRAT_TEST_LOG ]]
            printf X | dd of="$PACKRAT_TEST_LOG" bs=1 count=1 conv=notrunc status=none
            touch -m -d '2000-01-01 UTC' -- "$PACKRAT_TEST_LOG"
            ;;
        truncate) : >"$PACKRAT_TEST_LOG" ;;
        rotate) mv -- "$PACKRAT_TEST_LOG" "$PACKRAT_TEST_LOG.rotated"; touch -- "$PACKRAT_TEST_LOG" ;;
    esac
    case ${PACKRAT_TEST_PREVIOUS_RACE:-} in
        append) printf '%s\n' snapshot >>"$PACKRAT_TEST_PREVIOUS_LOG" ;;
        rotate)
            mv -- "$PACKRAT_TEST_PREVIOUS_LOG" "$PACKRAT_TEST_PREVIOUS_LOG.rotated"
            cp -p -- "$PACKRAT_TEST_PREVIOUS_LOG.rotated" "$PACKRAT_TEST_PREVIOUS_LOG"
            ;;
    esac
    if [[ -n ${PACKRAT_TEST_ALERT_COUNT:-} ]]; then
        jq -cn --argjson count "$PACKRAT_TEST_ALERT_COUNT" --arg large "${PACKRAT_TEST_LARGE_ALERTS:-0}" \
            --argjson offset "${PACKRAT_TEST_ALERT_OFFSET:-0}" --arg priority "${PACKRAT_TEST_OPEN_PRIORITY:-0}" '
            [range($count; 0; -1) | {alert_id:(. + $offset),session_id:"1700000000-432",capture_id:"00000000000000000000000000000001"}
                + (if $priority == "1" then {severity:"HIGH",disposition:"New"} else {} end)
                + (if $large == "1" then {detail: ("\ud83d\udd0d" * 512), title: ("\ud83d\udd0d" * 160)}
                   else {} end)]'
    elif [[ ${PACKRAT_TEST_INDEX:-0} == 1 ]]; then
        jq -cn --argjson extra "${PACKRAT_TEST_INDEX_EXTRA:-[]}" --arg scoped "${PACKRAT_TEST_INDEX_SCOPE:-}" --arg mismatch "${PACKRAT_TEST_INDEX_SCOPE_MISMATCH:-0}" '
            {session_id:"1700000000-432",capture_id:"00000000000000000000000000000001",
             alert_id:1,first_seen:10,last_seen:20,severity:"HIGH",disposition:"New",detail:"not in index",
             rule_id:"test.rule",revision:10,evidence_frame_set_sha256:("0"*64)} as $base
            | [$base, ($base + {alert_id:2,first_seen:12,last_seen:22,severity:"HIGH",disposition:"Benign"}),
               ($base + {alert_id:3,first_seen:13,last_seen:19,severity:"CRITICAL",disposition:"Reviewing"}),
               ($base + {session_id:"1700000000-123",last_seen:30,severity:"CRITICAL",disposition:"Confirmed"}),
               ($base + {capture_id:null,rule_id:null,revision:null,legacy_rule_hint:"dns.competing_responders",evidence_frame_count:1}),
               ($base + {capture_id:"legacy",disposition:"Benign"})] + ($extra | map($base + .)) |
            if $scoped == "" or $mismatch == "1" then . else map(select(.session_id == $base.session_id and .capture_id == $base.capture_id)) end
        '
    else
        jq -cn --arg mismatch "${PACKRAT_TEST_WRONG_ALERT_SCOPE:-}" --arg queue "${PACKRAT_TEST_AUTO_QUEUE:-}" \
            --argjson refs "${PACKRAT_TEST_FRAME_COUNT:-2}" --argjson first "${PACKRAT_TEST_FIRST_SEEN:-1700000000}" '
            {alert_id:42,title:"Scoped alert",session_id:"1700000000-432",capture_id:"00000000000000000000000000000001",
             evidence_frame_count:$refs,evidence_frame_set_sha256:("0"*64),
             first_seen:$first,last_seen:1700000000,
             flow:{transport:"tcp",source:"192.0.2.1:4321",destination:"192.0.2.2:443"}} as $valid
            | if $queue == "yes" then [
                  ({Benign:46,Contained:47,Closed:48} | to_entries[] | $valid + {alert_id:.value,severity:"CRITICAL",disposition:.key}),
                  ($valid + {alert_id:45,severity:"CRITICAL",disposition:"New",evidence_frame_count:0}),
                  ($valid + {alert_id:44,severity:"HIGH",disposition:"New"}),
                  ($valid + {severity:"CRITICAL",disposition:"Confirmed",rule_id:"test.rule",revision:10}),
                  ($valid + {alert_id:41,severity:"CRITICAL",disposition:"New"})
              ] elif $queue == "socket" then [$valid + {severity:"HIGH",disposition:"New"}]
                elif $queue == "many" then [range(60;53;-1) | $valid + {alert_id:.,severity:"HIGH",disposition:"New"}]
                elif $queue == "vlan" then [
                  ($valid + {alert_id:44,severity:"INFO",disposition:"New",rule_id:"vlan.tag_stack_observed"}),
                  ($valid + {alert_id:43,severity:"INFO",disposition:"New",rule_id:"vlan.vid_one_observed"}),
                  ($valid + {severity:"WARN",disposition:"New",rule_id:"vlan.mac_crossing"}),
                  ($valid + {alert_id:41,severity:"CRIT",disposition:"Reviewing",rule_id:"test.critical"})
                ]
                elif $queue == "configured" then [
                  ($valid + {alert_id:43,severity:"MEDIUM",disposition:"New",rule_id:"traffic.periodic_fixed_size"}),
                  ($valid + {severity:"MEDIUM",disposition:"Reviewing",rule_id:"tcp.payload_after_observed_reset"})
              ] elif $queue == "backlog" then
                [range(101;43;-1) | $valid + {alert_id:.,severity:"LOW",disposition:"New"}]
                + [($valid + {severity:"HIGH",disposition:"New"})]
              else [$valid] + (if $mismatch == "" then [] else
                [($valid | .alert_id = 43 | .[$mismatch] = "other")]
              end) end'
    fi
}
packrat-archive() {
    if [[ ${1-} != --alerts ]]; then mock_archive "$@"; return; fi
    mock_archive "$@" | jq -c --argjson invalid "${PACKRAT_TEST_INVALID_RECORDS:-0}" \
        --argjson oversized "${PACKRAT_TEST_OVERSIZED_RECORDS:-0}" \
        --arg target "${PACKRAT_TEST_TARGET:-}" --argjson stopped "${PACKRAT_TEST_SCAN_STOPPED:-false}" \
        --argjson timing "${PACKRAT_TEST_REVIEW_LATENCY:-null}" '
        {alerts:.,integrity:{invalid_records:$invalid,oversized_records:$oversized,
            stopped_at_limit:(length == (if $target != "" then 1 else 512 end)),stopped_at_scan_budget:$stopped},review_latency:$timing}'
}

timeout() {
    [[ $# -gt 3 && $1 == --kill-after=2s && $2 =~ ^[1-9][0-9]*s$ ]] || return 2
    (( ${2%s} <= ${PACKRAT_TEST_TIMEOUT_SECONDS:-10} )) || return 2
    shift 2
    if [[ ${3-} == --alert-status && ${6-} == "${PACKRAT_TEST_EVIDENCE_TIMEOUT_ID:-never}" ]]; then
        sleep 2.2
        return 124
    fi
    if [[ -n ${PACKRAT_TEST_TIMEOUT_STATUS:-} ]]; then
        printf '%s\n' '[{"alert_id":999}]'
        return "$PACKRAT_TEST_TIMEOUT_STATUS"
    fi
    "$@"
}

export -f date mock_archive packrat-archive timeout
sample='{"record_type":"capture_health","timestamp":"2023-11-14T22:12:50Z",
         "capture_active":true,"telemetry_fresh":true,"issues":[],
         "capture_id":"00000000000000000000000000000001","alert_session_id":"1700000000-432"}'
sample=$(jq -c --arg log "$PACKRAT_TEST_LOG" '.alert_watcher_log = $log' <<< "$sample")
printf '%s\n' "$sample" >"$health"
result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.status == "current" and .age_seconds == 30 and .max_age_seconds == 360
    and .alerts[0].alert_id == 42 and .alerts[0].packet_evidence_status == "not_checked"
    and .live_packet_archive == "unknown" and .has_more_alerts == false and .evidence_status == null' <<< "$result" >/dev/null
[[ -f $PACKRAT_TEST_CALL ]]
for archive_status in enabled paused disabled; do
    jq -c --arg status "$archive_status" '. + {
        archive_enabled:($status != "disabled"),archive_paused:($status == "paused")
    }' <<< "$sample" >"$health"
    result=$(PACKRAT_TEST_FRAME_COUNT=0 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e --arg status "$archive_status" '.status == "current" and .live_packet_archive == $status
        and .alerts[0].packet_evidence_status == "no_references"' <<< "$result" >/dev/null
done
printf '%s\n' "$sample" >"$health"
# shellcheck source=tests/support/packrat_triage_socket_context.bash
source "$root/tests/support/packrat_triage_socket_context.bash"
status=0
result=$(PACKRAT_TEST_ALERT_COUNT=0 PACKRAT_TEST_INVALID_RECORDS=2 PACKRAT_TEST_OVERSIZED_RECORDS=1 \
    bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "degraded" and .alerts == []
    and .alert_log_integrity == {invalid_records:2,oversized_records:1,stopped_at_limit:false}' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_SCAN_STOPPED=true bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "degraded" and .alerts[0].alert_id == 42 and .alert_log_integrity.stopped_at_scan_budget' <<< "$result" >/dev/null
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
printf '%s\n' "$sample" >"$health"
(
    export PACKRAT_TRIAGE_PROJECT="$scratch/case with spaces.json"
    result=$(bash "$triage" --saved 1700000000-432 00000000000000000000000000000001 "$PACKRAT_TEST_LOG")
    jq -e '.status == "saved" and .evidence_status.status == "checked"
        and [.evidence_status.frames[].status] == ["truncated","missing"]
        and (.evidence_status.frames[0] | has("bytes") | not)' <<< "$result" >/dev/null
    status=0
    PACKRAT_TRIAGE_ARCHIVE="$scratch/archive" bash "$triage" "$health" "$PACKRAT_TEST_LOG" 2>/dev/null || status=$?
    [[ $status == 2 ]]
)
unset PACKRAT_TRIAGE_EVIDENCE_ALERT_ID
(
    run_auto() {
        PACKRAT_TRIAGE_AUTO_EVIDENCE=1 PACKRAT_TRIAGE_ARCHIVE="$scratch/archive space" \
            bash "$triage" "$health" "$PACKRAT_TEST_LOG"
    }
    jq -c '.archive_enabled = true | .archive_paused = false' <<< "$sample" >"$health"
    result=$(PACKRAT_TEST_AUTO_QUEUE=yes run_auto)
    jq -e '.evidence_selection == "automatic" and .evidence_status.alert_id == 42
        and [.evidence_checks[].alert_id] == [42,41,44]
        and [.alerts[].packet_evidence_status] == ["not_checked","not_checked","not_checked","no_references","partial","partial","partial"]
        and .open_priority_alerts_in_sample == 4 and [.review_queue[].alert_id] == [45,42,41,44] and .review_queue[1].disposition=="Confirmed"
        and .review_queue[1].rule_id=="test.rule" and .review_queue[1].revision==10 and .review_queue[0].revision==null
        and .review_queue[1].evidence_frame_count==2 and .review_queue[1].evidence_frame_set_sha256==("0"*64)
        and [.review_queue[].next_evidence_step] == ["corroborate_with_host_or_service_logs",
            "inspect_retained_and_recover_missing_frames","inspect_retained_and_recover_missing_frames","inspect_retained_and_recover_missing_frames"]' \
        <<< "$result" >/dev/null
    PACKRAT_TEST_AUTO_QUEUE=many run_auto | jq -e '[.evidence_checks[].alert_id] == [60,59,58,57,56]
        and [.alerts[] | select(.packet_evidence_status=="not_checked") | .alert_id] == [55,54]' >/dev/null
    status=0; result=$(PACKRAT_TEST_AUTO_QUEUE=yes PACKRAT_TEST_EVIDENCE_FAIL_ID=41 run_auto) || status=$?
    jq -e --arg status "$status" '$status=="2" and [.evidence_checks[]|[.alert_id,.status]] == [[42,"checked"],[41,"unavailable"],[44,"checked"]]' <<< "$result" >/dev/null
    status=0; result=$(PACKRAT_TEST_AUTO_QUEUE=yes PACKRAT_TEST_EVIDENCE_TIMEOUT_ID=42 PACKRAT_TRIAGE_READ_TIMEOUT=2 run_auto) || status=$?
    [[ $status == 2 ]]
    jq -e '[.evidence_checks[] | [.alert_id,.status]] == [[42,"timed_out"],[41,"deferred"],[44,"deferred"]]
        and [.review_queue[] | select(.alert_id!=45) | [.packet_evidence_status,.next_evidence_step]] ==
        [["check_timed_out","retry_evidence_check"],["check_deferred","retry_evidence_check"],["check_deferred","retry_evidence_check"]]' \
        <<< "$result" >/dev/null
    result=$(PACKRAT_TEST_ALERT_COUNT=0 run_auto)
    jq -e '.evidence_selection == "automatic" and .evidence_status == null and .alerts == []
        and .open_priority_alerts_in_sample == 0 and .review_queue == []' <<< "$result" >/dev/null
    PACKRAT_TEST_AUTO_QUEUE=configured run_auto | jq -e '.evidence_status == null' >/dev/null
    jq -c '. + {archive_enabled:true,archive_paused:false,archive_alert_evidence_only:true,
        archive_evidence_rules:["tcp.payload_after_observed_reset"]}' <<< "$sample" >"$health"
    PACKRAT_TEST_AUTO_QUEUE=configured run_auto | jq -e '.evidence_status.alert_id==42
        and .alerts[1].packet_evidence_status=="partial" and .open_priority_alerts_in_sample==0
        and .open_archive_rule_alerts_in_sample==1 and .review_queue_truncated==false
        and (.review_queue | map({alert_id,severity,archive_rule,packet_evidence_status}))==
            [{alert_id:42,severity:"MEDIUM",archive_rule:true,packet_evidence_status:"partial"}]' >/dev/null
    jq -c '.archive_evidence_rules=["vlan.mac_crossing","vlan.vid_one_observed"]' "$health" >"$scratch/vlan-health.json"
    mv -- "$scratch/vlan-health.json" "$health"
    PACKRAT_TEST_AUTO_QUEUE=vlan run_auto | jq -e '
        [.alerts[].severity]==["INFO","INFO","MEDIUM","CRITICAL"]
        and .open_priority_alerts_in_sample==1 and .open_archive_rule_alerts_in_sample==2
        and [.review_queue[]|[.alert_id,.severity,.archive_rule]]==[[41,"CRITICAL",false],[42,"MEDIUM",true],[43,"INFO",true]]
        and [.evidence_checks[]|[.alert_id,.status]]==[[41,"checked"],[42,"checked"],[43,"checked"]]
        and .alerts[0].packet_evidence_status=="not_selected_by_current_policy"
        and .alerts[0].next_evidence_step=="locate_original_capture_or_corroborate_with_host_logs"
        and .alerts[0].evidence_availability==null
        and .alerts[1].packet_evidence_status=="partial"
    ' >/dev/null
    result=$(PACKRAT_TEST_AUTO_QUEUE=backlog run_auto)
    jq -e '.has_more_alerts and .priority_sample_limit == 512 and .priority_sample_at_limit == false
        and (.alerts | length) == 50 and all(.alerts[]; .alert_id != 42)
        and .open_priority_alerts_in_sample == 1 and .review_queue[0].alert_id == 42
        and .review_queue[0].in_recent_alerts == false and .review_queue[0].packet_evidence_status == "partial"
        and .review_queue[0].disposition == "New"
        and .evidence_status.status == "checked" and .evidence_status.in_recent_alerts == false' <<< "$result" >/dev/null
    jq -c '.archive_enabled = true | .archive_paused = null' <<< "$sample" >"$health"
    result=$(PACKRAT_TEST_AUTO_QUEUE=yes run_auto)
    jq -e '.live_packet_archive == "unknown" and .evidence_status == null' <<< "$result" >/dev/null
    printf '%s\n' "$sample" >"$health"
    result=$(PACKRAT_TEST_AUTO_QUEUE=yes run_auto)
    jq -e '.evidence_selection == "automatic" and .evidence_status == null' <<< "$result" >/dev/null
    status=0
    PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=42 run_auto >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
)
for count in 0 50 51; do
    result=$(PACKRAT_TEST_ALERT_COUNT=$count bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e --argjson count "$count" '
        .status == "current" and .alert_limit == 50 and .has_more_alerts == ($count > 50)
        and ([.alerts[].alert_id] == [range($count; ([$count - 50, 0] | max); -1)])
    ' <<< "$result" >/dev/null
done
result=$(PACKRAT_TEST_ALERT_COUNT=51 PACKRAT_TEST_LARGE_ALERTS=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.has_more_alerts and (.alerts | length) == 50 and all(.alerts[]; (.detail | length) == 512)' \
    <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=51 PACKRAT_TEST_OPEN_PRIORITY=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.has_more_alerts and .open_priority_alerts_in_sample == 51
    and .open_archive_rule_alerts_in_sample == 0 and .review_queue_truncated
    and [.review_queue[].alert_id] == [51,50,49,48,47]' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=5 PACKRAT_TEST_OPEN_PRIORITY=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.review_queue_truncated == false and (.review_queue|length) == 5' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=512 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.has_more_alerts and .priority_sample_at_limit and .open_priority_alerts_in_sample == 0' \
    <<< "$result" >/dev/null

previous="$scratch/older log.jsonl"
touch -- "$previous"
result=$(PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $previous" bash "$triage" "$health" "$PACKRAT_TEST_LOG" "$previous")
jq -e '.status == "current" and .previous_logs == 1 and .alerts[0].alert_id == 42' <<< "$result" >/dev/null
earliest="$scratch/earliest log.jsonl"
touch -- "$earliest"
for change in append rotate; do
    status=0
    result=$(PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $earliest --previous-log $previous" \
        PACKRAT_TEST_PREVIOUS_RACE="$change" PACKRAT_TEST_PREVIOUS_LOG="$previous" \
        bash "$triage" "$health" "$PACKRAT_TEST_LOG" "$earliest" "$previous") || status=$?
    [[ $status == 1 ]]
    jq -e '.status == "previous_log_changed" and .previous_logs == 2 and .alerts == null' \
        <<< "$result" >/dev/null
done

check_failure() {
    local expected_rc=$1 expected_status=$2 actual=0 output
    output=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG") || actual=$?
    [[ $actual == "$expected_rc" ]]
    jq -e --arg status "$expected_status" '.status == $status and .alerts == null and .has_more_alerts == null
        and .review_queue == null and .open_priority_alerts_in_sample == null' \
        <<< "$output" >/dev/null
}

rm -- "$PACKRAT_TEST_CALL"
PACKRAT_TRIAGE_MAX_AGE=29 check_failure 1 stale_health
[[ ! -e $PACKRAT_TEST_CALL ]]
jq -c '.poll_interval_seconds = 5' <<< "$sample" >"$health"
check_failure 1 stale_health
[[ ! -e $PACKRAT_TEST_CALL ]]
result=$(PACKRAT_TRIAGE_MAX_AGE=30 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.status == "current" and .max_age_seconds == 30' <<< "$result" >/dev/null
jq -c '.poll_interval_seconds = 15' <<< "$sample" >"$health"
result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.status == "current" and .max_age_seconds == 50' <<< "$result" >/dev/null
rm -- "$PACKRAT_TEST_CALL"
jq -c '.timestamp = "2023-11-14T22:13:21Z"' <<< "$sample" >"$health"
check_failure 1 stale_health
[[ ! -e $PACKRAT_TEST_CALL ]]
jq -c '.capture_id = null' <<< "$sample" >"$health"
check_failure 1 capture_scope_unavailable
[[ ! -e $PACKRAT_TEST_CALL ]]
jq -c 'del(.alert_watcher_log)' <<< "$sample" >"$health"
check_failure 1 alert_log_unverified
[[ ! -e $PACKRAT_TEST_CALL ]]
jq -c --arg log "$scratch/other.jsonl" '.alert_watcher_log = $log' <<< "$sample" >"$health"
check_failure 1 alert_log_mismatch
[[ ! -e $PACKRAT_TEST_CALL ]]

strict_sample() {
    jq -c --arg identity "$(stat -Lc '%d:%i' "$PACKRAT_TEST_LOG")" \
        '. + {alert_watcher_open_log_required:true,alert_watcher_source_matches:true,
            alert_log_storage:"private",alert_log_identity:$identity}' <<< "$sample"
}
strict_sample >"$health"
result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.status == "current" and .alerts[0].alert_id == 42' <<< "$result" >/dev/null
PACKRAT_TEST_WATCH_ID_RACE=1 check_failure 1 alert_log_watcher_unverified
rm -- "$PACKRAT_TEST_CALL"
check_failure 1 alert_log_watcher_unverified
[[ ! -e $PACKRAT_TEST_CALL ]]
strict_sample >"$health"
PACKRAT_TEST_WATCH_ID_RACE=downgrade check_failure 1 alert_log_watcher_unverified
rm -- "$PACKRAT_TEST_CALL"
strict_sample >"$health"
mv -- "$PACKRAT_TEST_LOG" "$scratch/unfollowed.jsonl"
touch -- "$PACKRAT_TEST_LOG"
check_failure 1 alert_log_watcher_unverified
[[ ! -e $PACKRAT_TEST_CALL ]]
strict_sample >"$health"
bash "$triage" "$health" "$PACKRAT_TEST_LOG" | jq -e '.status == "current"' >/dev/null
rm -- "$PACKRAT_TEST_CALL"
jq -c '.alert_log_storage = "unsafe"' <<< "$sample" >"$health"
check_failure 1 alert_log_watcher_unverified
[[ ! -e $PACKRAT_TEST_CALL ]]

printf '%s\n' "$sample" >"$health"
PACKRAT_TEST_SCOPE_RACE=1 check_failure 1 capture_scope_changed
[[ -e $PACKRAT_TEST_CALL ]]
rm -- "$PACKRAT_TEST_CALL"
jq -c '.capture_run_id = null' <<< "$sample" >"$health"
check_failure 1 capture_scope_unavailable
[[ ! -e $PACKRAT_TEST_CALL ]]
jq -c '.capture_run_id = "0000000000000001"' <<< "$sample" >"$health"
bash "$triage" "$health" "$PACKRAT_TEST_LOG" | jq -e '.status == "current"' >/dev/null
PACKRAT_TEST_RUN_RACE=1 check_failure 1 capture_scope_changed
printf '%s\n' "$sample" >"$health"
PACKRAT_TEST_LOG_ERROR=1 check_failure 2 alert_log_unavailable
PACKRAT_TEST_INVALID_RECORDS=-1 check_failure 2 alert_log_unavailable
[[ -e $PACKRAT_TEST_CALL ]]
for field in session_id capture_id; do
    PACKRAT_TEST_WRONG_ALERT_SCOPE="$field" check_failure 2 alert_log_scope_mismatch
done
PACKRAT_TRIAGE_READ_TIMEOUT=3 PACKRAT_TEST_TIMEOUT_SECONDS=3 PACKRAT_TEST_TIMEOUT_STATUS=124 \
    check_failure 2 alert_log_read_timeout
PACKRAT_TEST_TIMEOUT_STATUS=137 check_failure 2 alert_log_read_interrupted
status=0
PACKRAT_TRIAGE_READ_TIMEOUT=0 bash "$triage" "$health" "$PACKRAT_TEST_LOG" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]
result=$(PACKRAT_TEST_LOG_RACE=append bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.status == "current" and .alerts[0].alert_id == 42 and .alert_log_advanced_during_review==true' <<< "$result" >/dev/null
bash "$triage" "$health" "$PACKRAT_TEST_LOG" |
    jq -e '.status=="current" and .alert_log_advanced_during_review==false' >/dev/null
[[ -s $PACKRAT_TEST_LOG ]]
before_rewrite=$(stat -Lc '%d:%i %s' -- "$PACKRAT_TEST_LOG")
PACKRAT_TEST_LOG_RACE=rewrite check_failure 1 alert_log_changed
[[ $(stat -Lc '%d:%i %s' -- "$PACKRAT_TEST_LOG") == "$before_rewrite" ]]
[[ $(head -c1 -- "$PACKRAT_TEST_LOG") == X ]]
PACKRAT_TEST_LOG_RACE=truncate check_failure 1 alert_log_changed
PACKRAT_TEST_LOG_RACE=rotate check_failure 1 alert_log_changed
[[ -f $PACKRAT_TEST_LOG.rotated && -f $PACKRAT_TEST_LOG ]]
jq -c '.issues = ["pcap_buffer_drops"]' <<< "$sample" >"$health"
status=0
result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "degraded" and .alerts[0].alert_id == 42' <<< "$result" >/dev/null

rm -- "$PACKRAT_TEST_CALL"
for invalid in 'not JSON' "$sample"$'\n'"$sample" \
    "$(jq -c '.poll_interval_seconds = "15"' <<< "$sample")" \
    "$(jq -nc --argjson sample "$sample" '$sample + {padding: ("x" * 65536)}')"; do
    printf '%s\n' "$invalid" >"$health"
    status=0
    bash "$triage" "$health" "$PACKRAT_TEST_LOG" >/dev/null 2>&1 || status=$?
    [[ $status == 2 && ! -e $PACKRAT_TEST_CALL ]]
done

saved() {
    bash "$triage" --saved 1700000000-432 00000000000000000000000000000001 "$@"
}
saved_alert() {
    PACKRAT_TEST_TARGET="$1" bash "$triage" --saved-alert 1700000000-432 00000000000000000000000000000001 "$@"
}
result=$(PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $previous" saved_alert 42 "$PACKRAT_TEST_LOG" "$previous")
jq -e '.status == "saved" and .scope.alert_id == 42 and .alerts[0].alert_id == 42
    and .previous_logs == 1 and .has_more_alerts == false
    and .alerts[0].next_evidence_step == "verify_frame_availability"' <<< "$result" >/dev/null
for evidence_status in complete partial unavailable; do
    case $evidence_status in
        complete) frames='["complete","complete"]'; step=inspect_retained_frames ;;
        partial) frames='["truncated","missing"]'; step=inspect_retained_and_recover_missing_frames ;;
        unavailable) frames='["missing","missing"]'; step=locate_original_capture ;;
    esac
    result=$(PACKRAT_TEST_FRAME_STATUSES="$frames" PACKRAT_TRIAGE_ARCHIVE="$scratch/archive space" saved_alert 42 "$PACKRAT_TEST_LOG")
    jq -e --arg expected "$evidence_status" --arg step "$step" '.status == "saved" and .live_packet_archive == "unknown"
        and .evidence_status.alert_id == .scope.alert_id and .review_queue == []
        and .alerts[0].packet_evidence_status == $expected and .alerts[0].next_evidence_step == $step' <<< "$result" >/dev/null
done
status=0
result=$(PACKRAT_TEST_ALERT_COUNT=0 saved_alert 99 "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "saved_alert_not_observed" and .scope.alert_id == 99 and .alerts == []' <<< "$result" >/dev/null
status=0
result=$(saved_alert 99 "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 2 ]]
jq -e '.status == "alert_log_scope_mismatch" and .alerts == null' <<< "$result" >/dev/null
status=0
PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=99 saved_alert 42 "$PACKRAT_TEST_LOG" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]
result=$(saved "$PACKRAT_TEST_LOG")
jq -e '.status == "saved" and .health == null and .alerts[0].alert_id == 42
    and (has("age_seconds") | not)' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $previous" saved "$PACKRAT_TEST_LOG" "$previous")
jq -e '.status == "saved" and .previous_logs == 1 and .health == null' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_ALERT_COUNT=0 saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "saved_scope_not_observed" and .health == null and .alerts == []
    and .scope == {session_id:"1700000000-432",capture_id:"00000000000000000000000000000001"}' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_ALERT_COUNT=0 PACKRAT_TEST_INVALID_RECORDS=1 saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "saved_log_degraded" and .alerts == [] and .alert_log_integrity.invalid_records == 1' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_INVALID_RECORDS=1 saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "saved_log_degraded" and .health == null and .alerts[0].alert_id == 42' \
    <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_WRONG_ALERT_SCOPE=session_id saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 2 ]]
jq -e '.status == "alert_log_scope_mismatch" and .alerts == null' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_LOG_RACE=rotate saved "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "alert_log_changed" and .alerts == null' <<< "$result" >/dev/null
status=0
bash "$triage" --saved 1700000000-432 'legacy-unspecified' "$PACKRAT_TEST_LOG" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

# shellcheck source=tests/support/packrat_triage_saved_index.bash
source "$root/tests/support/packrat_triage_saved_index.bash"
printf '%s\n' 'Packrat triage tests passed'
