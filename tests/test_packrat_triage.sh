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
unset PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE
unset PACKRAT_TRIAGE_PROJECT

date() {
    [[ $* == '-u +%s' ]] || return 2
    printf '%s\n' 1700000000
}

mock_archive() {
    printf '%s\n' called >"$PACKRAT_TEST_CALL"
    if [[ ${2-} == --alert-status || ${1-} == --project-alert-status ]]; then
        if [[ $1 == --project-alert-status ]]; then
            [[ $2 == "$PACKRAT_TRIAGE_PROJECT" && $3 == "$PACKRAT_TEST_LOG" &&
               $4 == 1700000000-432 && $5 == 00000000000000000000000000000001 && $6 == 42 ]] || return 2
        else
            [[ $* == "$PACKRAT_TRIAGE_ARCHIVE --alert-status $PACKRAT_TEST_LOG 1700000000-432 42 --capture-id 00000000000000000000000000000001${PACKRAT_TEST_PREVIOUS_ARGS:-}" ]] || return 2
        fi
        if [[ ${PACKRAT_TEST_EVIDENCE_RESTART:-0} == 1 ]]; then
            jq -c '.capture_id = "00000000000000000000000000000002"' "$PACKRAT_TEST_STATE" >"$PACKRAT_TEST_STATE.next"
            mv -- "$PACKRAT_TEST_STATE.next" "$PACKRAT_TEST_STATE"
        fi
        jq -cn --arg capture "${PACKRAT_TEST_EVIDENCE_SCOPE:-00000000000000000000000000000001}" \
            --arg drift "${PACKRAT_TEST_EVIDENCE_DRIFT:-0}" '
            {session_id:"1700000000-432",capture_id:$capture,alert_id:42,
             evidence_frame_set_sha256:($drift * 64),
             frames:[{frame_number:1,status:"truncated",bytes:[0,1]}, {frame_number:2,status:"missing"}]}'
        return
    fi
    local scope=' --session 1700000000-432 --capture-id 00000000000000000000000000000001' limit=51
    if [[ ${PACKRAT_TEST_INDEX:-0} == 1 ]]; then scope='' limit=512; fi
    local selector="--limit $limit"
    if [[ -n ${PACKRAT_TEST_TARGET:-} ]]; then selector="--alert-id $PACKRAT_TEST_TARGET"; fi
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
    case ${PACKRAT_TEST_LOG_RACE:-} in
        append) printf '%s\n' snapshot >>"$PACKRAT_TEST_LOG" ;;
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
            --argjson offset "${PACKRAT_TEST_ALERT_OFFSET:-0}" '
            [range($count; 0; -1) | {alert_id:(. + $offset),session_id:"1700000000-432",capture_id:"00000000000000000000000000000001"}
                + (if $large == "1" then {detail: ("\ud83d\udd0d" * 512), title: ("\ud83d\udd0d" * 160)}
                   else {} end)]'
    elif [[ $limit == 512 ]]; then
        jq -cn '
            {session_id:"1700000000-432",capture_id:"00000000000000000000000000000001",
             alert_id:1,first_seen:10,last_seen:20,severity:"HIGH",detail:"not in index"} as $base
            | [$base, ($base + {alert_id:2,first_seen:12,last_seen:22,severity:"LOW"}),
               ($base + {session_id:"1700000000-123",last_seen:30,severity:"CRITICAL"}),
               ($base + {capture_id:null}), ($base + {capture_id:"legacy"})]
        '
    else
        jq -cn --arg mismatch "${PACKRAT_TEST_WRONG_ALERT_SCOPE:-}" '
            {alert_id:42,title:"Scoped alert",session_id:"1700000000-432",capture_id:"00000000000000000000000000000001",
             evidence_frame_count:2,evidence_frame_set_sha256:("0"*64),
             last_seen:1700000000,
             flow:{transport:"tcp",source:"192.0.2.1:4321",destination:"192.0.2.2:443"}} as $valid
            | [$valid] + (if $mismatch == "" then [] else
                [($valid | .alert_id = 43 | .[$mismatch] = "other")]
              end)'
    fi
}

packrat-archive() {
    if [[ ${1-} != --alerts ]]; then mock_archive "$@"; return; fi
    mock_archive "$@" | jq -c --argjson invalid "${PACKRAT_TEST_INVALID_RECORDS:-0}" \
        --argjson oversized "${PACKRAT_TEST_OVERSIZED_RECORDS:-0}" --arg index "${PACKRAT_TEST_INDEX:-0}" \
        --arg target "${PACKRAT_TEST_TARGET:-}" '
        {alerts:.,integrity:{invalid_records:$invalid,oversized_records:$oversized,
            stopped_at_limit:(length == (if $target != "" then 1 elif $index == "1" then 512 else 51 end))}}'
}

timeout() {
    [[ $# -gt 3 && $1 == --kill-after=2s && $2 == "${PACKRAT_TEST_TIMEOUT_SECONDS:-10}s" ]] || return 2
    shift 2
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
    and .alerts[0].alert_id == 42 and .has_more_alerts == false and .evidence_status == null' <<< "$result" >/dev/null
[[ -f $PACKRAT_TEST_CALL ]]
(
    export PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE="$scratch/socket context.jsonl"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status == "not_recorded" and (.alerts[0] | has("socket_context") | not)' \
        <<< "$result" >/dev/null
    jq -cn '
        {alert_id:42, session_id:"1700000000-432",capture_id:"00000000000000000000000000000001",
         flow:{transport:"tcp",source:"192.0.2.1:4321",destination:"192.0.2.2:443"},
         alert_last_seen:1699999999.5,
         socket_context:{status:"exact_tuple_snapshot",observed_at:"2023-11-14T22:13:20Z",
            local:"192.0.2.1:4321",peer:"192.0.2.2:443",process:"client",pid:123,private:"do not export"}} as $valid |
        $valid,
        ($valid | .capture_id = "00000000000000000000000000000002" | .socket_context.process = "wrong capture"),
        ($valid | .session_id = "1700000000-567" | .socket_context.process = "wrong session"),
        ($valid | .flow.source = "192.0.2.1:4322" | .socket_context.process = "wrong port"),
        ($valid | .socket_context.observed_at = "2023-11-14T22:20:00Z")
    ' >"$PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status == "available" and .alerts[0].socket_context.process == "client"
        and .alerts[0].socket_context.alert_last_seen == 1699999999.5
        and (.alerts[0].socket_context | has("private") | not)' <<< "$result" >/dev/null
    result=$(bash "$triage" --saved 1700000000-432 00000000000000000000000000000001 "$PACKRAT_TEST_LOG")
    jq -e '.mode == "saved" and .status == "saved" and .health == null
        and .scope == {session_id:"1700000000-432",capture_id:"00000000000000000000000000000001"}
        and .alerts[0].socket_context.process == "client"' <<< "$result" >/dev/null
    printf '%s\n' '{malformed' >>"$PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status == "unavailable" and (.alerts[0] | has("socket_context") | not)' \
        <<< "$result" >/dev/null
)
status=0
result=$(PACKRAT_TEST_ALERT_COUNT=0 PACKRAT_TEST_INVALID_RECORDS=2 PACKRAT_TEST_OVERSIZED_RECORDS=1 \
    bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "degraded" and .alerts == []
    and .alert_log_integrity == {invalid_records:2,oversized_records:1,stopped_at_limit:false}' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_INVALID_RECORDS=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
[[ $status == 1 ]]
jq -e '.status == "degraded" and .alerts[0].alert_id == 42' <<< "$result" >/dev/null

export PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=42
(
    export PACKRAT_TRIAGE_ARCHIVE="$scratch/archive space"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.status == "current" and .evidence_status == {status:"checked",alert_id:42,in_recent_alerts:true,
        frames:[{frame_number:1,status:"truncated"},{frame_number:2,status:"missing"}]}' <<< "$result" >/dev/null
    result=$(bash "$triage" --saved 1700000000-432 00000000000000000000000000000001 "$PACKRAT_TEST_LOG")
    jq -e '.status == "saved" and .health == null and .evidence_status.status == "checked"
        and [.evidence_status.frames[].status] == ["truncated","missing"]' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_EVIDENCE_DRIFT=1 bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 2 ]]
    jq -e '.status == "current" and .alerts[0].alert_id == 42
        and .evidence_status == {status:"alert_evidence_changed",alert_id:42,frames:null}' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_ALERT_COUNT=0 bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 2 ]]
    jq -e '.alerts == [] and .evidence_status.status == "alert_evidence_changed"' <<< "$result" >/dev/null
    result=$(PACKRAT_TEST_ALERT_COUNT=51 PACKRAT_TEST_ALERT_OFFSET=50 bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.has_more_alerts and .evidence_status.status == "checked"
        and .evidence_status.in_recent_alerts == false' <<< "$result" >/dev/null
    status=0
    result=$(PACKRAT_TEST_EVIDENCE_SCOPE=other bash "$triage" "$health" "$PACKRAT_TEST_LOG") || status=$?
    [[ $status == 2 ]]
    jq -e '.status == "current" and .alerts[0].alert_id == 42
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
    jq -e --arg status "$expected_status" '.status == $status and .alerts == null and .has_more_alerts == null' \
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
jq -e '.status == "current" and .alerts[0].alert_id == 42' <<< "$result" >/dev/null
[[ -s $PACKRAT_TEST_LOG ]]
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
    and .previous_logs == 1 and .has_more_alerts == false' <<< "$result" >/dev/null
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

list_saved() {
    PACKRAT_TEST_INDEX=1 bash "$triage" --list-saved "$@"
}
result=$(list_saved "$PACKRAT_TEST_LOG")
jq -e '.record_type == "saved_capture_index" and .status == "saved"
    and .sampled_alerts == 5 and .sampled_unscoped_alerts == 2
    and .alert_sample_limit == 512 and .alert_log_integrity.stopped_at_limit == false
    and (.captures | map(.session_id)) == ["1700000000-123","1700000000-432"]
    and (.captures | map(.sampled_alerts)) == [1,2]
    and (.captures | map(.sampled_high_or_critical)) == [1,1]
    and .captures[1].first_seen == 10 and .captures[1].last_seen == 22
    and (tostring | contains("not in index") | not)' <<< "$result" >/dev/null
result=$(PACKRAT_TEST_ALERT_COUNT=512 list_saved "$PACKRAT_TEST_LOG")
jq -e '.status == "saved" and .sampled_alerts == 512 and .alert_log_integrity.stopped_at_limit
    and .captures[0].last_seen == null' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_INVALID_RECORDS=1 PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $previous" \
    list_saved "$PACKRAT_TEST_LOG" "$previous") || status=$?
[[ $status == 1 ]]
jq -e '.status == "saved_log_degraded" and .previous_logs == 1 and (.captures | length) == 2' \
    <<< "$result" >/dev/null
printf '%s\n' 'Packrat triage tests passed'
