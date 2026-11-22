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
unset PACKRAT_TRIAGE_MAX_AGE

date() {
    [[ $* == '-u +%s' ]] || return 2
    printf '%s\n' 1700000000
}

packrat-archive() {
    printf '%s\n' called >"$PACKRAT_TEST_CALL"
    [[ $* == "--alerts $PACKRAT_TEST_LOG --session 1700000000-432 --capture-id 00000000000000000000000000000001 --limit 50${PACKRAT_TEST_PREVIOUS_ARGS:-}" ]] || return 2
    if [[ ${PACKRAT_TEST_LOG_ERROR:-0} == 1 ]]; then return 1; fi
    if [[ ${PACKRAT_TEST_SCOPE_RACE:-0} == 1 ]]; then
        jq -c '.capture_id = "00000000000000000000000000000002"' "$PACKRAT_TEST_STATE" >"$PACKRAT_TEST_STATE.next"
        mv -- "$PACKRAT_TEST_STATE.next" "$PACKRAT_TEST_STATE"
    fi
    case ${PACKRAT_TEST_LOG_RACE:-} in
        append) printf '%s\n' snapshot >>"$PACKRAT_TEST_LOG" ;;
        truncate) : >"$PACKRAT_TEST_LOG" ;;
        rotate) mv -- "$PACKRAT_TEST_LOG" "$PACKRAT_TEST_LOG.rotated"; touch -- "$PACKRAT_TEST_LOG" ;;
    esac
    printf '%s\n' '[{"alert_id":42,"title":"Scoped alert"}]'
}

export -f date packrat-archive

sample='{"record_type":"capture_health","timestamp":"2023-11-14T22:12:50Z",
         "capture_active":true,"telemetry_fresh":true,"issues":[],
         "capture_id":"00000000000000000000000000000001","alert_session_id":"1700000000-432"}'
sample=$(jq -c --arg log "$PACKRAT_TEST_LOG" '.alert_watcher_log = $log' <<< "$sample")
printf '%s\n' "$sample" >"$health"
result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
jq -e '.status == "current" and .age_seconds == 30 and .alerts[0].alert_id == 42' <<< "$result" >/dev/null
[[ -f $PACKRAT_TEST_CALL ]]

previous="$scratch/older log.jsonl"
touch -- "$previous"
result=$(PACKRAT_TEST_PREVIOUS_ARGS=" --previous-log $previous" bash "$triage" "$health" "$PACKRAT_TEST_LOG" "$previous")
jq -e '.status == "current" and .previous_logs == 1 and .alerts[0].alert_id == 42' <<< "$result" >/dev/null

check_failure() {
    local expected_rc=$1 expected_status=$2 actual=0 output
    output=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG") || actual=$?
    [[ $actual == "$expected_rc" ]]
    jq -e --arg status "$expected_status" '.status == $status and .alerts == null' <<< "$output" >/dev/null
}

rm -- "$PACKRAT_TEST_CALL"
PACKRAT_TRIAGE_MAX_AGE=29 check_failure 1 stale_health
[[ ! -e $PACKRAT_TEST_CALL ]]
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
printf '%s\n' "$sample" >"$health"
PACKRAT_TEST_LOG_ERROR=1 check_failure 2 alert_log_unavailable
[[ -e $PACKRAT_TEST_CALL ]]
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
for invalid in 'not JSON' "$sample"$'\n'"$sample" "$(jq -nc --argjson sample "$sample" '$sample + {padding: ("x" * 65536)}')"; do
    printf '%s\n' "$invalid" >"$health"
    status=0
    bash "$triage" "$health" "$PACKRAT_TEST_LOG" >/dev/null 2>&1 || status=$?
    [[ $status == 2 && ! -e $PACKRAT_TEST_CALL ]]
done
printf '%s\n' 'Packrat triage tests passed'
