#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-triage HEALTH_STATE.json ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        'Supply up to eight previous logs, oldest first.' \
        'Reports up to 50 alerts from the capture and alert log in a fresh health record.' \
        'Set PACKRAT_ALERT_LOG in the health watcher to identify the expected log.' \
        'PACKRAT_TRIAGE_MAX_AGE sets the maximum health record age in seconds (default: 360).'
}

if [[ ${1-} == --help || ${1-} == -h ]]; then usage; exit 0; fi
if (( $# < 2 || $# > 10 )); then usage >&2; exit 2; fi

previous_logs=()
for log in "${@:3}"; do
    if [[ ! -f $log ]]; then
        printf 'Previous alert log is not a regular file: %s\n' "$log" >&2
        exit 2
    fi
    previous_logs+=(--previous-log "$log")
done

max_age=${PACKRAT_TRIAGE_MAX_AGE:-360}
if [[ ! $max_age =~ ^[1-9][0-9]{0,5}$ || ! -f $1 ]]; then
    printf '%s\n' 'Expected a regular health file and a positive PACKRAT_TRIAGE_MAX_AGE.' >&2
    exit 2
fi

load_state() {
    head -c 65537 -- "$1" | jq -Rces --argjson now "$(date -u +%s)" '
        select(utf8bytelength <= 65536) | fromjson | objects
        | select(.record_type == "capture_health" and (.issues | type) == "array")
        | (.timestamp | strings | fromdateiso8601) as $recorded_at
        | {age_seconds: ($now - $recorded_at), health: .}
    '
}

if ! state=$(load_state "$1"); then
    printf '%s\n' 'Could not read a valid Packrat health record.' >&2
    exit 2
fi

report() {
    jq -c --arg status "$1" --argjson max_age "$max_age" --argjson alerts "${2-null}" \
        --argjson previous "$((${#previous_logs[@]} / 2))" '
        . + {record_type:"capture_triage", status:$status, max_age_seconds:$max_age,
             alert_limit:50, previous_logs:$previous, alerts:$alerts}
    ' <<< "$state"
}

fresh() {
    jq -e --argjson max "$max_age" '.age_seconds >= 0 and .age_seconds <= $max' <<< "$state" >/dev/null
}

match_log() {
    local expected
    if ! expected=$(jq -er '.health.alert_watcher_log | strings | select(startswith("/") and test("[[:cntrl:]]") == false)' <<< "$state"); then
        report alert_log_unverified
        return 1
    fi
    if [[ ! -f $1 || ! $1 -ef $expected ]]; then
        report alert_log_mismatch
        return 1
    fi
}

if ! fresh; then
    report stale_health
    exit 1
fi
if ! jq -e '
    .health | .capture_active == true and .telemetry_fresh == true
    and (.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"))
    and (.alert_session_id | type == "string" and length <= 128 and test("\\A[0-9]+-[0-9]+\\z"))
' <<< "$state" >/dev/null; then
    report capture_scope_unavailable
    exit 1
fi

match_log "$2" || exit 1
session=$(jq -er '.health.alert_session_id' <<< "$state")
capture=$(jq -er '.health.capture_id' <<< "$state")
if ! alerts=$(packrat-archive --alerts "$2" --session "$session" --capture-id "$capture" --limit 50 "${previous_logs[@]}" |
        jq -cse 'select(length == 1) | .[0] | arrays'); then
    report alert_log_unavailable
    exit 2
fi
if ! latest=$(load_state "$1"); then
    report health_recheck_failed
    exit 2
fi
state=$latest
if ! fresh; then
    report stale_health
    exit 1
fi
if ! jq -e --arg session "$session" --arg capture "$capture" '
    .health | .capture_active == true and .telemetry_fresh == true
    and .alert_session_id == $session and .capture_id == $capture
' <<< "$state" >/dev/null; then
    report capture_scope_changed
    exit 1
fi
match_log "$2" || exit 1
if jq -e '.health.issues == []' <<< "$state" >/dev/null; then
    report current "$alerts"
else
    report degraded "$alerts"
    exit 1
fi
