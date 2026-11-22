#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-triage HEALTH_STATE.json ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        'Supply up to eight immutable previous logs, oldest first.' \
        'Reports up to 50 alerts from the capture and alert log in a fresh health record.' \
        'has_more_alerts indicates that older matching alerts were omitted.' \
        'Set PACKRAT_ALERT_LOG in the health watcher to identify the expected log.' \
        'PACKRAT_TRIAGE_MAX_AGE overrides the freshness limit in seconds.' \
        'PACKRAT_TRIAGE_READ_TIMEOUT sets the alert log read deadline in seconds (default: 10).' \
        'Set PACKRAT_TRIAGE_ARCHIVE and PACKRAT_TRIAGE_EVIDENCE_ALERT_ID to check frame availability for one alert.' \
        'By default, allow three poll intervals plus five seconds, or 360 seconds for older records.'
}

if [[ ${1-} == --help || ${1-} == -h ]]; then usage; exit 0; fi
if (( $# < 2 || $# > 10 )); then usage >&2; exit 2; fi
alert_limit=50

previous_logs=("${@:3}")
previous_args=()
for log in "${previous_logs[@]}"; do
    if [[ ! -f $log ]]; then
        printf 'Previous alert log is not a regular file: %s\n' "$log" >&2
        exit 2
    fi
    previous_args+=(--previous-log "$log")
done

max_age_override=${PACKRAT_TRIAGE_MAX_AGE:-}
read_timeout=${PACKRAT_TRIAGE_READ_TIMEOUT:-10}
archive=${PACKRAT_TRIAGE_ARCHIVE:-}
evidence_id=${PACKRAT_TRIAGE_EVIDENCE_ALERT_ID:-}
if [[ ! -f $1 || ( -n $max_age_override && ! $max_age_override =~ ^[1-9][0-9]{0,5}$ ) ]]; then
    printf '%s\n' 'Expected a regular health file and a positive PACKRAT_TRIAGE_MAX_AGE.' >&2
    exit 2
fi
if [[ -n $archive || -n $evidence_id ]]; then
    if [[ $archive != /* || $archive == *[[:cntrl:]]* || ! $evidence_id =~ ^[1-9][0-9]{0,14}$ ]]; then
        printf '%s\n' 'Evidence status requires an absolute PACKRAT_TRIAGE_ARCHIVE and a positive alert ID.' >&2
        exit 2
    fi
fi
if [[ ! $read_timeout =~ ^[1-9][0-9]{0,3}$ ]]; then
    printf '%s\n' 'PACKRAT_TRIAGE_READ_TIMEOUT must be between 1 and 9999 seconds.' >&2
    exit 2
fi

load_state() {
    head -c 65537 -- "$1" | jq -Rces --argjson now "$(date -u +%s)" \
        --arg override "$max_age_override" '
        select(utf8bytelength <= 65536) | fromjson | objects
        | select(.record_type == "capture_health" and (.issues | type) == "array")
        | select((has("poll_interval_seconds") | not) or (
              .poll_interval_seconds | type == "number" and floor == . and . >= 1 and . <= 999999
          ))
        | (.timestamp | strings | fromdateiso8601) as $recorded_at
        | {age_seconds: ($now - $recorded_at), health: .,
           max_age_seconds: (if $override != "" then ($override | tonumber)
                             elif has("poll_interval_seconds") then .poll_interval_seconds * 3 + 5
                             else 360 end)}
    '
}

if ! state=$(load_state "$1"); then
    printf '%s\n' 'Could not read a valid Packrat health record.' >&2
    exit 2
fi

report() {
    printf '%s\n%s\n%s\n' "$state" "${2-null}" "${3-null}" | jq -cs --arg status "$1" --argjson limit "$alert_limit" \
        --argjson previous "${#previous_logs[@]}" '
        .[1] as $alerts
        | .[2] as $evidence
        | .[0] + {record_type:"capture_triage", status:$status, alert_limit:$limit, previous_logs:$previous,
             has_more_alerts:(if $alerts == null then null else ($alerts | length) > $limit end),
             alerts:(if $alerts == null then null else $alerts[:$limit] end),
             evidence_status:$evidence}
    '
}

fresh() {
    jq -e '.age_seconds >= 0 and .age_seconds <= .max_age_seconds' <<< "$state" >/dev/null
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

previous_log_stamps() {
    local path stamp
    for path in "${previous_logs[@]}"; do
        [[ -f $path ]] || return 1
        stamp=$(stat -L --format='%d:%i:%s:%y:%z' -- "$path") || return 1
        printf '%s\n' "$stamp"
    done
}

check_evidence() {
    local response
    response=$(timeout --kill-after=2s "${read_timeout}s" packrat-archive "$archive" \
        --alert-status "$1" "$session" "$evidence_id" --capture-id "$capture" "${previous_args[@]}") || return 1
    jq -cse --arg session "$session" --arg capture "$capture" --argjson id "$evidence_id" '
        select(length == 1) | .[0] | objects
        | select(.session_id == $session and .capture_id == $capture and .alert_id == $id
            and (.frames | type == "array" and length <= 131
                and all(.[]; type == "object" and (.frame_number | type == "number" and . > 0 and floor == .)
                    and (.status == "complete" or .status == "truncated" or .status == "missing"
                        or .status == "length_unknown" or .status == "unreadable"))))
        | {status:"checked", alert_id, frames:(.frames | map({frame_number,status}))}
    ' <<< "$response"
}

if ! fresh; then
    report stale_health
    exit 1
fi
if ! jq -e '
    .health | .capture_active == true and .telemetry_fresh == true
    and (.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"))
    and (.alert_session_id | type == "string" and length <= 128 and test("\\A[0-9]+-[0-9]+\\z"))
    and ((has("capture_run_id") | not) or
         (.capture_run_id | type == "string" and test("\\A[0-9a-f]{16}\\z")))
' <<< "$state" >/dev/null; then
    report capture_scope_unavailable
    exit 1
fi

match_log "$2" || exit 1
if ! read -r log_identity log_size <<< "$(stat -L --format='%d:%i %s' -- "$2")" ||
   [[ -z $log_identity || ! $log_size =~ ^[0-9]+$ ]]; then
    report alert_log_unavailable
    exit 2
fi
if ! previous_stamps=$(previous_log_stamps); then
    report previous_log_unavailable
    exit 2
fi
session=$(jq -er '.health.alert_session_id' <<< "$state")
capture=$(jq -er '.health.capture_id' <<< "$state")
run=$(jq -c '.health.capture_run_id' <<< "$state")
read_status=0
raw_alerts=$(timeout --kill-after=2s "${read_timeout}s" packrat-archive \
    --alerts "$2" --session "$session" --capture-id "$capture" \
    --limit "$((alert_limit + 1))" "${previous_args[@]}") || read_status=$?
if (( read_status == 124 )); then
    report alert_log_read_timeout
    exit 2
fi
if (( read_status == 137 )); then
    report alert_log_read_interrupted
    exit 2
fi
if (( read_status != 0 )) || ! alerts=$(jq -cse 'select(length == 1) | .[0] | arrays' <<< "$raw_alerts"); then
    report alert_log_unavailable
    exit 2
fi
if ! jq -e --arg session "$session" --arg capture "$capture" '
    all(.[]; type == "object" and .session_id == $session and .capture_id == $capture)
' <<< "$alerts" >/dev/null; then
    report alert_log_scope_mismatch
    exit 2
fi
evidence=null
evidence_failed=false
if [[ -n $evidence_id ]] && ! evidence=$(check_evidence "$2"); then
    evidence=$(jq -cn --argjson id "$evidence_id" '{status:"unavailable",alert_id:$id,frames:null}')
    evidence_failed=true
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
if ! jq -e --arg session "$session" --arg capture "$capture" --argjson run "$run" '
    .health | .capture_active == true and .telemetry_fresh == true
    and .alert_session_id == $session and .capture_id == $capture
    and .capture_run_id == $run
' <<< "$state" >/dev/null; then
    report capture_scope_changed
    exit 1
fi
match_log "$2" || exit 1
if ! read -r latest_identity latest_size <<< "$(stat -L --format='%d:%i %s' -- "$2")" ||
   [[ $latest_identity != "$log_identity" || ! $latest_size =~ ^[0-9]+$ ]] ||
   (( latest_size < log_size )); then
    report alert_log_changed
    exit 1
fi
if ! latest_stamps=$(previous_log_stamps) || [[ $latest_stamps != "$previous_stamps" ]]; then
    report previous_log_changed
    exit 1
fi
if jq -e '.health.issues == []' <<< "$state" >/dev/null; then
    report current "$alerts" "$evidence"
    if "$evidence_failed"; then exit 2; fi
else
    report degraded "$alerts" "$evidence"
    exit 1
fi
