#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-triage HEALTH_STATE.json ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        '       packrat-triage --saved SESSION_ID CAPTURE_ID ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        '       packrat-triage --list-saved ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        'Supply up to eight immutable previous logs, oldest first.' \
        'Reports up to 50 alerts from the capture and alert log in a fresh health record.' \
        '--saved reviews an explicit saved capture without consulting live health.' \
        '--list-saved groups the latest 512 distinct saved alerts by session and capture; counts cover only that sample.' \
        'has_more_alerts indicates that older matching alerts were omitted.' \
        'Alert log integrity counts apply only to records scanned, including records outside the capture scope.' \
        'Set PACKRAT_ALERT_LOG in the health watcher to identify the expected log.' \
        'PACKRAT_TRIAGE_MAX_AGE overrides the freshness limit in seconds.' \
        'PACKRAT_TRIAGE_READ_TIMEOUT sets the alert log read deadline in seconds (default: 10).' \
        'Set PACKRAT_TRIAGE_ARCHIVE or PACKRAT_TRIAGE_PROJECT, plus PACKRAT_TRIAGE_EVIDENCE_ALERT_ID, to check one alert.' \
        'Evidence for an alert in the recent report is withheld if its frame references changed during triage.' \
        'PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE optionally adds saved live socket snapshots for matching alerts.' \
        'By default, allow three poll intervals plus five seconds, or 360 seconds for older records.'
}

if [[ ${1-} == --help || ${1-} == -h ]]; then usage; exit 0; fi
mode=live
if [[ ${1-} == --saved ]]; then
    if (( $# < 4 || $# > 12 )) ||
       [[ ! $2 =~ ^[A-Za-z0-9_-]{1,128}$ || ! $3 =~ ^[0-9a-f]{32}$ ]]; then
        usage >&2; exit 2
    fi
    mode=saved
    session=$2 capture=$3 alert_log=$4
    shift 4
elif [[ ${1-} == --list-saved ]]; then
    if (( $# < 2 || $# > 10 )); then usage >&2; exit 2; fi
    mode=list_saved
    alert_log=$2
    shift 2
else
    if (( $# < 2 || $# > 10 )); then usage >&2; exit 2; fi
    health_file=$1 alert_log=$2
    shift 2
fi
alert_limit=50
query_limit=$((alert_limit + 1))
if [[ $mode == list_saved ]]; then query_limit=512; fi

previous_logs=("$@")
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
project=${PACKRAT_TRIAGE_PROJECT:-}
evidence_id=${PACKRAT_TRIAGE_EVIDENCE_ALERT_ID:-}
socket_file=${PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE:-}
if [[ $mode == list_saved ]]; then archive='' project='' evidence_id='' socket_file=''; fi
socket_status=not_configured
if [[ -n $socket_file ]]; then
    if [[ $socket_file != /* || $socket_file == */ || $socket_file == *[[:cntrl:]]* ]]; then
        printf '%s\n' 'PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE requires an absolute file path.' >&2
        exit 2
    fi
    socket_status=not_checked
fi
if [[ $mode == live && ( ! -f $health_file ||
      ( -n $max_age_override && ! $max_age_override =~ ^[1-9][0-9]{0,5}$ ) ) ]]; then
    printf '%s\n' 'Expected a regular health file and a positive PACKRAT_TRIAGE_MAX_AGE.' >&2
    exit 2
fi
if [[ -n $archive || -n $project || -n $evidence_id ]]; then
    evidence_path=${archive:-$project}
    if [[ ( -n $archive && -n $project ) || $evidence_path != /* ||
          $evidence_path == *[[:cntrl:]]* || ! $evidence_id =~ ^[1-9][0-9]{0,14}$ ]]; then
        printf '%s\n' 'Evidence status requires exactly one absolute archive or project path and a positive alert ID.' >&2
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

report() {
    printf '%s\n%s\n%s\n%s\n' "$state" "${2-null}" "${3-null}" "${4-null}" | jq -cs --arg status "$1" --argjson limit "$alert_limit" \
        --argjson previous "${#previous_logs[@]}" --arg socket "$socket_status" '
        .[1] as $alerts
        | .[2] as $evidence
        | .[0] + {record_type:"capture_triage", status:$status, alert_limit:$limit, previous_logs:$previous,
             has_more_alerts:(if $alerts == null then null else ($alerts | length) > $limit end),
             alerts:(if $alerts == null then null else $alerts[:$limit] end),
             evidence_status:$evidence, alert_log_integrity:.[3], socket_context_status:$socket}
    '
}

report_saved_index() {
    jq -c --argjson limit "$query_limit" --argjson previous "${#previous_logs[@]}" '
        def scoped:
            (.session_id | type == "string" and test("\\A[A-Za-z0-9_-]{1,128}\\z"))
            and (.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"));
        def seen:
            numbers | select(isfinite and . > 0);
        .integrity as $integrity
        | (.alerts | map(select(scoped))) as $scoped
        | {
            record_type:"saved_capture_index",
            status:(if $integrity.invalid_records == 0 and $integrity.oversized_records == 0 then "saved" else "saved_log_degraded" end),
            previous_logs:$previous,
            alert_sample_limit:$limit,
            sampled_alerts:(.alerts | length),
            sampled_unscoped_alerts:((.alerts | length) - ($scoped | length)),
            alert_log_integrity:$integrity,
            captures:($scoped | group_by([.session_id, .capture_id]) | map({
                session_id:.[0].session_id, capture_id:.[0].capture_id, sampled_alerts:length,
                sampled_high_or_critical:map(select(.severity == "HIGH" or .severity == "CRITICAL")) | length,
                first_seen:([.[].first_seen | seen] | min),
                last_seen:([.[].last_seen | seen] | max)
            }) | sort_by([-(.last_seen // 0), .session_id, .capture_id]))
          }
    ' <<< "$history"
}

with_socket_context() {
    local snapshots
    [[ -f $socket_file && ! -L $socket_file ]] || return 1
    snapshots=$(head -c 65537 -- "$socket_file" | jq -Rces '
        select(utf8bytelength <= 65536)
        | split("\n") | map(select(length > 0) | fromjson)
        | select(length <= 64 and all(.[]; type == "object"))
    ') || return 1
    jq -ce --argjson snapshots "$snapshots" '
        def snapshot($alert):
            .alert_last_seen as $seen
            | select(.session_id == $alert.session_id and .capture_id == $alert.capture_id
                and .alert_id == $alert.alert_id and .flow == $alert.flow and .flow.transport == "tcp"
                and (.alert_last_seen | type == "number" and isfinite and . > 0)
                and ($alert.last_seen | type == "number" and . >= $seen));
        map(. as $alert
            | ([$snapshots[] | snapshot($alert)
                | .alert_last_seen as $when
                | .socket_context | objects
                | select(.status == "exact_tuple_snapshot"
                    and ((.local == $alert.flow.source and .peer == $alert.flow.destination)
                        or (.local == $alert.flow.destination and .peer == $alert.flow.source))
                    and (.process | type == "string" and test("\\A[A-Za-z0-9_. -]{1,64}\\z"))
                    and (.pid | type == "number" and floor == . and . >= 1 and . <= 4294967295)
                    and ((try (.observed_at | fromdateiso8601) catch null)
                        | . != null and . >= ($when | floor) and . <= ($when | floor) + 8))
                | {status,observed_at,local,peer,process,pid,alert_last_seen:$when}] | last) as $context
            | if $context == null then . else . + {socket_context:$context} end)
    ' <<< "$alerts"
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
    local response expected
    local -a evidence_args
    if [[ -n $project ]]; then
        evidence_args=(--project-alert-status "$project" "$1" "$session" "$capture" "$evidence_id")
    else
        evidence_args=("$archive" --alert-status "$1" "$session" "$evidence_id" --capture-id "$capture")
    fi
    response=$(timeout --kill-after=2s "${read_timeout}s" packrat-archive \
        "${evidence_args[@]}" "${previous_args[@]}") || return 1
    expected=$(jq -c --argjson id "$evidence_id" --argjson limit "$alert_limit" '
        {match:(first(.alerts[] | select(.alert_id == $id) |
            {digest:.evidence_frame_set_sha256, count:.evidence_frame_count}) // null),
         outside_report: ([.alerts[:$limit][] | select(.alert_id == $id)] | length) == 0,
         stopped_at_limit:.integrity.stopped_at_limit}
    ' <<< "$history") || return 1
    jq -cse --arg session "$session" --arg capture "$capture" --argjson id "$evidence_id" \
        --argjson expected "$expected" '
        select(length == 1) | .[0] | objects
        | select(.session_id == $session and .capture_id == $capture and .alert_id == $id
            and (.evidence_frame_set_sha256 | type == "string" and test("\\A[0-9a-f]{64}\\z"))
            and (.frames | type == "array" and length >= 1 and length <= 131
                and all(.[]; type == "object"
                    and (.frame_number | type == "number" and isfinite and . > 0 and floor == .)
                    and (.status == "complete" or .status == "truncated" or .status == "missing"
                        or .status == "length_unknown" or .status == "unreadable"))
                and (map(.frame_number) | . == unique)))
        | if ($expected.match != null and ($expected.match.digest != .evidence_frame_set_sha256
                  or $expected.match.count != (.frames | length)))
              or ($expected.match == null and ($expected.stopped_at_limit | not))
          then {status:"alert_evidence_changed", alert_id, frames:null}
          else {status:"checked", alert_id, frames:(.frames | map({frame_number,status})),
                in_recent_alerts:($expected.outside_report | not)}
          end
    ' <<< "$response"
}

scope_args=()
if [[ $mode == live ]]; then
    if ! state=$(load_state "$health_file"); then
        printf '%s\n' 'Could not read a valid Packrat health record.' >&2
        exit 2
    fi
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
    match_log "$alert_log" || exit 1
    session=$(jq -er '.health.alert_session_id' <<< "$state")
    capture=$(jq -er '.health.capture_id' <<< "$state")
    run=$(jq -c '.health.capture_run_id' <<< "$state")
elif [[ $mode == saved ]]; then
    state=$(jq -cn --arg session "$session" --arg capture "$capture" '
        {mode:"saved",health:null,scope:{session_id:$session,capture_id:$capture}}
    ')
else
    state='{"mode":"list_saved","health":null}'
fi
if [[ $mode != list_saved ]]; then scope_args=(--session "$session" --capture-id "$capture"); fi

if [[ ! -f $alert_log ]] ||
   ! read -r log_identity log_size <<< "$(stat -L --format='%d:%i %s' -- "$alert_log")" ||
   [[ -z $log_identity || ! $log_size =~ ^[0-9]+$ ]]; then
    report alert_log_unavailable
    exit 2
fi
if ! previous_stamps=$(previous_log_stamps); then
    report previous_log_unavailable
    exit 2
fi
read_status=0
raw_alerts=$(timeout --kill-after=2s "${read_timeout}s" packrat-archive \
    --alerts "$alert_log" "${scope_args[@]}" \
    --limit "$query_limit" --report-integrity "${previous_args[@]}") || read_status=$?
if (( read_status == 124 )); then
    report alert_log_read_timeout
    exit 2
fi
if (( read_status == 137 )); then
    report alert_log_read_interrupted
    exit 2
fi
if (( read_status != 0 )) || ! history=$(jq -cse --argjson limit "$query_limit" '
    def count: type == "number" and isfinite and floor == . and . >= 0;
    select(length == 1) | .[0] | objects
    | select((.alerts | type == "array" and length <= $limit and all(.[]; type == "object"))
        and (.integrity | type == "object" and (.invalid_records | count)
            and (.oversized_records | count) and (.stopped_at_limit | type == "boolean"))
        and (.integrity.stopped_at_limit == ((.alerts | length) == $limit)))
' <<< "$raw_alerts"); then
    report alert_log_unavailable
    exit 2
fi
alerts=$(jq -c '.alerts' <<< "$history")
integrity=$(jq -c '.integrity | {invalid_records,oversized_records,stopped_at_limit}' <<< "$history")
if [[ $mode != list_saved ]] && ! jq -e --arg session "$session" --arg capture "$capture" '
    all(.[]; type == "object" and .session_id == $session and .capture_id == $capture)
' <<< "$alerts" >/dev/null; then
    report alert_log_scope_mismatch
    exit 2
fi
if [[ -n $socket_file ]]; then
    if [[ ! -e $socket_file && ! -L $socket_file ]]; then
        socket_status=not_recorded
    elif enriched=$(with_socket_context 2>/dev/null); then
        alerts=$enriched
        socket_status=available
    else
        socket_status=unavailable
    fi
fi
evidence=null
evidence_failed=false
if [[ -n $evidence_id ]]; then
    if ! evidence=$(check_evidence "$alert_log"); then
        evidence=$(jq -cn --argjson id "$evidence_id" '{status:"unavailable",alert_id:$id,frames:null}')
    fi
    if ! jq -e '.status == "checked"' <<< "$evidence" >/dev/null; then evidence_failed=true; fi
fi
if [[ $mode == live ]]; then
    if ! latest=$(load_state "$health_file"); then
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
    match_log "$alert_log" || exit 1
fi
if [[ ! -f $alert_log ]] ||
   ! read -r latest_identity latest_size <<< "$(stat -L --format='%d:%i %s' -- "$alert_log")" ||
   [[ $latest_identity != "$log_identity" || ! $latest_size =~ ^[0-9]+$ ]] ||
   (( latest_size < log_size )); then
    report alert_log_changed
    exit 1
fi
if ! latest_stamps=$(previous_log_stamps) || [[ $latest_stamps != "$previous_stamps" ]]; then
    report previous_log_changed
    exit 1
fi
if [[ $mode == list_saved ]]; then
    index=$(report_saved_index)
    printf '%s\n' "$index"
    if jq -e '.status == "saved"' <<< "$index" >/dev/null; then exit 0; else exit 1; fi
fi
clean_status=current
degraded_status=degraded
if [[ $mode == saved ]]; then
    clean_status=saved
    degraded_status=saved_log_degraded
fi
if { [[ $mode == saved ]] || jq -e '.health.issues == []' <<< "$state" >/dev/null; } &&
   jq -e '.invalid_records == 0 and .oversized_records == 0' <<< "$integrity" >/dev/null; then
    report "$clean_status" "$alerts" "$evidence" "$integrity"
    if "$evidence_failed"; then exit 2; fi
else
    report "$degraded_status" "$alerts" "$evidence" "$integrity"
    exit 1
fi
