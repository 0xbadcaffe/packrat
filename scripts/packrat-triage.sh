#!/usr/bin/env bash
set -euo pipefail
usage() {
    printf '%s\n' 'Usage: packrat-triage HEALTH_STATE.json ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        '       packrat-triage --saved SESSION_ID CAPTURE_ID ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        '       packrat-triage --saved-alert SESSION_ID CAPTURE_ID ALERT_ID ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        '       packrat-triage --list-saved [--review-scope SESSION_ID CAPTURE_ID] [--review-rule RULE_ID] [--review-offset N] ALERT_LOG.jsonl [PREVIOUS_LOG ...]' \
        'Supply up to eight immutable previous logs, oldest first.' \
        'Live triage and saved backlog indexing scan up to 8 MiB and report when the budget limits coverage.' \
        '--saved does not consult live health; an unmatched scope reports saved_scope_not_observed.' \
        '--saved-alert looks up one alert beyond the recent sample; a missing match reports saved_alert_not_observed.' \
        '--list-saved ranks five scoped priority findings per page, or only a named rule at any severity. Use immutable logs across pages.' \
        'review_queue lists up to five unresolved CRITICAL or HIGH alerts (New, Reviewing, or Confirmed), even outside the recent list.' \
        'Alert log integrity counts apply only to records scanned, including records outside the capture scope.' \
        'Strict watcher mode checks the identity of the log configured via PACKRAT_ALERT_LOG.' \
        'PACKRAT_TRIAGE_MAX_AGE and PACKRAT_TRIAGE_READ_TIMEOUT override freshness and log-read deadlines in seconds.' \
        'Set PACKRAT_TRIAGE_ARCHIVE or PACKRAT_TRIAGE_PROJECT, plus PACKRAT_TRIAGE_EVIDENCE_ALERT_ID, to check one alert.' \
        'In live mode, PACKRAT_TRIAGE_AUTO_EVIDENCE=1 with PACKRAT_TRIAGE_ARCHIVE checks up to five open alerts in one read-timeout budget.' \
        'Automatic checks prefer CRITICAL, HIGH, then opted-in MEDIUM/LOW rules; newest eligible alerts first.' \
        '--saved-alert uses its explicit ID when an evidence source is supplied without PACKRAT_TRIAGE_EVIDENCE_ALERT_ID.' \
        'Evidence status distinguishes timeouts, deferred lookups, and references that changed during triage.' \
        'By default, allow three poll intervals plus five seconds, or 360 seconds for older records.'
}
if [[ ${1-} == --help || ${1-} == -h ]]; then usage; exit 0; fi
mode=live target_alert='' review_offset=0 review_rule='' session='' capture=''
if [[ ${1-} == --saved-alert ]]; then
    if (( $# < 5 || $# > 13 )) || [[ ! $4 =~ ^[1-9][0-9]{0,14}$ ]]; then usage >&2; exit 2; fi
    target_alert=$4; set -- --saved "$2" "$3" "${@:5}"
fi
if [[ ${1-} == --saved ]]; then
    if (( $# < 4 || $# > 12 )) ||
       [[ ! $2 =~ ^[A-Za-z0-9_-]{1,128}$ || ! $3 =~ ^[0-9a-f]{32}$ ]]; then usage >&2; exit 2; fi
    mode=saved session=$2 capture=$3 alert_log=$4
    shift 4
elif [[ ${1-} == --list-saved ]]; then
    shift
    if [[ ${1-} == --review-scope ]]; then
        session=${2-} capture=${3-}
        [[ $session =~ ^[A-Za-z0-9_-]{1,128}$ && $capture =~ ^[0-9a-f]{32}$ ]] || { usage >&2; exit 2; }
        shift 3
    fi
    if [[ ${1-} == --review-rule ]]; then
        review_rule=${2-}; shift 2 || { usage >&2; exit 2; }
        [[ $review_rule =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ ]] || { usage >&2; exit 2; }
    fi
    if [[ ${1-} == --review-offset ]]; then
        review_offset=${2-}
        if [[ ! $review_offset =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( review_offset >= 512 )); then usage >&2; exit 2; fi
        shift 2
    fi
    if (( $# < 1 || $# > 9 )); then usage >&2; exit 2; fi
    mode=list_saved alert_log=$1; shift
else
    if (( $# < 2 || $# > 10 )); then usage >&2; exit 2; fi
    health_file=$1 alert_log=$2; shift 2
fi
alert_limit=50 query_limit=512
limit_args=(--limit "$query_limit")
if [[ $mode == live || $mode == list_saved ]]; then limit_args+=(--scan-bytes 8388608); fi
if [[ -n $target_alert ]]; then
    alert_limit=1 query_limit=1
    limit_args=(--alert-id "$target_alert")
fi
previous_logs=("$@") previous_args=()
for log in "${previous_logs[@]}"; do
    [[ -f $log ]] || { printf 'Previous alert log is not a regular file: %s\n' "$log" >&2; exit 2; }
    previous_args+=(--previous-log "$log")
done
max_age_override=${PACKRAT_TRIAGE_MAX_AGE:-} read_timeout=${PACKRAT_TRIAGE_READ_TIMEOUT:-10}
archive=${PACKRAT_TRIAGE_ARCHIVE:-} project=${PACKRAT_TRIAGE_PROJECT:-}
evidence_id=${PACKRAT_TRIAGE_EVIDENCE_ALERT_ID:-}
auto_evidence=${PACKRAT_TRIAGE_AUTO_EVIDENCE:-0}
socket_file=${PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE:-}
if [[ $mode == list_saved ]]; then archive='' project='' evidence_id='' socket_file='' auto_evidence=0; fi
if [[ -n $target_alert && -z $evidence_id && ( -n $archive || -n $project ) ]]; then
    evidence_id=$target_alert
fi
if [[ -n $target_alert && -n $evidence_id && $target_alert != "$evidence_id" ]]; then
    printf '%s\n' 'The evidence alert ID must match the requested saved alert.' >&2
    exit 2
fi
socket_status=not_configured archive_rules='[]' log_advanced=null
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
if [[ $auto_evidence != 0 && $auto_evidence != 1 ]] ||
   [[ $auto_evidence == 1 && ( $mode != live || -z $archive || -n $project || -n $evidence_id ) ]]; then
    printf '%s\n' 'Automatic evidence checks require live mode and an archive, without an explicit alert ID or project.' >&2
    exit 2
fi
evidence_selection=off
if [[ -n $evidence_id ]]; then evidence_selection=explicit; elif [[ $auto_evidence == 1 ]]; then evidence_selection=automatic; fi
if [[ -n $archive || -n $project || -n $evidence_id ]]; then
    evidence_path=${archive:-$project}
    if [[ ( -n $archive && -n $project ) || $evidence_path != /* ||
          $evidence_path == *[[:cntrl:]]* ||
          ( $auto_evidence == 0 && ! $evidence_id =~ ^[1-9][0-9]{0,14}$ ) ]]; then
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
unresolved_jq='def unresolved: .disposition == "New" or .disposition == "Reviewing" or .disposition == "Confirmed";'
report() {
    printf '%s\n%s\n%s\n%s\n' "$state" "${2-null}" "${3-null}" "${4-null}" | jq -cs --arg status "$1" --argjson limit "$alert_limit" \
        --argjson query_limit "$query_limit" --argjson rules "$archive_rules" \
        --argjson previous "${#previous_logs[@]}" --arg socket "$socket_status" --arg selection "$evidence_selection" \
        --argjson advanced "$log_advanced" "$unresolved_jq"'
        def live_archive:
            if $status != "current" and $status != "degraded" then "unknown"
            elif .health.archive_enabled == false then "disabled"
            elif .health.archive_paused == true then "paused"
            elif .health.archive_enabled == true and .health.archive_paused == false then "enabled"
            else "unknown" end;
        def evidence_step:
            if . == "complete" then "inspect_retained_frames"
            elif . == "partial" then "inspect_retained_and_recover_missing_frames"
            elif . == "unavailable" then "locate_original_capture"
            elif . == "no_references" then "corroborate_with_host_or_service_logs"
            elif . == "check_failed" or . == "changed_during_review" or . == "check_timed_out" or . == "check_deferred" then "retry_evidence_check"
            else "verify_frame_availability" end;
        def with_evidence($checks):
            .alert_id as $id | (first($checks[] | select(.alert_id == $id)) // null) as $evidence
            | (if $evidence.status == "checked" then $evidence.frames | group_by(.status)
               | map({key:.[0].status,value:length}) | from_entries else null end) as $counts
            | (if $counts.complete == ($evidence.frames | length) and $counts != null then "complete"
               elif $counts.complete or $counts.truncated or $counts.length_unknown then "partial"
               elif $counts != null then "unavailable" elif .evidence_frame_count == 0 then "no_references"
               else (($evidence.status // "") | {alert_evidence_changed:"changed_during_review",unavailable:"check_failed",
                     timed_out:"check_timed_out",deferred:"check_deferred"}[.] // "not_checked") end) as $availability
            | . + {packet_evidence_status:$availability,evidence_availability:$counts,
                 next_evidence_step:(if $counts.unreadable then "check_archive_integrity"
                   else $availability | evidence_step end)}
            | if .socket_context != null then .socket_evidence = (if .earlier_socket_context != null then "latest_and_earlier" else "latest" end)
              elif .earlier_socket_context != null then .socket_evidence = "earlier" else . end;
        .[1] as $alerts
        | (.[2] // []) as $evidence
        | (if $alerts == null then null else $alerts[:$limit] |
            map(with_evidence($evidence)) end) as $sample
        | (if $alerts == null then null else [
            ("CRITICAL", "HIGH", "MEDIUM", "LOW") as $severity | $alerts | to_entries[]
            | (.key < $limit) as $recent | .value
            | select(.severity == $severity and unresolved)
            | ($severity == "MEDIUM" or $severity == "LOW") as $opt_in
            | select(($opt_in | not) or (.rule_id as $rule | any($rules[]; . == $rule)))
            | with_evidence($evidence)
            | {alert_id,title,rule_id,revision,severity,disposition,hit_count,confidence,verify,packet_evidence_status,evidence_frame_count,evidence_frame_set_sha256,
               archive_rule:$opt_in,in_recent_alerts:$recent,evidence_availability,next_evidence_step}
              + (if has("socket_evidence") then {socket_evidence} else {} end)
          ] end) as $review
        | .[0] + {record_type:"capture_triage", status:$status, alert_limit:$limit, previous_logs:$previous,
             live_packet_archive:(.[0] | live_archive),
             alerts:$sample, has_more_alerts:(if $alerts == null then null else ($alerts | length) > $limit end),
             priority_sample_limit:$query_limit, priority_sample_at_limit:.[3].stopped_at_limit,
             open_priority_alerts_in_sample:(if $review == null then null else $review | map(select(.archive_rule | not)) | length end),
             open_archive_rule_alerts_in_sample:(if $review == null then null else $review | map(select(.archive_rule)) | length end),
             review_queue_truncated:(if $review == null then null else ($review | length) > 5 end),
             review_queue:(if $review == null then null else $review[:5] end),
             evidence_selection:$selection, evidence_status:$evidence[0], evidence_checks:$evidence,
             alert_log_integrity:.[3], alert_log_advanced_during_review:$advanced, socket_context_status:$socket}
    '
}
report_saved_index() {
    jq -c --arg rule "$review_rule" --arg session "$session" --arg capture "$capture" --argjson limit "$query_limit" \
        --argjson previous "${#previous_logs[@]}" --argjson offset "$review_offset" --argjson advanced "$log_advanced" "$unresolved_jq"'
        def valid_session: .session_id | type == "string" and test("\\A[A-Za-z0-9_-]{1,128}\\z");
        def scoped: valid_session and (.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"));
        def seen: numbers | select(isfinite and . > 0);
        def priority: .severity | IN("HIGH","CRITICAL");
        def valid_alert_id: .alert_id | type == "number" and . >= 1 and . <= 999999999999999 and floor == .;
        def selected: if $rule == "" then priority else .rule_id == $rule and (.severity | IN("CRITICAL","HIGH","MEDIUM","LOW")) end;
        def review_rank: [({LOW:0,MEDIUM:1,HIGH:2,CRITICAL:3}[.severity]), ((.last_seen | seen) // 0), .session_id, .capture_id, .alert_id];
        .integrity as $integrity
        | (.alerts | map(select(scoped))) as $scoped | [.alerts[] | select((scoped | not) and priority and unresolved)] as $unscoped
        | ($scoped | map(select(selected and unresolved and valid_alert_id)) | sort_by(review_rank) | reverse) as $review
        | {
            record_type:"saved_capture_index", review_scope:(if $capture == "" then null else {session_id:$session,capture_id:$capture} end),
            status:(if $integrity.invalid_records == 0 and $integrity.oversized_records == 0
                and $integrity.stopped_at_scan_budget != true then "saved" else "saved_log_degraded" end),
            previous_logs:$previous, alert_sample_limit:$limit,
            sampled_alerts:(.alerts | length), sampled_unscoped_alerts:((.alerts | length) - ($scoped | length)),
            sampled_unscoped_open_high_or_critical:($unscoped | length),
            unscoped_review_queue:($unscoped | map(select(valid_session and valid_alert_id))
                | sort_by([(.severity == "CRITICAL"), ((.last_seen | seen) // 0), .session_id, .alert_id]) | reverse | .[:5]
                | map({session_id,alert_id,severity,disposition,last_seen:((.last_seen | seen) // null),
                       legacy_rule_hint:(.legacy_rule_hint | strings | select(test("\\A[a-z0-9_.-]{1,128}\\z"))) // null,
                       evidence_frame_count:(.evidence_frame_count | numbers | select(. >= 0 and . <= 131 and floor == .)) // null,
                       next_evidence_step:(if .evidence_frame_count == 0 then "corroborate_with_host_or_service_logs" else "locate_original_capture_or_host_logs" end)})),
            alert_log_advanced_during_review:$advanced,
            sample_scan_complete:($advanced == false and $integrity.invalid_records == 0 and $integrity.oversized_records == 0
                and $integrity.stopped_at_limit == false and $integrity.stopped_at_scan_budget != true),
            review_rule:(if $rule == "" then null else $rule end), review_offset:$offset, review_eligible_in_sample:($review | length),
            review_shortlist_truncated:($review | length > $offset + 5),
            next_review_offset:(if ($review | length) > $offset + 5 then $offset + 5 else null end),
            review_shortlist:($review[$offset:$offset + 5] | map({session_id,capture_id,alert_id,severity,disposition,rule_id,revision,confidence,evidence_frame_count,evidence_frame_set_sha256,last_seen})),
            alert_log_integrity:$integrity, review_latency:((.review_latency | objects | {sampled_alerts,measured_alerts,unmeasured_alerts,min_ms,median_ms,max_ms}) // null),
            captures:($scoped | group_by([.session_id, .capture_id]) | map(
              map(select(priority)) as $priority
              | ($priority | map(select(unresolved))) as $open | {
                session_id:.[0].session_id, capture_id:.[0].capture_id, sampled_alerts:length,
                sampled_high_or_critical:($priority | length), sampled_open_high_or_critical:($open | length),
                next_review_alert_id:($open | map(select(valid_alert_id)) | max_by(review_rank) | .alert_id),
                first_seen:([.[].first_seen | seen] | min), last_seen:([.[].last_seen | seen] | max)
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
        def context($alert; $time):
            [$snapshots[] | select(.session_id == $alert.session_id and .capture_id == $alert.capture_id
                and .alert_id == $alert.alert_id and .flow == $alert.flow and .flow.transport == "tcp"
                and (.alert_last_seen | type == "number" and isfinite and . > 0) and .alert_last_seen == $time)
                | .alert_last_seen as $when
                | .socket_context | objects
                | select(.status == "exact_tuple_snapshot" and (.tcp_state == null or .tcp_state == "ESTAB" or .tcp_state == "SYN-SENT")
                    and ((.local == $alert.flow.source and .peer == $alert.flow.destination)
                        or (.tcp_state != "SYN-SENT" and .local == $alert.flow.destination and .peer == $alert.flow.source))
                    and (.process | type == "string" and test("\\A[A-Za-z0-9_. -]{1,64}\\z"))
                    and (.pid | type == "number" and floor == . and . >= 1 and . <= 4294967295)
                    and ((try (.observed_at | fromdateiso8601) catch null)
                        | . != null and . >= ($when | floor) and . <= ($when | floor) + 8))
                | {status,observed_at,local,peer,process,pid,alert_last_seen:$when} + (if .tcp_state == "ESTAB" or .tcp_state == "SYN-SENT" then {tcp_state} else {} end)]
            | if (map([.local,.peer,.process,.pid]) | unique | length)==1 then max_by(.observed_at) else null end;
        map(. as $alert | context($alert; $alert.last_seen) as $latest
            | (if ([$alert.first_seen,$alert.last_seen] | all(.[]; type == "number" and isfinite)) and $alert.first_seen < $alert.last_seen
               then context($alert; $alert.first_seen) else null end) as $earlier
            | if $latest != null then .socket_context=$latest else . end
            | if $earlier != null then .earlier_socket_context=$earlier else . end)
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
verify_watch_identity() {
    jq -e --arg identity "$1" '
        .health | if .alert_watcher_open_log_required == true or $required then
            .alert_watcher_open_log_required == true
            and .alert_log_storage == "private" and .alert_watcher_source_matches == true
            and .alert_log_identity == $identity
        else .alert_log_storage != "unsafe" and .alert_log_storage != "unavailable" end
    ' --argjson required "$watch_identity_required" <<< "$state" >/dev/null || {
        report alert_log_watcher_unverified
        return 1
    }
}
log_stamp() {
    [[ -f $1 ]] && stat -L --format='%d:%i %s %y %z' -- "$1"
}
previous_log_stamps() {
    local path stamp
    for path in "${previous_logs[@]}"; do
        stamp=$(log_stamp "$path") || return 1
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
    response=$(timeout --kill-after=2s "${2}s" packrat-archive \
        "${evidence_args[@]}" "${previous_args[@]}") || return "$?"
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
    watch_identity_required=$(jq -c '.health.alert_watcher_open_log_required == true' <<< "$state")
elif [[ $mode == saved ]]; then
    state=$(jq -cn --arg session "$session" --arg capture "$capture" --arg target "$target_alert" '
        {mode:"saved",health:null,scope:{session_id:$session,capture_id:$capture}}
        | if $target == "" then . else .scope.alert_id = ($target | tonumber) end
    ')
else
    state='{"mode":"list_saved","health":null}'
fi
if [[ -n $capture ]]; then scope_args=(--session "$session" --capture-id "$capture"); fi
if ! initial_stamp=$(log_stamp "$alert_log") ||
   ! read -r log_identity log_size _ <<< "$initial_stamp" ||
   [[ ! $log_identity =~ ^[0-9]{1,20}:[0-9]{1,20}$ || ! $log_size =~ ^[0-9]+$ ]]; then
    report alert_log_unavailable
    exit 2
fi
if [[ $mode == live ]]; then verify_watch_identity "$log_identity" || exit 1; fi
if ! previous_stamps=$(previous_log_stamps); then
    report previous_log_unavailable
    exit 2
fi
read_status=0
raw_alerts=$(timeout --kill-after=2s "${read_timeout}s" packrat-archive \
    --alerts "$alert_log" "${scope_args[@]}" \
    "${limit_args[@]}" --report-integrity "${previous_args[@]}") || read_status=$?
case $read_status in
    124) report alert_log_read_timeout; exit 2 ;;
    137) report alert_log_read_interrupted; exit 2 ;;
esac
if (( read_status != 0 )) || ! history=$(jq -cse --argjson limit "$query_limit" '
    def count: type == "number" and isfinite and floor == . and . >= 0;
    select(length == 1) | .[0] | objects
    | select((.alerts | type == "array" and length <= $limit and all(.[]; type == "object"))
        and (.integrity | type == "object" and (.invalid_records | count)
            and (.oversized_records | count) and (.stopped_at_limit | type == "boolean")
            and (.stopped_at_scan_budget | . == null or type == "boolean"))
        and (.integrity.stopped_at_limit == ((.alerts | length) == $limit)))
' <<< "$raw_alerts"); then
    report alert_log_unavailable
    exit 2
fi
# Preserve stored labels in the log; use one vocabulary for triage and evidence selection.
alerts=$(jq -c '.alerts | map(.severity |=
    if . == "WARN" then "MEDIUM" elif . == "CRIT" then "CRITICAL" else . end)' <<< "$history")
integrity=$(jq -c '.integrity | {invalid_records,oversized_records,stopped_at_limit} + if .stopped_at_scan_budget == true then {stopped_at_scan_budget:true} else {} end' <<< "$history")
if [[ -n $capture ]] && ! jq -e --arg session "$session" --arg capture "$capture" --arg target "$target_alert" '
    all(.[]; type == "object" and .session_id == $session and .capture_id == $capture
        and ($target == "" or .alert_id == ($target | tonumber)))
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
evidence='[]' evidence_failed=false evidence_ids=()
if [[ -n $evidence_id ]]; then evidence_ids+=("$evidence_id"); fi
if jq -e '.health | .archive_enabled == true and (.archive_paused | type == "boolean")' <<< "$state" >/dev/null; then
    archive_rules=$(jq -c '.health | if .archive_alert_evidence_only == true and
        (.archive_evidence_rules | type == "array" and length <= 16 and all(.[];
            type == "string" and test("\\A[a-z0-9][a-z0-9_.-]{0,127}\\z")))
        then .archive_evidence_rules else [] end' <<< "$state")
    if [[ $auto_evidence == 1 ]]; then
        candidates=$(jq -r --argjson rules "$archive_rules" "$unresolved_jq"'
        limit(5; ("CRITICAL", "HIGH", "MEDIUM", "LOW") as $severity | .[]
            | select(.severity == $severity and unresolved
                and ($severity == "CRITICAL" or $severity == "HIGH"
                    or (.rule_id as $rule | any($rules[]; . == $rule)))
                and (.evidence_frame_count | type == "number" and . >= 1 and . <= 131 and floor == .))
            | .alert_id | select(type == "number" and . >= 1 and . <= 999999999999999 and floor == .))
        ' <<< "$alerts")
        if [[ -n $candidates ]]; then mapfile -t evidence_ids <<< "$candidates"; fi
    fi
fi
evidence_deadline=$((SECONDS + read_timeout))
for evidence_id in "${evidence_ids[@]}"; do
    remaining=$((evidence_deadline - SECONDS))
    check_status=deferred
    if (( remaining > 0 )); then
        check_status=''
        check=$(check_evidence "$alert_log" "$remaining") || case $? in
            124|137) check_status=timed_out ;; *) check_status=unavailable ;; esac
    fi
    if [[ -n $check_status ]]; then
        check=$(jq -cn --argjson id "$evidence_id" --arg status "$check_status" '{status:$status,alert_id:$id,frames:null}')
    fi
    if ! jq -e '.status == "checked"' <<< "$check" >/dev/null; then evidence_failed=true; fi
    evidence=$(jq -c --argjson check "$check" '. + [$check]' <<< "$evidence")
done
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
if ! latest_stamp=$(log_stamp "$alert_log") ||
   ! read -r latest_identity latest_size _ <<< "$latest_stamp" ||
   [[ $latest_identity != "$log_identity" || ! $latest_size =~ ^[0-9]+$ ]] ||
   (( latest_size < log_size )) ||
   { (( latest_size == log_size )) && [[ $latest_stamp != "$initial_stamp" ]]; }; then
    report alert_log_changed
    exit 1
fi
if ! latest_stamps=$(previous_log_stamps) || [[ $latest_stamps != "$previous_stamps" ]]; then
    report previous_log_changed
    exit 1
fi
[[ $mode != live ]] || verify_watch_identity "$latest_identity" || exit 1
log_advanced=false
if (( latest_size > log_size )); then log_advanced=true; fi
if [[ $mode == list_saved ]]; then
    index=$(report_saved_index)
    printf '%s\n' "$index"
    if jq -e '.status == "saved"' <<< "$index" >/dev/null; then exit 0; else exit 1; fi
fi
clean_status=current degraded_status=degraded
if [[ $mode == saved ]]; then clean_status=saved degraded_status=saved_log_degraded; fi
if { [[ $mode == saved ]] || jq -e '.health.issues == []' <<< "$state" >/dev/null; } &&
   jq -e '.invalid_records == 0 and .oversized_records == 0 and .stopped_at_scan_budget != true' <<< "$integrity" >/dev/null; then
    if [[ $mode == saved ]] && jq -e 'length == 0' <<< "$alerts" >/dev/null; then
        absent_status=saved_scope_not_observed
        if [[ -n $target_alert ]]; then absent_status=saved_alert_not_observed; fi
        report "$absent_status" "$alerts" "$evidence" "$integrity"
        exit 1
    fi
    report "$clean_status" "$alerts" "$evidence" "$integrity"
    if "$evidence_failed"; then exit 2; fi
else
    report "$degraded_status" "$alerts" "$evidence" "$integrity"
    exit 1
fi
