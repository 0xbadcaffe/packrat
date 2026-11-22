#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

snapshot_validation='
    def scope_id: if type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z") then . else null end;
    def valid_current:
        .status != "current" or (
            (.capture_id | scope_id) != null and (.session_id | scope_id) != null and
            (.packets | type == "number" and . >= 0 and . <= 9007199254740991 and floor == .) and
            .alert_saving == true and .issues == [] and (.recent_alerts | type == "array") and
            .alert_log_integrity.invalid_records == 0 and .alert_log_integrity.oversized_records == 0 and
            (.alert_log_integrity.stopped_at_scan_budget | . == false or . == null));
'

usage() {
    printf '%s\n' 'Usage: watch-packrat-triage.sh [--once|--supervise] STATE.json -- TRIAGE_COMMAND [ARG ...]' \
        '       watch-packrat-triage.sh --check STATE.json' \
        'The state file must be in a private directory owned by the current user.' \
        'Check prints snapshot freshness and exits 0 for current, 1 for unhealthy, or 2 for unreadable state.' \
        'Refreshes the sanitized state every poll; changes include alert observations for the same capture session.' \
        'alert_sample_gap warns that a burst may have exceeded the recent-alert sample; review saved history.' \
        'Supervision retries unexpected exits with backoff; configuration errors stop the supervisor.' \
        'PACKRAT_TRIAGE_WATCH_INTERVAL sets the poll interval in seconds (default: 30).' \
        'PACKRAT_TRIAGE_WATCH_TIMEOUT sets the triage command deadline in seconds (default: 25).'
}

once=false
check=false
supervise=false
case ${1-} in
    --help|-h) usage; exit 0 ;;
    --once) once=true; shift ;;
    --check) check=true; shift ;;
    --supervise) supervise=true; shift ;;
esac
if [[ ${1-} != /* || $1 == */ || $1 == *[[:cntrl:]]* ]] ||
   { "$check" && (( $# != 1 )); } ||
   { ! "$check" && { (( $# < 3 )) || [[ $2 != -- ]]; }; }; then
    usage >&2
    exit 2
fi
state=$1
directory=${state%/*}
if [[ -z $directory || ! -d $directory || -L $directory || ! -O $directory ||
      -L $state || -L $state.lock ||
      ( -e $state && ! -f $state ) || ( -e $state.lock && ! -f $state.lock ) ]] ||
   ! mode=$(stat --format='%a' -- "$directory") || [[ ! $mode =~ ^[0-7]{3,4}$ ]] ||
   (( (8#$mode & 077) != 0 )); then
    printf '%s\n' 'Triage state requires a private, owned directory and regular files.' >&2
    exit 2
fi
check_snapshot() {
    local raw result
    if [[ ! -e $state ]]; then
        printf '%s\n' '{"status":"snapshot_missing"}'
        return 2
    fi
    if [[ ! -r $state || ! -O $state ]] ||
       ! raw=$(head -c 131073 -- "$state" 2>/dev/null) ||
       (( ${#raw} > 131072 )) ||
       ! result=$(jq -cse "$snapshot_validation"'
        select(length == 1) | .[0] | objects
        | select(.record_type == "capture_triage_watch" and
            (.status | type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z")) and
            (.max_age_seconds | type == "number" and . >= 9 and . <= 200005 and floor == .) and valid_current)
        | (now - (.updated_at | fromdateiso8601) | floor) as $age
        | {status:(if $age < -5 then "snapshot_future"
                   elif $age > .max_age_seconds then "snapshot_stale"
                   elif .status == "current" then "current"
                   else "triage_unhealthy" end),
           triage_status:.status, age_seconds:$age, max_age_seconds,
           alert_sample_gap:(.alert_sample_gap | if type == "boolean" then . else null end),
           capture_id:(.capture_id | scope_id), session_id:(.session_id | scope_id)}' <<< "$raw" 2>/dev/null); then
        printf '%s\n' '{"status":"snapshot_invalid"}'
        return 2
    fi
    printf '%s\n' "$result"
    jq -e '.status == "current"' <<< "$result" >/dev/null
}

if "$check"; then
    command -v jq >/dev/null || { printf '%s\n' 'Missing dependency: jq' >&2; exit 2; }
    if check_snapshot; then exit 0; else exit "$?"; fi
fi
shift 2
interval=${PACKRAT_TRIAGE_WATCH_INTERVAL:-30}
deadline=${PACKRAT_TRIAGE_WATCH_TIMEOUT:-25}
if [[ ! $interval =~ ^[1-9][0-9]{0,4}$ || ! $deadline =~ ^[1-9][0-9]{0,4}$ ]]; then
    printf '%s\n' 'Triage interval and deadline must be positive seconds.' >&2
    exit 2
fi
for command in jq timeout flock; do
    command -v "$command" >/dev/null || { printf 'Missing dependency: %s\n' "$command" >&2; exit 2; }
done

supervise_watcher() {
    local child='' status delay=2 started
    # On termination, reap the current watcher or its retry timer.
    trap 'if [[ -n $child ]]; then kill "$child" 2>/dev/null || :; wait "$child" 2>/dev/null || :; fi; exit 0' HUP INT TERM
    while :; do
        started=$SECONDS
        bash "${BASH_SOURCE[0]}" "$state" -- "$@" &
        child=$!
        status=0
        wait "$child" || status=$?
        child=''
        if (( status == 2 )); then return 2; fi
        if (( SECONDS - started >= interval )); then delay=2; fi
        printf 'Triage watcher exited (%d); retrying in %d seconds.\n' "$status" "$delay" >&2
        sleep "$delay" &
        child=$!
        wait "$child"
        child=''
        delay=$((delay < 16 ? delay * 2 : 30))
    done
}

if "$supervise"; then
    supervise_watcher "$@"
    exit 0
fi
exec {lock_fd}>>"$state.lock"
flock -n "$lock_fd" || { printf '%s\n' 'Triage state is already being refreshed.' >&2; exit 2; }

sanitize() {
    jq -cse "$snapshot_validation"'
        def token: scope_id;
        def counter: if type == "number" and . >= 0 and . <= 9007199254740991 and floor == . then . else null end;
        def flag: if type == "boolean" then . else null end;
        def severity: if . == "CRITICAL" or . == "HIGH" or . == "MEDIUM" or . == "LOW" then . else null end;
        def disposition: if . == "New" or . == "Reviewing" or . == "Confirmed" or
            . == "Benign" or . == "Contained" or . == "Closed" then . else null end;
        def archive_mode:
            if .archive_enabled == false then "disabled"
            elif .archive_enabled != true then null
            elif .archive_alert_evidence_only == true then "alert_evidence"
            elif .archive_alert_evidence_only == false then "all_packets"
            else null end;
        def archive_rules:
            if type == "array" and length <= 16 and all(.[]; type == "string" and
                test("\\A[a-z0-9][a-z0-9_.-]{0,127}\\z")) then unique else null end;
        def archive_usage:
            if type != "object" then null else {
                frames:(.frames | counter), payload_bytes:(.payload_bytes | counter),
                max_frames:(.max_frames | counter), max_payload_bytes:(.max_payload_bytes | counter)
            } | if .frames == null or .payload_bytes == null or
                .max_frames <= 0 or .max_payload_bytes <= 0 then null else . end end;
        select(length == 1) | .[0] | objects
        | select(.record_type == "capture_triage" and (.status | token) != null)
        | select(.status != "current" or (.health.issues == [] and
            (.alert_log_integrity.stopped_at_scan_budget | . == false or . == null)))
        | {
            status, capture_id:(.health.capture_id | token), session_id:(.health.alert_session_id | token),
            interface:(.health.capture_interface | token),
            link_type:(.health.capture_link_type | counter),
            link_decodable:(.health.capture_link_decodable | flag),
            issues:(.health.issues | if type == "array" then .[:64] | map(token | select(. != null)) | unique else null end),
            packets:(.health.packets_total | counter), buffer_drops:(.health.pcap_buffer_drops | counter),
            truncated_frames:(.health.capture_truncated_frames | counter),
            alert_saving:(.health.alert_saving | flag), archive:(.live_packet_archive | token),
            archive_mode:(.health | archive_mode),
            archive_rule_ids:(.health | if archive_mode == "alert_evidence"
                then .archive_evidence_rules | archive_rules else null end),
            archive_usage:(.health.archive_usage | archive_usage),
            archive_pause_reason:(.health.archive_pause_reason | token),
            disk_free_mib:(.health.disk_free_mib | counter),
            alert_log_integrity:(.alert_log_integrity | if type == "object" then {
                invalid_records:(.invalid_records | counter),
                oversized_records:(.oversized_records | counter),
                stopped_at_limit:(.stopped_at_limit | flag),
                stopped_at_scan_budget:(.stopped_at_scan_budget | flag)
            } else null end),
            open_priority_alerts:(.open_priority_alerts_in_sample | counter),
            priority_sample_at_limit:(.priority_sample_at_limit | flag),
            evidence_check:(.evidence_status | if type == "object" then
                {alert_id:(.alert_id | counter), status:(.status | token)} else null end),
            recent_alerts_at_limit:(.alerts | if type == "array" then length > 50 else null end),
            has_older_alerts:(.has_more_alerts | flag),
            recent_alerts:(.alerts | if type == "array" then .[:50] | map(objects
                | {alert_id:(.alert_id | counter), severity:(.severity | severity), rule_id:(.rule_id | token),
                   disposition:(.disposition | disposition), hit_count:(.hit_count | counter),
                   packet_evidence_status:(.packet_evidence_status | token)}
                | select(.alert_id > 0 and .severity != null)) | sort_by(.alert_id) else null end),
            review_queue:(.review_queue | if type == "array" then .[:5] | map(objects
                | {alert_id:(.alert_id | counter), severity:(.severity | token), rule_id:(.rule_id | token),
                   confidence:(.confidence | token), packet_evidence_status:(.packet_evidence_status | token),
                   archive_rule:(.archive_rule | flag),
                   next_evidence_step:(.next_evidence_step | token)}
                | select(.alert_id > 0 and (.severity == "HIGH" or .severity == "CRITICAL" or
                    (.archive_rule == true and (.severity == "MEDIUM" or .severity == "LOW"))))) else null end)
          } | .archive_near_limit = (.archive_usage | if . == null then null else
                (.frames / .max_frames >= 0.9 or .payload_bytes / .max_payload_bytes >= 0.9) end)
            | select(valid_current)'
}

read_status() {
    local raw result status=0
    # A bad or noisy child must not leak its output or grow the snapshot without bound.
    raw=$(timeout --kill-after=2s "${deadline}s" "$@" 2>/dev/null | head -c 2097153) || status=$?
    if (( status == 124 || status == 137 )); then
        printf '%s\n' '{"status":"triage_timeout"}'
    elif (( ${#raw} <= 2097152 )) && result=$(sanitize <<< "$raw" 2>/dev/null); then
        printf '%s\n' "$result"
    else
        printf '%s\n' '{"status":"triage_unavailable"}'
    fi
}

temp=''
timer=''
trap 'if [[ -n $temp ]]; then rm -f -- "$temp"; fi' EXIT
trap 'if [[ -n $timer ]]; then kill "$timer" 2>/dev/null || :; wait "$timer" 2>/dev/null || :; fi; exit 0' HUP INT TERM
previous=''
prior=null
if ! "$once" && [[ -f $state && -O $state ]]; then
    # A restart can recover only a recent, bounded snapshot from this watcher.
    prior=$(head -c 65537 -- "$state" |
        jq -Rces "$snapshot_validation"'
            select(utf8bytelength <= 65536) | fromjson | objects
            | select(.record_type == "capture_triage_watch"
                and (.max_age_seconds | type == "number" and . >= 9 and . <= 200005 and floor == .)
                and valid_current)
            | (now - (.updated_at | fromdateiso8601) | floor) as $age
            | select($age >= -5 and $age <= .max_age_seconds)
            | .last_observed // .
            | select((.status == "current" or .status == "degraded") and
                (.capture_id | type == "string") and (.session_id | type == "string") and
                (.recent_alerts | type == "array" and length <= 50 and all(.[]; type == "object"
                    and (.alert_id | type == "number" and . > 0 and . <= 9007199254740991 and floor == .))))
            | {status,capture_id,session_id,recent_alerts,alert_sample_gap:(.alert_sample_gap == true),
                highest_observed_alert_id:(
                .highest_observed_alert_id | if type == "number" and . >= 0 and . <= 9007199254740991
                    and floor == . then . else null end)}
        ' 2>/dev/null) || prior=null
fi
while :; do
    # Poll commands and the timer must not hold the writer lock after a crash.
    snapshot=$(exec {lock_fd}>&-; read_status "$@")
    # Allow the poll interval, the next triage deadline, and timeout cleanup/scheduling.
    event=$(jq -c --argjson prior "$prior" --argjson max_age "$((interval + deadline + 7))" '
            def observed:
                (.status == "current" or .status == "degraded") and
                .capture_id != null and .session_id != null and (.recent_alerts | type == "array");
            . as $now
            | (($prior | observed) and observed and
               $prior.capture_id == .capture_id and $prior.session_id == .session_id) as $comparable
            | ([.recent_alerts[]?.alert_id] | max // 0) as $seen
            | ([$prior.highest_observed_alert_id, ($prior.recent_alerts | map(.alert_id)? | max)] | max // 0) as $high
            | . + {record_type:"capture_triage_watch", updated_at:(now | todateiso8601), max_age_seconds:$max_age,
                highest_observed_alert_id:(if $comparable then [$seen,$high] | max else $seen end),
                alert_sample_gap: if observed | not then null elif $comparable then
                    $prior.alert_sample_gap == true or (
                        (.recent_alerts_at_limit == true or .has_older_alerts == true) and
                        (([.recent_alerts[].alert_id] | min // 0) - $high > 1))
                else false end,
                alert_changes: if $comparable then
                    ($prior.recent_alerts | INDEX(.alert_id | tostring)) as $before
                    | {
                        newly_observed: [.recent_alerts[] | select(.alert_id > $high) | .alert_id],
                        updated: [
                            $now.recent_alerts[] as $item
                            | $before[$item.alert_id | tostring] as $old | select($old != null)
                            | {alert_id:$item.alert_id, fields:[
                                ("hit_count", "severity", "disposition", "packet_evidence_status") as $field
                                | select($old[$field] != $item[$field]) | $field]}
                            | select(.fields | length > 0)
                        ]
                    }
                else null end}
            | if (observed | not) and ($prior | observed) then
                .last_observed = ($prior | {
                    status,capture_id,session_id,highest_observed_alert_id,alert_sample_gap,
                    recent_alerts: [.recent_alerts[] | {alert_id,hit_count,severity,disposition,packet_evidence_status}]
                })
              else . end' <<< "$snapshot")
    snapshot=$(jq -c 'del(.alert_changes)' <<< "$event")
    temp=$(mktemp -- "$directory/.packrat-triage.XXXXXXXX")
    printf '%s\n' "$snapshot" >"$temp"
    mv -fT -- "$temp" "$state"
    temp=''
    if "$once"; then printf '%s\n' "$snapshot"; break; fi
    key=$(jq -c 'del(.updated_at, .packets, .disk_free_mib, .archive_usage, .highest_observed_alert_id, .last_observed)' <<< "$snapshot")
    if [[ $key != "$previous" ]]; then
        jq -c 'del(.last_observed)' <<< "$event"
        previous=$key
    fi
    prior=$(jq -c '.last_observed // .' <<< "$snapshot")
    sleep "$interval" {lock_fd}>&- &
    timer=$!
    wait "$timer"
    timer=''
done
