#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: watch-packrat-triage.sh [--once] STATE.json -- TRIAGE_COMMAND [ARG ...]' \
        '       watch-packrat-triage.sh --check STATE.json' \
        'The state file must be in a private directory owned by the current user.' \
        'Check prints snapshot freshness and exits 0 for current, 1 for unhealthy, or 2 for unreadable state.' \
        'Refreshes the sanitized state every poll; prints changes to health, the review queue, or recent alerts.' \
        'PACKRAT_TRIAGE_WATCH_INTERVAL sets the poll interval in seconds (default: 30).' \
        'PACKRAT_TRIAGE_WATCH_TIMEOUT sets the triage command deadline in seconds (default: 25).'
}

once=false
check=false
case ${1-} in
    --help|-h) usage; exit 0 ;;
    --once) once=true; shift ;;
    --check) check=true; shift ;;
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
       ! result=$(jq -cse '
        def scope_id: if type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z") then . else null end;
        select(length == 1) | .[0] | objects
        | select(.record_type == "capture_triage_watch" and
            (.status | type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z")) and
            (.max_age_seconds | type == "number" and . >= 9 and . <= 200005 and floor == .))
        | (now - (.updated_at | fromdateiso8601) | floor) as $age
        | {status:(if $age < -5 then "snapshot_future"
                   elif $age > .max_age_seconds then "snapshot_stale"
                   elif .status == "current" then "current"
                   else "triage_unhealthy" end),
           triage_status:.status, age_seconds:$age, max_age_seconds,
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
exec {lock_fd}>>"$state.lock"
flock -n "$lock_fd" || { printf '%s\n' 'Triage state is already being refreshed.' >&2; exit 2; }

sanitize() {
    jq -cse '
        def token: if type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z") then . else null end;
        def counter: if type == "number" and . >= 0 and . <= 9007199254740991 and floor == . then . else null end;
        def flag: if type == "boolean" then . else null end;
        def severity: if . == "CRITICAL" or . == "HIGH" or . == "MEDIUM" or . == "LOW" then . else null end;
        def disposition: if . == "New" or . == "Reviewing" or . == "Confirmed" or
            . == "Benign" or . == "Contained" or . == "Closed" then . else null end;
        select(length == 1) | .[0] | objects
        | select(.record_type == "capture_triage" and (.status | token) != null)
        | {
            status, capture_id:(.health.capture_id | token), session_id:(.health.alert_session_id | token),
            interface:(.health.capture_interface | token),
            link_type:(.health.capture_link_type | counter),
            link_decodable:(.health.capture_link_decodable | flag),
            issues:(.health.issues | if type == "array" then .[:64] | map(token | select(. != null)) | unique else null end),
            packets:(.health.packets_total | counter), buffer_drops:(.health.pcap_buffer_drops | counter),
            truncated_frames:(.health.capture_truncated_frames | counter),
            alert_saving:(.health.alert_saving | flag), archive:(.live_packet_archive | token),
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
                   next_evidence_step:(.next_evidence_step | token)}
                | select(.alert_id > 0 and (.severity == "HIGH" or .severity == "CRITICAL"))) else null end)
          }'
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
trap 'if [[ -n $temp ]]; then rm -f -- "$temp"; fi' EXIT
trap 'exit 0' INT TERM
previous=''
while :; do
    snapshot=$(read_status "$@")
    # Allow the poll interval, the next triage deadline, and timeout cleanup/scheduling.
    snapshot=$(jq -c --argjson max_age "$((interval + deadline + 7))" \
        '. + {record_type:"capture_triage_watch", updated_at:(now | todateiso8601), max_age_seconds:$max_age}' <<< "$snapshot")
    temp=$(mktemp -- "$directory/.packrat-triage.XXXXXXXX")
    printf '%s\n' "$snapshot" >"$temp"
    mv -fT -- "$temp" "$state"
    temp=''
    key=$(jq -c 'del(.updated_at, .packets, .disk_free_mib)' <<< "$snapshot")
    if [[ $key != "$previous" ]]; then
        printf '%s\n' "$snapshot"
        previous=$key
    fi
    "$once" && break
    sleep "$interval"
done
