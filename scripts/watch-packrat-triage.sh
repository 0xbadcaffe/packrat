#!/usr/bin/env bash
set -euo pipefail
umask 077; export LC_ALL=C
# shellcheck disable=SC2016
snapshot_validation='
    def scope_id: if type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z") then . else null end;
    def counter: if type == "number" and . >= 0 and . <= 9007199254740991 and floor == . then . else null end;
    def sample_count: counter | if . != null and . <= 50 then . else null end;
    def socket_status: if IN("not_configured","not_checked","not_recorded","available","unavailable") then . else null end;
    def flow_cache: if type == "object" then {retained_summaries:(.retained_summaries | counter),summary_evictions:(.summary_evictions | counter)}
        | if any(.[]; . == null) then null else . end else null end;
    def tcp_stream_cache: if type == "object" then {retained_streams,evicted_streams} | map_values(counter)
        | if any(.[]; . == null) then null else . end else null end;
    def dns_capacity: if type == "object" then
        {query_key_declines,query_candidate_declines,nxdomain_client_declines,external_resolver_pair_declines}
        | map_values(counter) | if any(.[]; . == null) then null else . end else null end;
    def dns_capacity_delta($before):
        . as $current | if $current == null or $before == null or any($current | keys[]; $current[.] < $before[.])
            then null else with_entries(.value -= $before[.key]) end;
    def archive_usage:
        if type != "object" then null else {
            frames:(.frames | counter), payload_bytes:(.payload_bytes | counter),
            max_frames:(.max_frames | counter), max_payload_bytes:(.max_payload_bytes | counter)
        } | if .frames == null or .payload_bytes == null or
            .max_frames <= 0 or .max_payload_bytes <= 0 then null else . end end;
    def near_archive_limit:
        if . == null then null else (.frames / .max_frames >= 0.9 or .payload_bytes / .max_payload_bytes >= 0.9) end;
    def evidence_failures:
        if type == "array" and length <= 5 and
            all(.[]; type == "object" and (.status | scope_id) != null)
        then map(.status | select(. != "checked")
            | if IN("alert_evidence_changed","outside_history_scan","trigger_snapshot_unverified",
                    "evidence_frame_set_mismatch","scan_budget_exhausted","timed_out","unavailable","deferred")
              then . else "other" end) else null end;
    def packet_evidence_counts: (.evidence_frame_count | counter) as $refs
        | if (.evidence_availability | type == "object" and length > 0 and
              all(to_entries[]; (.key | IN("complete","truncated","missing","length_unknown","unreadable"))
                  and (.value | counter | . != null and . > 0 and . <= 131)) and ([.[]] | add) == $refs and $refs <= 131)
          then {evidence_availability} else {} end;
    def valid_scope_and_log:
        (.capture_id | scope_id) != null and (.session_id | scope_id) != null and
        (.packets | counter) != null and
        .alert_saving == true and (.recent_alerts | type == "array") and
        .alert_log_integrity.invalid_records == 0 and .alert_log_integrity.oversized_records == 0 and
        (.alert_log_integrity.stopped_at_scan_budget | . == false or . == null);
    def valid_current:
        .status != "current" or (valid_scope_and_log and .issues == []);
    def log_scan_interrupted:
        .alert_log_integrity |
        ((.invalid_records | counter) // 0) > 0 or ((.oversized_records | counter) // 0) > 0
        or .stopped_at_scan_budget == true;
    def log_scan_complete:
        if log_scan_interrupted then false
        elif .alert_log_advanced_during_review == true then false
        elif .alert_log_integrity.stopped_at_limit == true then false
        elif .alert_log_advanced_during_review == false and .alert_log_integrity.stopped_at_limit == false
            and .alert_log_integrity.invalid_records == 0 and .alert_log_integrity.oversized_records == 0
            and (.alert_log_integrity.stopped_at_scan_budget | . == false or . == null)
        then true else null end;
    def alert_sample_ids($limit):
        if type == "array" and length <= $limit
            and all(.[]; type == "object" and (.alert_id | counter | . != null and . > 0))
        then map(.alert_id) | if length == (unique | length) then . else null end
        else null end;
    def alert_counts:
        (.recent_alerts | alert_sample_ids(50)) as $recent
        | (.review_queue | alert_sample_ids(5)) as $queue
        | (.highest_observed_alert_id | counter) as $highest
        | if (.status | IN("current","degraded")) and valid_scope_and_log
            and .alert_log_advanced_during_review == false
            and .invalid_alert_rows == 0 and .duplicate_alert_ids == 0
            and $recent != null and $queue != null and $highest != null
            and ((($recent + $queue) | max // 0) <= $highest)
          then {
            status:(if log_scan_complete == true and .alert_sample_gap == false
                    and .recent_alerts_at_limit == false and .has_older_alerts == false
                    and .review_queue_truncated == false and .priority_sample_at_limit == false
                    and ($recent | max // 0) == $highest and (($queue - $recent) | length) == 0
                then "complete" else "sampled" end),
            recent_sample_count:($recent | length),review_queue_sample_count:($queue | length),
            highest_observed_alert_id:$highest}
          else {status:"unverified"} end;
    def mark_backlog_loss:
        if ((.alert_save_backlog_dropped | counter) // 0) > 0 and (.status | IN("current","degraded"))
        then .status = "degraded"
             | .issues = ((.issues // []) + ["alert_backlog_snapshots_dropped"] | unique)
        else . end;
'
usage() {
    printf '%s\n' 'Usage: watch-packrat-triage.sh [--once|--supervise] STATE.json -- TRIAGE_COMMAND [ARG ...]' \
        '       watch-packrat-triage.sh --check STATE.json' \
        '       watch-packrat-triage.sh --history STATE.json' \
        'The state file must be in a private directory owned by the current user.' \
        'Check prints snapshot freshness and exits 0 for current, 1 for unhealthy, or 2 for unreadable state.' \
        'Check reports validated alert sample counts separately from capture health. A highest observed ID is not a total.' \
        'DNS capacity counters describe analysis limits, not packet loss. Deltas require comparable fresh readings.' \
        'TCP stream evictions describe lost reconstruction context, not packet loss.' \
        'Check includes current disk space and archive capacity without exposing storage paths.' \
        'socket_context_status describes the optional snapshot store, not capture health or per-alert attribution.' \
        'healthy_capture_seconds restarts after a packet counter regression; packet_counter_gap marks the affected capture.' \
        'Refreshes the sanitized state every poll; changes include alert observations for the same capture session.' \
        'review_queue_entries and review_queue_exits report bounded queue changes, not incident openings or inferred resolutions.' \
        'alert_sample_gap warns that the watcher may have missed alerts in a bounded sample; review saved history.' \
        'Continuous mode journals changes and quiet capture checkpoints in STATE.json.events.jsonl with one 1 MiB rotation.' \
        'Set PACKRAT_TRIAGE_WATCH_JOURNAL=0 to disable the journal and checkpoints.' \
        'journal_unconfirmed_events counts discarded events and events whose pending writes could not be confirmed after restart.' \
        'History emits retained journal events oldest first, or asks to retry if the journal changes during the read.' \
        'Supervision retries unexpected exits with backoff; configuration errors stop the supervisor.' \
        'PACKRAT_TRIAGE_WATCH_INTERVAL sets polling (default 30s); PACKRAT_TRIAGE_WATCH_CHECKPOINT_INTERVAL sets checkpoints (default 300s).' \
        'PACKRAT_TRIAGE_WATCH_TIMEOUT sets the triage command deadline in seconds (default: 25).'
}
once=false check=false read_only=false supervise=false
case ${1-} in
    --help|-h) usage; exit 0 ;;
    --once) once=true; shift ;;
    --check) check=true read_only=true; shift ;;
    --history) read_only=true; shift ;;
    --supervise) supervise=true; shift ;;
esac
if [[ ${1-} != /* || $1 == */ || $1 == *[[:cntrl:]]* ]] ||
   { "$read_only" && (( $# != 1 )); } ||
   { ! "$read_only" && { (( $# < 3 )) || [[ $2 != -- ]]; }; }; then
    usage >&2; exit 2
fi
state=$1 directory=${1%/*}
if [[ -z $directory || ! -d $directory || -L $directory || ! -O $directory ||
      -L $state || -L $state.lock ||
      ( -e $state && ! -f $state ) || ( -e $state.lock && ! -f $state.lock ) ]] ||
   ! mode=$(stat --format='%a' -- "$directory") || [[ ! $mode =~ ^[0-7]{3,4}$ ]] ||
   (( (8#$mode & 077) != 0 )); then
    printf '%s\n' 'Triage state requires a private, owned directory and regular files.' >&2; exit 2
fi
journal="$state.events.jsonl" journal_limit=1048576
journal_path_safe() {
    local path=$1 attrs
    [[ ! -L $path ]] || return 1
    [[ -e $path ]] || return 0
    [[ -f $path && -O $path ]] && attrs=$(stat --format='%a:%h' -- "$path") &&
        [[ $attrs =~ ^([0-7]{3,4}):1$ ]] && (( (8#${BASH_REMATCH[1]} & 077) == 0 ))
}
journal_fingerprint() {
    local path metadata size
    for path in "$journal.1" "$journal"; do
        journal_path_safe "$path" || return 1
        if [[ -f $path ]]; then
            metadata=$(stat --format='%s %d:%i:%y:%z' -- "$path") || return 1
            size=${metadata%% *}
            [[ $size =~ ^[0-9]{1,7}$ ]] && (( size <= journal_limit )) || return 1
            printf '%s\n' "$metadata"
        else
            printf '%s\n' '-'
        fi
    done
}
read_journal_history() {
    local before after records path
    if ! before=$(journal_fingerprint 2>/dev/null); then
        printf '%s\n' 'Triage journal is unsafe, unreadable, or over its size limit.' >&2; return 2
    fi
    local valid=true
    records=$(
        for path in "$journal.1" "$journal"; do
            if [[ -f $path ]]; then head -c "$((journal_limit + 1))" -- "$path" || exit 1; fi
        done | jq -Rc 'fromjson | if type == "object" and .record_type == "capture_triage_watch"
            and (.updated_at | type == "string") and (has("last_observed") | not)
            then . else error("invalid triage journal record") end'
    ) 2>/dev/null || valid=false
    if ! after=$(journal_fingerprint 2>/dev/null) || [[ $before != "$after" ]]; then
        printf '%s\n' 'Triage journal changed during the read; retry.' >&2
        return 1
    fi
    if ! "$valid"; then
        printf '%s\n' 'Triage journal contains invalid records.' >&2
        return 2
    fi
    if [[ -n $records ]]; then printf '%s\n' "$records"; fi
}
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
        | mark_backlog_loss | . as $snapshot | (.updated_at | fromdateiso8601) as $observed_at | (now - $observed_at | floor) as $age
        | (if $age >= -5 and $age <= .max_age_seconds then .evidence_checks | evidence_failures else null end) as $failures
        | {status:(if $age < -5 then "snapshot_future"
                   elif $age > .max_age_seconds then "snapshot_stale"
                   elif .packet_counter_regressed == true then "packet_counter_regressed"
                   elif .status == "current" then "current"
                   else "triage_unhealthy" end),
           triage_status:.status, age_seconds:$age, max_age_seconds, packets:(.packets | counter), flow_cache:(if $age >= -5 and $age <= .max_age_seconds then .flow_cache | flow_cache else null end),
           tcp_stream_cache:(if $age >= -5 and $age <= .max_age_seconds then .tcp_stream_cache | tcp_stream_cache else null end),
           tcp_stream_eviction_delta:(if $age >= -5 and $age <= .max_age_seconds and (.tcp_stream_cache | tcp_stream_cache) != null
               then .tcp_stream_eviction_delta | counter else null end),
           dns_capacity:(if $age >= -5 and $age <= .max_age_seconds then .dns_capacity | dns_capacity else null end),
           dns_capacity_delta:(if $age >= -5 and $age <= .max_age_seconds and (.dns_capacity | dns_capacity) != null
               then .dns_capacity_delta | dns_capacity else null end),
           storage:(if $age >= -5 and $age <= .max_age_seconds and (.status | IN("current","degraded")) then
               (.archive | if IN("enabled","paused","disabled") then . else null end) as $archive
               | (if $archive | IN("enabled","paused") then .archive_usage | archive_usage else null end) as $usage
               | {disk_free_mib:(.disk_free_mib | counter),
                  disk_space_low:(if (.disk_free_mib | counter) != null and (.issues | type) == "array"
                     then (.issues | index("disk_space_low") != null) else null end),
                  archive:$archive, archive_usage:$usage, archive_near_limit:($usage | near_archive_limit),
                  archive_pause_reason:(if $archive == "paused" and
                      (.archive_pause_reason | IN("frame_limit","byte_limit","disk_reserve","queue_unavailable","write_failed"))
                      then .archive_pause_reason else null end)}
               else null end),
           evidence_check_failures:($failures | if . == null then null else length end),
           evidence_check_failure_reasons:($failures | if . == null then null
               else group_by(.) | map({key:.[0],value:length}) | from_entries end),
           socket_context_status:(if $age >= -5 and $age <= .max_age_seconds
               then .socket_context_status | socket_status else null end),
           alert_save_failures:(if $age >= -5 and $age <= .max_age_seconds then .alert_save_failures | counter else null end),
           alert_save_backlog_dropped:(if $age >= -5 and $age <= .max_age_seconds then .alert_save_backlog_dropped | counter else null end),
           capture_queue_full_packets:(if $age >= -5 and $age <= .max_age_seconds then .capture_queue_full_packets | counter else null end),
           alert_log_scan_complete:(if $age >= -5 and $age <= .max_age_seconds then log_scan_complete else null end),
           alert_counts:(if $age >= -5 and $age <= .max_age_seconds and .packet_counter_regressed != true then alert_counts else null end),
           alert_log_advanced_during_review:(if $age >= -5 and $age <= .max_age_seconds
               then .alert_log_advanced_during_review | if type == "boolean" then . else null end else null end),
           invalid_alert_rows:(if $age >= -5 and $age <= .max_age_seconds
               then .invalid_alert_rows | sample_count else null end),
           duplicate_alert_ids:(if $age >= -5 and $age <= .max_age_seconds
               then .duplicate_alert_ids | sample_count else null end),
           packet_counter_gap:(.packet_counter_gap | if type == "boolean" then . else null end),
           poll_started_at:(.poll_started_at | if type == "number" and . > 0 and floor == .
                and . <= 9007199254740991 then . else null end),
           healthy_capture_seconds:(.healthy_capture_since | if $age >= -5 and $age <= $snapshot.max_age_seconds
               and $snapshot.status == "current" and $snapshot.packet_counter_regressed != true
               and type == "number" and floor == . and . > 0 and . <= $observed_at
               then $observed_at - . else null end),
           historical_drop_total:(if $age >= -5 and $age <= .max_age_seconds and .status == "degraded" and .packet_counter_regressed != true
              and valid_scope_and_log and .issues == ["pcap_buffer_drops"] and .buffer_drops_delta == 0
              then .buffer_drops | select(type == "number" and . > 0 and . <= 4294967295 and floor == .) // null
              else null end),
           journal_status:(.journal_status | if . == "current" or . == "write_failed" or
              . == "disabled" or . == "not_checked" then . else null end),
           journal_pending_events:(.journal_pending_events | counter | if . != null and . <= 16 then . else null end),
           journal_unconfirmed_events:(.journal_unconfirmed_events | counter),
           alert_sample_gap:(.alert_sample_gap | if type == "boolean" then . else null end),
           capture_id:(.capture_id | scope_id), session_id:(.session_id | scope_id)}' <<< "$raw" 2>/dev/null); then
        printf '%s\n' '{"status":"snapshot_invalid"}'
        return 2
    fi
    printf '%s\n' "$result"
    jq -e '.status == "current"' <<< "$result" >/dev/null
}
if "$read_only"; then
    command -v jq >/dev/null || { printf '%s\n' 'Missing dependency: jq' >&2; exit 2; }
    if "$check"; then check_snapshot; else read_journal_history; fi
    exit "$?"
fi
shift 2
interval=${PACKRAT_TRIAGE_WATCH_INTERVAL:-30}
deadline=${PACKRAT_TRIAGE_WATCH_TIMEOUT:-25}
journal_enabled=${PACKRAT_TRIAGE_WATCH_JOURNAL:-1} checkpoint_interval=${PACKRAT_TRIAGE_WATCH_CHECKPOINT_INTERVAL:-300}
if [[ ! $interval =~ ^[1-9][0-9]{0,4}$ || ! $deadline =~ ^[1-9][0-9]{0,4}$ || ! $checkpoint_interval =~ ^[1-9][0-9]{0,4}$ ]]; then
    printf '%s\n' 'Triage interval, deadline, and checkpoint interval must be positive seconds.' >&2
    exit 2
fi
if [[ $journal_enabled != 0 && $journal_enabled != 1 ]]; then
    printf '%s\n' 'PACKRAT_TRIAGE_WATCH_JOURNAL must be 0 or 1.' >&2
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
journal_failed=false journal_overflow=false journal_unconfirmed=0 journal_writer='' journal_sequence=0
if [[ $journal_enabled == 1 ]] && ! "$once"; then journal_writer="$BASHPID-$(date -u +%s%N)"; fi
pending_journal=()
append_journal() (
    local size=0 line=$1 staged rotate=false
    journal_path_safe "$journal" && journal_path_safe "$journal.1" || return 1
    (( ${#line} + 1 <= journal_limit )) || return 1
    if [[ -f $journal ]]; then
        size=$(stat --format='%s' -- "$journal") || return 1
        [[ $size =~ ^[0-9]{1,7}$ ]] && (( size <= journal_limit )) || return 1
        (( size == 0 )) || [[ $(tail -c1 -- "$journal" | od -An -tu1) =~ ^[[:space:]]*10$ ]] || return 1
    fi
    if (( size + ${#line} + 1 > journal_limit )); then rotate=true; fi
    staged=$(mktemp -- "$directory/.packrat-journal.XXXXXXXX") || return 1
    trap 'rm -f -- "$staged"' EXIT
    if ! "$rotate" && (( size > 0 )); then cp -- "$journal" "$staged" || return 1; fi
    printf '%s\n' "$line" >>"$staged" || return 1
    if "$rotate"; then mv -fT -- "$journal" "$journal.1" || return 1; fi
    mv -fT -- "$staged" "$journal"
)
flush_journal() {
    while (( ${#pending_journal[@]} > 0 )); do
        if ! append_journal "${pending_journal[0]}"; then
            if ! "$journal_failed"; then
                printf '%s\n' 'Triage event journal write failed; live monitoring continues.' >&2
                journal_failed=true
            fi
            return 0
        fi
        pending_journal=("${pending_journal[@]:1}")
    done
    journal_failed=false journal_overflow=false
}
sanitize() {
    jq -cse "$snapshot_validation"'
        def token: scope_id;
        def flag: if type == "boolean" then . else null end;
        def severity: if . == "WARN" then "MEDIUM" elif . == "CRIT" then "CRITICAL"
            elif IN("CRITICAL","HIGH","MEDIUM","LOW","INFO") then . else null end;
        def disposition: if IN("New","Reviewing","Confirmed","Benign","Contained","Closed") then . else null end;
        def evidence: if (.evidence_frame_set_sha256 | type == "string" and test("\\A[0-9a-f]{64}\\z"))
            and (.evidence_frame_count | counter | . != null and . <= 131)
            then {evidence_frame_count,evidence_frame_set_sha256} + packet_evidence_counts else {} end;
        def alert_fields:
            {alert_id:(.alert_id | counter), severity:(.severity | severity), rule_id:(.rule_id | token),
             disposition:(.disposition | disposition), hit_count:(.hit_count | counter),
             packet_evidence_status:(.packet_evidence_status | token), revision} + evidence
             + (if .socket_evidence | IN("latest","earlier","latest_and_earlier") then {socket_evidence} else {} end)
            | if .rule_id != null and (.revision | type == "number" and . >= 1 and . <= 65535 and floor == .) then . else del(.revision) end;
        def recent_sample:
            if type != "array" then {recent_alerts:null,invalid_alert_rows:null,duplicate_alert_ids:null}
            else .[:50] as $rows
                | [$rows[] | objects | alert_fields | select(.alert_id > 0 and .severity != null)] as $valid
                | ($valid | group_by(.alert_id)) as $groups
                | {recent_alerts:[$groups[] | select(length == 1) | .[0]],
                   invalid_alert_rows:(($rows | length) - ($valid | length)),
                   duplicate_alert_ids:([$groups[] | select(length > 1)] | length)}
            end;
        def archive_mode:
            if .archive_enabled == false then "disabled"
            elif .archive_enabled != true then null
            elif .archive_alert_evidence_only == true then "alert_evidence"
            elif .archive_alert_evidence_only == false then "all_packets"
            else null end;
        def archive_rules:
            if type == "array" and length <= 16 and all(.[]; type == "string" and
                test("\\A[a-z0-9][a-z0-9_.-]{0,127}\\z")) then unique else null end;
        select(length == 1) | .[0] | objects
        | select(.record_type == "capture_triage" and (.status | token) != null)
        | select(.status != "current" or (.health.issues == [] and
            (.alert_log_integrity.stopped_at_scan_budget | . == false or . == null)))
        | (.alerts | recent_sample) as $sample
        | (.health | if archive_mode == "alert_evidence"
            then .archive_evidence_rules | archive_rules else null end) as $archive_rule_ids
        | {
            status, capture_id:(.health.capture_id | token), session_id:(.health.alert_session_id | token),
            interface:(.health.capture_interface | token),
            link_type:(.health.capture_link_type | counter),
            link_decodable:(.health.capture_link_decodable | flag),
            issues:(.health.issues | if type == "array" then .[:64] | map(token | select(. != null)) | unique else null end),
            packets:(.health.packets_total | counter), buffer_drops:(.health.pcap_buffer_drops | counter), flow_cache:(.health.flow_cache | flow_cache),
            tcp_stream_cache:(if (.status | IN("current","degraded")) and .health.telemetry_fresh == true and .health.capture_active == true
                then .health.tcp_stream_cache | tcp_stream_cache else null end),
            dns_capacity:(if (.status | IN("current","degraded")) and .health.telemetry_fresh == true and .health.capture_active == true
                then .health.dns_capacity | dns_capacity else null end),
            capture_queue_full_packets:(.health.capture_queue_full_packets | counter),
            capture_queue_full_packets_delta:(.health.capture_queue_full_packets_delta | counter),
            truncated_frames:(.health.capture_truncated_frames | counter),
            alert_saving:(.health.alert_saving | flag), archive:(.live_packet_archive | token),
            alert_save_failures:(.health.alert_save_failures | counter),
            alert_save_backlog_dropped:(.health.alert_save_backlog_dropped | counter),
            archive_mode:(.health | archive_mode),
            archive_rule_ids:$archive_rule_ids,
            archive_usage:(.health.archive_usage | archive_usage),
            archive_pause_reason:(.health.archive_pause_reason | token),
            disk_free_mib:(.health.disk_free_mib | counter),
            alert_log_integrity:(.alert_log_integrity | if type == "object" then {
                invalid_records:(.invalid_records | counter),
                oversized_records:(.oversized_records | counter),
                stopped_at_limit:(.stopped_at_limit | flag),
                stopped_at_scan_budget:(.stopped_at_scan_budget | flag)
            } else null end),
            alert_log_advanced_during_review:(.alert_log_advanced_during_review | flag),
            open_priority_alerts:(.open_priority_alerts_in_sample | counter),
            open_archive_rule_alerts:(.open_archive_rule_alerts_in_sample | counter),
            review_queue_truncated:(.review_queue_truncated | flag),
            priority_sample_at_limit:(.priority_sample_at_limit | flag),
            socket_context_status:(.socket_context_status | socket_status),
            evidence_check:(.evidence_status | if type == "object" then
                {alert_id:(.alert_id | counter), status:(.status | token)} else null end),
            evidence_checks:(.evidence_checks | if type == "array" then .[:5] | map(objects
                | {alert_id:(.alert_id | counter), status:(.status | token)} | select(.alert_id > 0 and .status != null))
                else null end),
            recent_alerts_at_limit:(.alerts | if type == "array" then length > 50 else null end),
            has_older_alerts:(.has_more_alerts | flag),
            review_queue:(.review_queue | if type == "array" then .[:5] | map(objects
                | alert_fields + {confidence:(.confidence | token),
                   archive_rule:(.archive_rule | flag), in_recent_alerts:(.in_recent_alerts | flag),
                   next_evidence_step:(.next_evidence_step | token)}
                | select(.alert_id > 0 and (.severity == "HIGH" or .severity == "CRITICAL" or
                    (.archive_rule == true and ((.severity | IN("MEDIUM","LOW")) or
                        (.severity == "INFO" and (.rule_id as $id | any($archive_rule_ids[]?; . == $id)))))))) else null end)
          } + $sample | .archive_near_limit = (.archive_usage | near_archive_limit)
            | select(valid_current) | mark_backlog_loss'
}
read_status() {
    local raw result status=0
    # Bound the reader too: a helper may still hold the pipe after the command exits.
    raw=$(timeout --kill-after=2s "${deadline}s" bash -o pipefail -c '"$@" | head -c 2097153' triage "$@" 2>/dev/null) || status=$?
    if (( status == 124 || status == 137 )); then
        printf '%s\n' '{"status":"triage_timeout"}'
    # The triage command uses 1 for degraded reports and 2 for failed evidence reads.
    elif (( status <= 2 && ${#raw} <= 2097152 )) && result=$(sanitize <<< "$raw" 2>/dev/null); then
        printf '%s\n' "$result"
    else
        printf '%s\n' '{"status":"triage_unavailable"}'
    fi
}
temp='' timer=''
trap 'if [[ -n $temp ]]; then rm -f -- "$temp"; fi' EXIT
trap 'if [[ -n $timer ]]; then kill "$timer" 2>/dev/null || :; wait "$timer" 2>/dev/null || :; fi; exit 0' HUP INT TERM
publish_snapshot() {
    snapshot=$(jq -c --arg journal_status "$1" --argjson pending "${#pending_journal[@]}" \
        --argjson unconfirmed "$journal_unconfirmed" '
        . + {journal_status:$journal_status,journal_pending_events:$pending,
            journal_unconfirmed_events:$unconfirmed}' <<< "$snapshot")
    temp=$(mktemp -- "$directory/.packrat-triage.XXXXXXXX")
    printf '%s\n' "$snapshot" >"$temp"
    mv -fT -- "$temp" "$state"
    temp=''
}
previous='' next_checkpoint=0 prior=null
if [[ -f $state && -O $state ]]; then
    # A stale snapshot can still identify alerts already seen in the same capture.
    saved=$(head -c 65537 -- "$state" |
        jq -Rces "$snapshot_validation"'
            select(utf8bytelength <= 65536) | fromjson | objects
            | select(.record_type == "capture_triage_watch"
                and (.max_age_seconds | type == "number" and . >= 9 and . <= 200005 and floor == .)
                and valid_current)
            | mark_backlog_loss | (now - (.updated_at | fromdateiso8601) | floor) as $age
            | select($age >= -5)
            | {fresh:($age <= .max_age_seconds), snapshot:.}
        ' 2>/dev/null) || saved=null
    # The previous process no longer holds the lock. It cannot retry its in-memory queue.
    journal_unconfirmed=$(jq -r '
        def bounded($max): if type == "number" and . >= 0 and . <= $max and floor == . then . else 0 end;
        .snapshot | [9007199254740991, ((.journal_unconfirmed_events | bounded(9007199254740991))
            + (.journal_pending_events | bounded(16)))] | min
        ' <<< "$saved")
    prior=$(jq -ce "$snapshot_validation"'
            .fresh as $fresh | .snapshot
            | .last_observed // .
            | select((.status == "current" or .status == "degraded") and
                (.capture_id | type == "string") and (.session_id | type == "string") and
                (.recent_alerts | type == "array" and length <= 50 and all(.[]; type == "object"
                    and (.alert_id | type == "number" and . > 0 and . <= 9007199254740991 and floor == .))))
            | {status,capture_id,session_id,recent_alerts,alert_sample_gap:(.alert_sample_gap == true),
                packets:(.packets | counter),packet_counter_gap:(.packet_counter_gap == true),
                tcp_stream_cache:(if $fresh then .tcp_stream_cache | tcp_stream_cache else null end),
                dns_capacity:(if $fresh then .dns_capacity | dns_capacity else null end),
                capture_queue_full_packets:(.capture_queue_full_packets | counter),
                buffer_drops:(.buffer_drops | if $fresh and type == "number" and . >= 0 and . <= 4294967295
                    and floor == . then . else null end),
                review_queue:(.review_queue | if type == "array" and length <= 5 then
                    map(objects | select(.alert_id | type == "number" and . > 0 and . <= 9007199254740991 and floor == .))
                    else [] end),
                poll_started_at, healthy_capture_since:(if $fresh then .healthy_capture_since else null end),
                highest_observed_alert_id:(
                .highest_observed_alert_id | if type == "number" and . >= 0 and . <= 9007199254740991
                    and floor == . then . else null end)}
        ' <<< "$saved") || prior=null
fi
while :; do
    # Poll commands and the timer must not hold the writer lock after a crash.
    poll_started_at=$(date -u +%s)
    snapshot=$(exec {lock_fd}>&-; read_status "$@")
    # Allow the poll interval, the next triage deadline, and timeout cleanup/scheduling.
    event=$(jq -c --argjson prior "$prior" --argjson started "$poll_started_at" --argjson max_age "$((interval + deadline + 7))" "$snapshot_validation"'
            def observed:
                (.status == "current" or .status == "degraded") and
                .capture_id != null and .session_id != null and (.recent_alerts | type == "array");
            def alert_index: ((.review_queue // []) + .recent_alerts) | INDEX(.alert_id | tostring);
            def alert_ids: [((.review_queue // []) + (.recent_alerts // []))[] | .alert_id] | unique;
            def queue_index: .review_queue | INDEX(.alert_id | tostring);
            def queue_comparable($prior): (.review_queue | type) == "array" and ($prior.review_queue | type) == "array";
            def compact_alert: {alert_id,hit_count,severity,disposition,packet_evidence_status,revision,evidence_frame_count,evidence_frame_set_sha256}
                + packet_evidence_counts + (if .socket_evidence | IN("latest","earlier","latest_and_earlier") then {socket_evidence} else {} end);
            def queue_entries($prior):
                if queue_comparable($prior) | not then []
                else ($prior | queue_index) as $queued
                | ($prior.recent_alerts | INDEX(.alert_id | tostring)) as $recent
                | ([.review_queue[].alert_id] | unique)
                | map(. as $id | ($id | tostring) as $key | select($queued[$key] == null)
                    | {alert_id:$id, previously_in_recent_sample:($recent[$key] != null)})
                end;
            def queue_exits($prior):
                if queue_comparable($prior) | not then []
                else queue_index as $queued
                | alert_index as $current
                | ([$prior.review_queue[].alert_id] | unique) as $previous_ids
                | [$previous_ids[] | . as $id | ($id | tostring) as $key
                    | select($queued[$key] == null)
                    | $current[$key] as $item
                    | {alert_id:$id, disposition:$item.disposition,
                        outcome:(if $item == null then "not_in_sample"
                            elif $item.disposition == "Benign" or $item.disposition == "Contained"
                                or $item.disposition == "Closed" then "resolved"
                            else "still_in_recent_sample" end)}]
                end;
            (($prior | observed) and observed and
               $prior.capture_id == .capture_id and $prior.session_id == .session_id) as $comparable
            | (if $comparable and .capture_queue_full_packets != null and $prior.capture_queue_full_packets != null
               then if .capture_queue_full_packets > $prior.capture_queue_full_packets then "capture_queue_packets_dropped"
                    elif .capture_queue_full_packets < $prior.capture_queue_full_packets then "capture_queue_counter_regressed"
                    else null end
               else null end) as $queue_issue
            | if $queue_issue != null then .status = "degraded" | .issues = ((.issues // []) + [$queue_issue] | unique) else . end
            | . as $now
            | ($comparable and .packets != null and $prior.packets != null and .packets < $prior.packets) as $regressed
            | ($comparable and ($regressed | not) and ($prior.poll_started_at | type == "number"
                  and . <= $started and $started - . <= $max_age)) as $fresh_counters
            | alert_ids as $ids | ($ids[-1] // 0) as $seen
            | ([$prior.highest_observed_alert_id, ($prior | alert_ids | last)] | max // 0) as $high
            | (.recent_alerts_at_limit == true or .has_older_alerts == true) as $truncated
            | (log_scan_complete == true and .recent_alerts_at_limit == false and .has_older_alerts == false
                and ((($prior | alert_ids) - $ids) | length > 0)) as $lost_from_complete_sample
            | ((.invalid_alert_rows // 0) > 0 or (.duplicate_alert_ids // 0) > 0 or log_scan_interrupted) as $invalid_sample
            | [$ids[] | select(. > $high)] as $new_ids
            | . + {record_type:"capture_triage_watch", updated_at:(now | todateiso8601), max_age_seconds:$max_age,
                poll_started_at:$started,
                packet_counter_regressed:(if observed then $regressed else null end),
                packet_counter_gap:(if observed then $regressed or ($comparable and $prior.packet_counter_gap == true) else null end),
                healthy_capture_since:(if .status != "current" or $regressed then null elif $comparable and $prior.status == "current"
                    and ($prior.poll_started_at | type == "number" and . <= $started and $started - . <= $max_age)
                    and ($prior.healthy_capture_since | type == "number" and . > 0 and . <= $prior.poll_started_at)
                    then $prior.healthy_capture_since else $started end),
                buffer_drops_delta:(if $comparable and .buffer_drops != null and $prior.buffer_drops != null
                    and .buffer_drops >= $prior.buffer_drops then .buffer_drops - $prior.buffer_drops else null end),
                dns_capacity_delta:(if $fresh_counters then .dns_capacity | dns_capacity_delta($prior.dns_capacity) else null end),
                tcp_stream_eviction_delta:(if $fresh_counters and .tcp_stream_cache != null and $prior.tcp_stream_cache != null
                    and .tcp_stream_cache.evicted_streams >= $prior.tcp_stream_cache.evicted_streams
                    then .tcp_stream_cache.evicted_streams - $prior.tcp_stream_cache.evicted_streams else null end),
                highest_observed_alert_id:(if $comparable then [$seen,$high] | max else $seen end),
                alert_sample_gap: if observed | not then null elif $invalid_sample then true elif $comparable and $high > 0 then
                    $prior.alert_sample_gap == true or $seen < $high or $lost_from_complete_sample or ($seen - $high > ($new_ids | length))
                else ($comparable and $prior.alert_sample_gap == true) or $truncated
                    or ($seen - ($ids[0] // 1) + 1 > ($ids | length)) end,
                alert_changes: if $comparable then
                    ($prior | alert_index) as $before
                    | {
                        newly_observed: $new_ids,
                        review_queue_entries: ($now | queue_entries($prior)),
                        review_queue_exits: ($now | queue_exits($prior)),
                        updated: [
                            ($now | alert_index | [.[]] | sort_by(.alert_id))[] as $item
                            | $before[$item.alert_id | tostring] as $old | select($old != null)
                            | {alert_id:$item.alert_id, fields:[
                                ("hit_count", "severity", "disposition", "packet_evidence_status", "revision", "evidence_frame_set_sha256","evidence_availability","socket_evidence") as $field
                                | select($old[$field] != $item[$field] and
                                    (($field | IN("revision","evidence_frame_set_sha256","evidence_availability") | not) or ($old[$field] != null and $item[$field] != null)))
                                | if $field == "evidence_frame_set_sha256" then "evidence" else $field end]} | select(.fields | length > 0)
                        ]
                    }
                else null end}
            | if (observed | not) and ($prior | observed) then
                .last_observed = ($prior | {
                    status,capture_id,session_id,highest_observed_alert_id,alert_sample_gap,packets,packet_counter_gap,capture_queue_full_packets,
                    review_queue: [(.review_queue // [])[] | compact_alert], recent_alerts: [.recent_alerts[] | compact_alert]
                })
              else . end' <<< "$snapshot")
    snapshot=$(jq -c 'del(.alert_changes)' <<< "$event")
    if "$once"; then publish_snapshot not_checked; printf '%s\n' "$snapshot"; break; fi
    key=$(jq -c 'del(.updated_at, .poll_started_at, .packets, .disk_free_mib, .archive_usage, .flow_cache, .highest_observed_alert_id,
        .last_observed, .buffer_drops_delta, .capture_queue_full_packets_delta, .dns_capacity_delta,
        .tcp_stream_cache.retained_streams, .tcp_stream_eviction_delta)' <<< "$snapshot")
    checkpoint=false
    if [[ $key == "$previous" && $journal_enabled == 1 ]] && (( SECONDS >= next_checkpoint )); then
        checkpoint=$(jq -c '(.status == "current" or .status == "degraded") and .capture_id != null and .session_id != null and .packets != null' <<< "$snapshot")
    fi
    if [[ $key != "$previous" ]] || "$checkpoint"; then
        journal_sequence=$((journal_sequence + 1))
        if [[ $journal_enabled == 1 ]] && (( ${#pending_journal[@]} >= 16 )); then
            flush_journal
            if (( ${#pending_journal[@]} >= 16 )); then
                pending_journal=("${pending_journal[@]:1}")
                if (( journal_unconfirmed < 9007199254740991 )); then
                    journal_unconfirmed=$((journal_unconfirmed + 1))
                fi
                if ! "$journal_overflow"; then
                    printf '%s\n' 'Triage event journal backlog full; oldest pending event discarded.' >&2
                    journal_overflow=true
                fi
            fi
        fi
        event=$(jq -c --argjson checkpoint "$checkpoint" --arg writer "$journal_writer" --argjson sequence "$journal_sequence" \
            --argjson unconfirmed "$journal_unconfirmed" '
            del(.last_observed) | if $checkpoint then . + {checkpoint:true,alert_changes:null} else . end
            | if $writer == "" then . else . + {journal_writer:$writer,journal_sequence:$sequence,
                journal_unconfirmed_events:$unconfirmed} end' <<< "$event")
        if [[ $journal_enabled == 1 ]]; then pending_journal+=("$event"); fi
        if ! "$checkpoint"; then printf '%s\n' "$event"; fi
        previous=$key next_checkpoint=$((SECONDS + checkpoint_interval))
    fi
    journal_status=disabled
    if [[ $journal_enabled == 1 ]]; then
        if (( ${#pending_journal[@]} > 0 )); then flush_journal; fi
        if "$journal_failed"; then journal_status=write_failed; else journal_status=current; fi
    fi
    publish_snapshot "$journal_status"
    prior=$(jq -c '.last_observed // .' <<< "$snapshot")
    sleep "$interval" {lock_fd}>&- &
    timer=$!
    wait "$timer"
    timer=''
done
