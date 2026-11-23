#!/usr/bin/env bash
set -uo pipefail

usage() {
    printf '%s\n' 'Usage: bash watch-packrat-health.sh [--once]' \
        'Environment: PACKRAT_HEALTH_PORT (9477), PACKRAT_HEALTH_INTERVAL (15 seconds),' \
        'PACKRAT_HEALTH_HEARTBEAT (300 seconds between unchanged reports; 0 disables),' \
        'PACKRAT_HEALTH_STATE_FILE (optional absolute path refreshed every poll),' \
        'PACKRAT_EXPECT_INTERFACE (optional expected live capture interface),' \
        'PACKRAT_EXPECT_TRAFFIC_SECS (warn after this long without packet counter progress; 0 disables),' \
        'PACKRAT_ALERT_SESSION (optional tmux session),' \
        'PACKRAT_DISK_PATH (defaults to the alert log directory, or / without a log path),' \
        'PACKRAT_DISK_SUDO (1 retries an inaccessible disk path with noninteractive sudo),' \
        'PACKRAT_ALERT_PIPELINE (1 checks the alert session tail and jq processes),' \
        'PACKRAT_ALERT_LOG (optional absolute alert path; requires pipeline checking),' \
        'PACKRAT_ALERT_LOG_OWNER_UID (optional expected numeric owner of the private alert log),' \
        'PACKRAT_ALERT_VERIFY_OPEN (1 verifies the open file and pipe; uses noninteractive sudo if needed),' \
        'PACKRAT_ALERT_CONTEXT_WATCHER (optional absolute Bash script path; requires open-pipe verification),' \
        'PACKRAT_REQUIRE_ARCHIVE (1 requires active archiving; alert-evidence also verifies selective retention),' \
        'PACKRAT_MIN_FREE_MIB (512). Health requests always use IPv4 loopback.'
}
once=false
case ${1-} in
    '') ;;
    --once) once=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then usage >&2; exit 2; fi
port=${PACKRAT_HEALTH_PORT:-9477}
interval=${PACKRAT_HEALTH_INTERVAL:-15}
heartbeat=${PACKRAT_HEALTH_HEARTBEAT:-300}
state_file=${PACKRAT_HEALTH_STATE_FILE:-}
expected_interface=${PACKRAT_EXPECT_INTERFACE:-}
expect_traffic=${PACKRAT_EXPECT_TRAFFIC_SECS:-0}
alert_session=${PACKRAT_ALERT_SESSION:-}
alert_pipeline=${PACKRAT_ALERT_PIPELINE:-0}
alert_log=${PACKRAT_ALERT_LOG:-}
alert_log_owner=${PACKRAT_ALERT_LOG_OWNER_UID:-}
alert_verify_open=${PACKRAT_ALERT_VERIFY_OPEN:-0}
alert_context_watcher=${PACKRAT_ALERT_CONTEXT_WATCHER:-}
require_archive=${PACKRAT_REQUIRE_ARCHIVE:-0}
disk_path=${PACKRAT_DISK_PATH:-}
disk_sudo=${PACKRAT_DISK_SUDO:-0}
min_free=${PACKRAT_MIN_FREE_MIB:-512}
if [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )) ||
   [[ ! $interval =~ ^[1-9][0-9]{0,5}$ ]] ||
   [[ ! $heartbeat =~ ^(0|[1-9][0-9]{0,5})$ ]] ||
   [[ ! $min_free =~ ^(0|[1-9][0-9]{0,8})$ ]]; then
    printf '%s\n' 'Invalid health port, polling interval, heartbeat, or free-space threshold.' >&2
    exit 2
fi
if [[ -n $state_file && ( $state_file != /* || $state_file == */ ) ]]; then
    printf '%s\n' 'PACKRAT_HEALTH_STATE_FILE requires an absolute file path.' >&2
    exit 2
fi
if [[ ${#expected_interface} -gt 256 || $expected_interface == *[[:cntrl:]]* ]]; then
    printf '%s\n' 'Invalid PACKRAT_EXPECT_INTERFACE value.' >&2
    exit 2
fi
if [[ ! $expect_traffic =~ ^(0|[1-9][0-9]{0,5})$ ]]; then
    printf '%s\n' 'PACKRAT_EXPECT_TRAFFIC_SECS must be between 0 and 999999.' >&2
    exit 2
fi
for dependency in curl jq df; do
    if ! command -v "$dependency" >/dev/null; then
        printf 'Missing dependency: %s\n' "$dependency" >&2
        exit 2
    fi
done
if [[ -n $alert_session ]] && ! command -v tmux >/dev/null; then
    printf '%s\n' 'tmux is required when PACKRAT_ALERT_SESSION is set.' >&2
    exit 2
fi
if [[ $alert_pipeline != 0 && $alert_pipeline != 1 ]]; then
    printf '%s\n' 'PACKRAT_ALERT_PIPELINE must be 0 or 1.' >&2
    exit 2
fi
if [[ $require_archive != 0 && $require_archive != 1 && $require_archive != alert-evidence ]]; then
    printf '%s\n' 'PACKRAT_REQUIRE_ARCHIVE must be 0, 1, or alert-evidence.' >&2
    exit 2
fi
if [[ $alert_pipeline == 1 ]] && { [[ -z $alert_session ]] || ! command -v ps >/dev/null; }; then
    printf '%s\n' 'Pipeline checking requires ps and PACKRAT_ALERT_SESSION.' >&2
    exit 2
fi
if [[ -n $alert_log && ( $alert_log != /* || $alert_pipeline != 1 ) ]]; then
    printf '%s\n' 'PACKRAT_ALERT_LOG requires an absolute path and PACKRAT_ALERT_PIPELINE=1.' >&2
    exit 2
fi
if [[ -n $alert_log_owner ]] &&
   { [[ -z $alert_log || ! $alert_log_owner =~ ^(0|[1-9][0-9]{0,9})$ ]] ||
     (( alert_log_owner > 4294967295 )); }; then
    printf '%s\n' 'PACKRAT_ALERT_LOG_OWNER_UID requires a numeric UID and PACKRAT_ALERT_LOG.' >&2
    exit 2
fi
if [[ ( $alert_verify_open != 0 && $alert_verify_open != 1 ) ||
      ( $alert_verify_open == 1 && -z $alert_log ) ]]; then
    printf '%s\n' 'PACKRAT_ALERT_VERIFY_OPEN must be 0 or 1 and requires PACKRAT_ALERT_LOG when enabled.' >&2
    exit 2
fi
if [[ -n $alert_context_watcher &&
      ( $alert_context_watcher != /* || $alert_context_watcher == *[[:cntrl:]]* || $alert_verify_open != 1 ) ]]; then
    printf '%s\n' 'PACKRAT_ALERT_CONTEXT_WATCHER requires an absolute script path and PACKRAT_ALERT_VERIFY_OPEN=1.' >&2
    exit 2
fi
if [[ -z $disk_path ]]; then
    disk_path=${alert_log%/*}
    disk_path=${disk_path:-/}
fi
if [[ $disk_path != /* || $disk_path == *[[:cntrl:]]* || ( $disk_sudo != 0 && $disk_sudo != 1 ) ]]; then
    printf '%s\n' 'PACKRAT_DISK_PATH must be absolute and PACKRAT_DISK_SUDO must be 0 or 1.' >&2
    exit 2
fi

disk_free_kib() {
    local output
    if ! output=$(LC_ALL=C df -Pk -- "$disk_path" 2>/dev/null); then
        [[ $disk_sudo == 1 ]] || return 1
        output=$(LC_ALL=C sudo -n -- df -Pk -- "$disk_path" 2>/dev/null) || return 1
    fi
    awk 'NR == 2 { print $4 }' <<< "$output"
}

alert_log_storage() {
    local metadata mode links owner identity
    local -a probe=(stat --format='%f:%h:%u %d:%i' -- "$alert_log")
    metadata=$(LC_ALL=C "${probe[@]}" 2>/dev/null) ||
        metadata=$(LC_ALL=C sudo -n -- "${probe[@]}" 2>/dev/null) || return 1
    [[ $metadata =~ ^([0-9a-fA-F]{1,8}):([0-9]{1,20}):([0-9]{1,10})\ ([0-9]{1,20}:[0-9]{1,20})$ ]] || return 1
    mode=$((16#${BASH_REMATCH[1]}))
    links=${BASH_REMATCH[2]} owner=${BASH_REMATCH[3]} identity=${BASH_REMATCH[4]}
    if (( (mode & 0170000) == 0100000 && (mode & 077) == 0 )) &&
       [[ $links == 1 && ( -z $alert_log_owner || $owner == "$alert_log_owner" ) ]]; then
        printf 'private %s\n' "$identity"
    else
        printf '%s\n' unsafe
    fi
}

alert_pipeline_processes() {
    local pane=$1
    [[ $pane =~ ^[1-9][0-9]*$ ]] || return 1
    LC_ALL=C ps -e -o pid= -o ppid= -o stat= -o comm= | awk -v pane="$pane" '
        {
            parent[$1] = $2
            if ($3 !~ /^[TtZX]/ && ($4 == "tail" || $4 == "jq" || $4 == "bash")) roles[$1] = $4
        }
        END {
            for (pid in roles) {
                ancestor = pid
                for (steps = 0; ancestor > 1 && steps < 32; steps++) {
                    if (ancestor == pane) {
                        observed[roles[pid]] = 1
                        matched[pid] = roles[pid]
                        break
                    }
                    ancestor = parent[ancestor]
                }
            }
            if (!(observed["tail"] && observed["jq"])) exit 1
            for (pid in matched) print matched[pid], pid
        }'
}

alert_log_open() {
    local expected=$2 opened
    [[ $expected =~ ^[0-9]+:[0-9]+$ ]] || return 1
    local -a lookup=(find -L "/proc/$1/fd" -maxdepth 1 -type f -printf '%D:%i\n')
    opened=$("${lookup[@]}" 2>/dev/null) ||
        opened=$(sudo -n -- "${lookup[@]}" 2>/dev/null) || return 1
    grep -Fxq -- "$expected" <<< "$opened"
}

read_pipe() {
    local target
    target=$(readlink -- "$1" 2>/dev/null) ||
        target=$(sudo -n -- readlink -- "$1" 2>/dev/null) || return 1
    [[ $target =~ ^pipe:\[[0-9]+\]$ ]] || return 1
    printf '%s\n' "$target"
}

alert_log_followed() {
    local pid role arg follow pipe
    local -a args tails=()
    local -A parser_pipes=()
    while read -r role pid; do
        [[ $pid =~ ^[1-9][0-9]*$ ]] || continue
        if [[ $role == tail ]]; then
            tails+=("$pid")
        elif [[ $role == jq && $alert_verify_open == 1 ]] && pipe=$(read_pipe "/proc/$pid/fd/0"); then
            parser_pipes[$pipe]=$pid
        fi
    done <<< "$1"
    for pid in "${tails[@]}"; do
        mapfile -d '' -t args < <(cat -- "/proc/$pid/cmdline" 2>/dev/null)
        [[ ${#args[@]} -gt 1 && ${args[-1]} == "$alert_log" ]] || continue
        follow=false
        for arg in "${args[@]:1:${#args[@]}-2}"; do
            [[ $arg != -- ]] || break
            if [[ $arg == -F || $arg == --follow=name ]]; then follow=true; fi
        done
        "$follow" || continue
        if [[ $alert_verify_open == 0 ]]; then return 0; fi
        if pipe=$(read_pipe "/proc/$pid/fd/1") && [[ -n ${parser_pipes[$pipe]:-} ]] &&
            alert_log_open "$pid" "$2"; then
            printf '%s\n' "${parser_pipes[$pipe]}"
            return 0
        fi
    done
    return 1
}

alert_context_followed() {
    local role pid pipe parser_output
    local -a args
    [[ $2 =~ ^[1-9][0-9]*$ ]] || return 1
    parser_output=$(read_pipe "/proc/$2/fd/1") || return 1
    while read -r role pid; do
        [[ $role == bash && $pid =~ ^[1-9][0-9]*$ ]] || continue
        mapfile -d '' -t args < <(cat -- "/proc/$pid/cmdline" 2>/dev/null)
        [[ ${#args[@]} == 2 && ${args[0]##*/} == bash && ${args[1]} == "$alert_context_watcher" ]] || continue
        if pipe=$(read_pipe "/proc/$pid/fd/0") && [[ $pipe == "$parser_output" ]]; then
            return 0
        fi
    done <<< "$1"
    return 1
}

read_health() {
    local sample watcher=null pipeline=null source=null context=null processes parser pane_info dead pane disk=null free_kib
    local storage='' identity='' storage_probe
    if [[ -n $alert_context_watcher ]]; then context=false; fi
    if [[ -n $alert_log ]]; then
        if storage_probe=$(alert_log_storage); then
            read -r storage identity <<< "$storage_probe"
        else
            storage=unavailable
        fi
    fi
    sample=$(curl --disable --fail --silent --max-time 3 --noproxy '*' "http://127.0.0.1:$port/health") || sample=null
    if [[ -n $alert_session ]]; then
        watcher=false
        pane_info=$(tmux display-message -p -t "=$alert_session:" '#{pane_dead} #{pane_pid}' 2>/dev/null) || pane_info=
        read -r dead pane <<< "$pane_info"
        if [[ $dead == 0 ]]; then
            watcher=true
            if [[ $alert_pipeline == 1 ]]; then
                if processes=$(alert_pipeline_processes "$pane"); then
                    pipeline=true
                    if [[ -n $alert_log ]]; then
                        if parser=$(alert_log_followed "$processes" "$identity"); then
                            source=true
                            if [[ -n $alert_context_watcher ]] && alert_context_followed "$processes" "$parser"; then
                                context=true
                            fi
                        else
                            source=false
                        fi
                    fi
                else
                    pipeline=false
                fi
            fi
        fi
    fi
    free_kib=$(disk_free_kib) || free_kib=
    if [[ $free_kib =~ ^[0-9]{1,15}$ ]]; then
        disk=$((10#$free_kib / 1024))
    fi
    printf '%s\n' "$sample" | jq -Rcse \
        --argjson watcher "$watcher" --argjson pipeline "$pipeline" --argjson source "$source" --argjson context "$context" \
        --arg alert_log "$alert_log" --arg expected_interface "$expected_interface" --arg disk_path "$disk_path" \
        --arg storage "$storage" --arg identity "$identity" \
        --argjson verify_open "$alert_verify_open" \
        --argjson disk "$disk" --argjson min_free "$min_free" --arg require_archive "$require_archive" \
        --argjson baseline "$baseline" --argjson clock "$SECONDS" --argjson expect_traffic "$expect_traffic" '
        (try fromjson catch null) as $health |
        (if ($health|type) == "object" then $health else {} end) as $h |
        ($h.capture_run_id | if type == "string" and test("^[0-9a-f]{16}$") then . else null end) as $run |
        ($h.capture_interface | if type == "string" and length > 0 and length <= 256
                                 and (test("[[:cntrl:]]") | not) then . else null end) as $interface |
        ($h.capture_link_type | if type == "number" and . >= 0 and . <= 4294967295 and floor == .
                                then . else null end) as $link_type |
        ($h.capture_link_decodable | if type == "boolean" then . else null end) as $link_decodable |
        ($h.capture_id | if type == "string" and test("^[0-9a-f]{32}$") then . else null end) as $capture |
        ($h.alert_session_id | if type == "string" and length <= 128 and test("^[0-9]+-[0-9]+$")
                              then . else null end) as $session |
        ($h.pcap_buffer_drops | if type == "number" and . >= 0 and . <= 4294967295 and floor == .
                                 then . else null end) as $drops |
        ($h.capture_truncated_frames | if type == "number" and . >= 0 and . <= 9007199254740991
                                      and floor == . then . else null end) as $truncated |
        ($h.capture_queue_full_packets | if type == "number" and . >= 0 and . <= 9007199254740991
                                      and floor == . then . else null end) as $queue_full |
        ($h.packets_total | if type == "number" and . >= 0 and . <= 9007199254740991 and floor == .
                            then . else null end) as $packets |
        ($h.capture_queue | if type == "object" and (.depth | type == "number")
           and (.capacity | type == "number") and .capacity > 0 and .depth >= 0 and .depth <= .capacity
           then . else null end) as $queue |
        ($h.status == "ok" and $h.telemetry_fresh == true and $h.capture_active == true) as $usable |
        ($usable and $run != null and $capture != null and $packets != null) as $has_counter |
        def counter_delta($current; $previous):
            if $usable and $run != null and $current != null and $previous.run == $run
               and $current >= $previous.total
            then $current - $previous.total else null end;
        def next_counter($current; $previous):
            if $usable and $run != null and $current != null then {run:$run,total:$current}
            elif $usable and $run != $previous.run then null
            else $previous end;
        ($has_counter and $baseline.packets.run == $run and $baseline.packets.capture == $capture) as $same_counter |
        (if $same_counter and $packets == $baseline.packets.total
         then ($baseline.packets.last_progress // $clock) else $clock end) as $last_progress |
        (if $same_counter and $packets >= $baseline.packets.total
         then ([0, $clock - $last_progress] | max) else null end) as $no_progress |
        ($h.archive_enabled | if type == "boolean" then . else null end) as $archive_enabled |
        ($h.archive_paused | if type == "boolean" then . else null end) as $archive_paused |
        (if $archive_paused == true then
            [$h.archive_pause_reason | strings | select(. as $reason |
                ["frame_limit","byte_limit","disk_reserve","queue_unavailable","write_failed"] | index($reason) != null
            )][0] else null end) as $pause_reason |
        ($h.archive_alert_evidence_only | if type == "boolean" then . else null end) as $evidence_only |
        ($h.archive_evidence_rules | if $archive_enabled == true and $evidence_only == true and type == "array" and
            length <= 16 and length == (unique | length) and
            all(.[]; type == "string" and test("\\A[a-z0-9][a-z0-9_.-]{0,127}\\z"))
            then sort else null end) as $evidence_rules |
        def archive_count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
        ($h.archive_usage
         | if $archive_enabled == true and type == "object" and (.frames | archive_count)
              and (.payload_bytes | archive_count) and all([.max_frames,.max_payload_bytes][]; archive_count and . > 0)
           then {frames,payload_bytes,max_frames,max_payload_bytes} else null end) as $archive_usage |
        {
            capture_active: ($h.capture_active // false),
            capture_run_id: $run,
            capture_interface: $interface,
            capture_link_type: $link_type,
            capture_link_decodable: $link_decodable,
            expected_capture_interface: (if $expected_interface == "" then null else $expected_interface end),
            capture_id: $capture,
            alert_session_id: $session,
            telemetry_fresh: ($h.telemetry_fresh // false),
            packets_total: (if $usable then $packets else null end),
            packets_since_last_poll: (
                if $same_counter and $packets >= $baseline.packets.total
                then $packets - $baseline.packets.total else null end
            ),
            packets_without_progress_seconds: $no_progress,
            expect_traffic_seconds: $expect_traffic,
            pcap_buffer_drops: $drops,
            pcap_buffer_drops_delta: counter_delta($drops; $baseline.drops),
            capture_truncated_frames: (if $usable then $truncated else null end),
            capture_truncated_frames_delta: counter_delta($truncated; $baseline.truncated),
            capture_queue_full_packets: (if $usable then $queue_full else null end),
            capture_queue_full_packets_delta: counter_delta($queue_full; $baseline.queue_full),
            capture_queue: $queue,
            flow_cache: (if $usable then $h.flow_cache | objects | {retained_summaries,summary_evictions}
                | select(all(.[]; type == "number" and . >= 0 and . <= 9007199254740991 and floor == .)) else empty end) // null,
            alert_saving: ($h.alert_saving // false),
            alert_watcher_alive: (if $pipeline == false or $source == false or $context == false then false else $watcher end),
            alert_watcher_pipeline_alive: $pipeline,
            alert_watcher_source_matches: $source,
            alert_socket_context_alive: $context,
            alert_watcher_open_log_required: ($verify_open == 1),
            alert_watcher_log: (if $alert_log == "" then null else $alert_log end),
            alert_log_storage: (if $storage == "" then null else $storage end),
            alert_log_identity: (if $verify_open == 1 and $source == true then $identity else null end),
            archive_enabled: $archive_enabled,
            archive_paused: $archive_paused,
            archive_pause_reason: $pause_reason,
            archive_usage: $archive_usage,
            archive_alert_evidence_only: $evidence_only,
            archive_evidence_rules: $evidence_rules,
            archive_requirement: (if $require_archive == "1" then "active"
                                  elif $require_archive == "alert-evidence" then "alert_evidence_only"
                                  else null end),
            disk_path: $disk_path,
            disk_free_mib: $disk,
            issues: [
                if $h.status != "ok" then "health_unreachable"
                else
                    (if $h.telemetry_fresh != true then "telemetry_stale" else empty end),
                    (if $h.capture_active != true then "capture_inactive" else empty end),
                    (if $usable and $link_decodable == false then "capture_link_unsupported" else empty end),
                    (if $usable and $expected_interface != "" then
                        if $interface == null then "capture_interface_unavailable"
                        elif $interface != $expected_interface then "capture_interface_mismatch"
                        else empty end
                     else empty end),
                    (if $usable and $expect_traffic > 0 then
                        if $has_counter | not then "capture_packet_counter_unavailable"
                        elif $same_counter and $packets < $baseline.packets.total then "capture_packet_counter_regressed"
                        elif $no_progress != null and $no_progress >= $expect_traffic then "capture_no_packet_progress"
                        else empty end
                     else empty end),
                    (if $h.alert_save_failed == true then "alert_save_failed"
                     elif $h.alert_saving != true then "alert_saving_disabled" else empty end),
                    (if $drops != null then
                         if $drops > 0 then "pcap_buffer_drops" else empty end
                     else "pcap_stats_unavailable" end),
                    (if $usable and $truncated != null and $truncated > 0
                     then "capture_frames_truncated" else empty end),
                    (if $h.capture_active == true and $queue != null and $queue.depth * 4 >= $queue.capacity * 3
                     then "capture_queue_high" else empty end),
                    (if (counter_delta($queue_full; $baseline.queue_full) // 0) > 0 then "capture_queue_packets_dropped"
                     elif $usable and $run != null and $queue_full != null and $baseline.queue_full.run == $run
                          and $queue_full < $baseline.queue_full.total then "capture_queue_counter_regressed" else empty end),
                    (if $archive_paused == true then "archive_paused"
                     elif $require_archive != "0" then
                        if $archive_enabled == false then "archive_disabled"
                        elif $archive_enabled != true or $archive_paused != false then "archive_status_unavailable"
                        elif $archive_usage == null then "archive_usage_unavailable"
                        else empty end
                     else empty end),
                    (if $require_archive == "alert-evidence" and $archive_enabled == true then
                        if $evidence_only == false then "archive_full_capture_unexpected"
                        elif $evidence_only == null then "archive_mode_unavailable"
                        elif $evidence_rules == null then "archive_rules_unavailable" else empty end
                     else empty end),
                    (if $archive_paused == false and $archive_usage != null then $archive_usage |
                        if .frames >= .max_frames or .payload_bytes >= .max_payload_bytes then "archive_at_capacity"
                        elif .frames / .max_frames >= 0.9 or .payload_bytes / .max_payload_bytes >= 0.9
                        then "archive_near_capacity" else empty end else empty end)
                end,
                (if $watcher == false then "alert_watcher_unavailable"
                 elif $pipeline == false then "alert_watcher_pipeline_inactive"
                 elif $source == false then "alert_watcher_source_unverified"
                 elif $context == false then "alert_socket_context_unverified" else empty end),
                (if $storage == "unsafe" then "alert_log_storage_unsafe"
                 elif $storage == "unavailable" then "alert_log_storage_unverified" else empty end),
                (if $disk == null then "disk_space_unknown"
                 elif $disk < $min_free then "disk_space_low" else empty end)
            ],
            next_baseline: {
                drops: next_counter($drops; $baseline.drops),
                truncated: next_counter($truncated; $baseline.truncated),
                queue_full: next_counter($queue_full; $baseline.queue_full),
                packets: (
                    if $has_counter
                    then {run:$run,capture:$capture,total:$packets,last_progress:$last_progress}
                    else null end
                )
            }
        }'
}

previous=
last_emit=0
baseline=null
pending_state=
if [[ -n $state_file ]]; then
    trap 'if [[ -n $pending_state ]]; then rm -f -- "$pending_state"; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
fi

publish_state() {
    local record=$1
    pending_state=$(mktemp -- "${state_file%/*}/.packrat-health.XXXXXXXX") || return 1
    printf '%s\n' "$record" >"$pending_state" && mv -T -- "$pending_state" "$state_file" || return 1
    pending_state=
}

while :; do
    if ! state=$(read_health); then
        state=$(jq -cn --argjson baseline "$baseline" '
            {issues:["monitor_input_error"],next_baseline:($baseline // {} | .packets=null)}')
    fi
    change_key=$(jq -c '[.issues, .capture_run_id, .capture_interface, .capture_link_type, .capture_id, .alert_session_id, .alert_log_identity, .pcap_buffer_drops, .capture_truncated_frames, .capture_queue_full_packets, .archive_enabled, .archive_paused, .archive_pause_reason, .archive_alert_evidence_only, .archive_evidence_rules]' <<< "$state") || exit 2
    event=
    if "$once"; then
        event=sample
    elif [[ -z $previous ]]; then
        event=initial
    elif [[ $change_key != "$previous" ]]; then
        event=changed
    elif (( heartbeat > 0 && SECONDS - last_emit >= heartbeat )); then
        event=heartbeat
    fi
    if [[ -n $event || -n $state_file ]]; then
        record=$(jq -c --arg time "$(date -u +%FT%TZ)" --arg event "${event:-sample}" \
            --argjson interval "$interval" '
            del(.next_baseline) + {record_type:"capture_health", timestamp:$time, event:$event,
                                  poll_interval_seconds:$interval}
        ' <<< "$state") || exit 2
        if [[ -n $state_file ]] && ! publish_state "$record"; then
            printf '%s\n' 'Could not publish the capture health record.' >&2
            exit 2
        fi
    fi
    if [[ -n $event ]]; then
        printf '%s\n' "$record" || exit 2
        previous=$change_key
        last_emit=$SECONDS
    fi
    if "$once"; then
        if jq -e '.issues == []' <<< "$state" >/dev/null; then exit 0; else exit 1; fi
    fi
    baseline=$(jq -c '.next_baseline' <<< "$state") || exit 2
    sleep "$interval"
done
