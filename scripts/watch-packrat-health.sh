#!/usr/bin/env bash
set -uo pipefail

usage() {
    printf '%s\n' 'Usage: bash watch-packrat-health.sh [--once]' \
        'Environment: PACKRAT_HEALTH_PORT (9477), PACKRAT_HEALTH_INTERVAL (15 seconds),' \
        'PACKRAT_ALERT_SESSION (optional tmux session), PACKRAT_DISK_PATH (/),' \
        'PACKRAT_ALERT_PIPELINE (1 checks the alert session tail and jq processes),' \
        'PACKRAT_ALERT_LOG (optional absolute alert path; requires pipeline checking),' \
        'PACKRAT_REQUIRE_ARCHIVE (1 reports missing or inactive packet archiving),' \
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
alert_session=${PACKRAT_ALERT_SESSION:-}
alert_pipeline=${PACKRAT_ALERT_PIPELINE:-0}
alert_log=${PACKRAT_ALERT_LOG:-}
require_archive=${PACKRAT_REQUIRE_ARCHIVE:-0}
disk_path=${PACKRAT_DISK_PATH:-/}
min_free=${PACKRAT_MIN_FREE_MIB:-512}
if [[ ! $port =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )) ||
   [[ ! $interval =~ ^[1-9][0-9]{0,5}$ ]] ||
   [[ ! $min_free =~ ^(0|[1-9][0-9]{0,8})$ ]]; then
    printf '%s\n' 'Invalid health port, polling interval, or free-space threshold.' >&2
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
if [[ $require_archive != 0 && $require_archive != 1 ]]; then
    printf '%s\n' 'PACKRAT_REQUIRE_ARCHIVE must be 0 or 1.' >&2
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

alert_pipeline_tails() {
    local pane=$1
    [[ $pane =~ ^[1-9][0-9]*$ ]] || return 1
    LC_ALL=C ps -e -o pid= -o ppid= -o stat= -o comm= | awk -v pane="$pane" '
        {
            parent[$1] = $2
            if ($3 !~ /^[TtZX]/ && ($4 == "tail" || $4 == "jq")) roles[$1] = $4
        }
        END {
            for (pid in roles) {
                ancestor = pid
                for (steps = 0; ancestor > 1 && steps < 32; steps++) {
                    if (ancestor == pane) {
                        observed[roles[pid]] = 1
                        if (roles[pid] == "tail") tails[pid] = 1
                        break
                    }
                    ancestor = parent[ancestor]
                }
            }
            if (!(observed["tail"] && observed["jq"])) exit 1
            for (pid in tails) print pid
        }'
}

alert_log_followed() {
    local pid arg follow
    local -a args
    while read -r pid; do
        [[ $pid =~ ^[1-9][0-9]*$ ]] || continue
        mapfile -d '' -t args < <(cat -- "/proc/$pid/cmdline" 2>/dev/null)
        [[ ${#args[@]} -gt 1 && ${args[-1]} == "$alert_log" ]] || continue
        follow=false
        for arg in "${args[@]:1:${#args[@]}-2}"; do
            [[ $arg != -- ]] || break
            if [[ $arg == -F || $arg == --follow=name ]]; then follow=true; fi
        done
        if "$follow"; then return 0; fi
    done <<< "$1"
    return 1
}

read_health() {
    local sample watcher=null pipeline=null source=null tails pane_info dead pane disk=null free_kib
    sample=$(curl --disable --fail --silent --max-time 3 --noproxy '*' "http://127.0.0.1:$port/health") || sample=null
    if [[ -n $alert_session ]]; then
        watcher=false
        pane_info=$(tmux display-message -p -t "=$alert_session:" '#{pane_dead} #{pane_pid}' 2>/dev/null) || pane_info=
        read -r dead pane <<< "$pane_info"
        if [[ $dead == 0 ]]; then
            watcher=true
            if [[ $alert_pipeline == 1 ]]; then
                if tails=$(alert_pipeline_tails "$pane"); then
                    pipeline=true
                    if [[ -n $alert_log ]]; then
                        if alert_log_followed "$tails"; then source=true; else source=false; fi
                    fi
                else
                    pipeline=false
                fi
            fi
        fi
    fi
    free_kib=$(LC_ALL=C df -Pk -- "$disk_path" 2>/dev/null | awk 'NR == 2 { print $4 }') || free_kib=
    if [[ $free_kib =~ ^[0-9]{1,15}$ ]]; then
        disk=$((10#$free_kib / 1024))
    fi
    printf '%s\n' "$sample" | jq -Rcse \
        --argjson watcher "$watcher" --argjson pipeline "$pipeline" --argjson source "$source" \
        --argjson disk "$disk" --argjson min_free "$min_free" --argjson require_archive "$require_archive" \
        --argjson baseline "$baseline" '
        (try fromjson catch null) as $health |
        (if ($health|type) == "object" then $health else {} end) as $h |
        ($h.capture_run_id | if type == "string" and test("^[0-9a-f]{16}$") then . else null end) as $run |
        ($h.capture_id | if type == "string" and test("^[0-9a-f]{32}$") then . else null end) as $capture |
        ($h.alert_session_id | if type == "string" and length <= 128 and test("^[0-9]+-[0-9]+$")
                              then . else null end) as $session |
        ($h.pcap_buffer_drops | if type == "number" and . >= 0 and . <= 4294967295 and floor == .
                                 then . else null end) as $drops |
        ($h.capture_queue | if type == "object" and (.depth | type == "number")
           and (.capacity | type == "number") and .capacity > 0 and .depth >= 0 and .depth <= .capacity
           then . else null end) as $queue |
        ($h.status == "ok" and $h.telemetry_fresh == true and $h.capture_active == true) as $usable |
        ($h.archive_enabled | if type == "boolean" then . else null end) as $archive_enabled |
        ($h.archive_paused | if type == "boolean" then . else null end) as $archive_paused |
        {
            capture_active: ($h.capture_active // false),
            capture_run_id: $run,
            capture_id: $capture,
            alert_session_id: $session,
            telemetry_fresh: ($h.telemetry_fresh // false),
            pcap_buffer_drops: $drops,
            capture_queue: $queue,
            pcap_buffer_drops_delta: (
                if $usable and $run != null and $drops != null and $baseline.run == $run
                   and $drops >= $baseline.drops
                then $drops - $baseline.drops else null end
            ),
            alert_saving: ($h.alert_saving // false),
            alert_watcher_alive: (if $pipeline == false or $source == false then false else $watcher end),
            alert_watcher_pipeline_alive: $pipeline,
            alert_watcher_source_matches: $source,
            archive_enabled: $archive_enabled,
            archive_paused: ($archive_paused // false),
            disk_free_mib: $disk,
            issues: [
                if $h.status != "ok" then "health_unreachable"
                else
                    (if $h.telemetry_fresh != true then "telemetry_stale" else empty end),
                    (if $h.capture_active != true then "capture_inactive" else empty end),
                    (if $h.alert_save_failed == true then "alert_save_failed"
                     elif $h.alert_saving != true then "alert_saving_disabled" else empty end),
                    (if $drops != null then
                         if $drops > 0 then "pcap_buffer_drops" else empty end
                     else "pcap_stats_unavailable" end),
                    (if $h.capture_active == true and $queue != null and $queue.depth * 4 >= $queue.capacity * 3
                     then "capture_queue_high" else empty end),
                    (if $archive_paused == true then "archive_paused"
                     elif $require_archive == 1 then
                        if $archive_enabled == false then "archive_disabled"
                        elif $archive_enabled != true or $archive_paused != false then "archive_status_unavailable"
                        else empty end
                     else empty end)
                end,
                (if $watcher == false then "alert_watcher_unavailable"
                 elif $pipeline == false then "alert_watcher_pipeline_inactive"
                 elif $source == false then "alert_watcher_source_unverified" else empty end),
                (if $disk == null then "disk_space_unknown"
                 elif $disk < $min_free then "disk_space_low" else empty end)
            ],
            next_baseline: (
                if $usable and $run != null and $drops != null then {run:$run,drops:$drops}
                elif $usable and $run != $baseline.run then null
                else $baseline end
            )
        }'
}

previous=
baseline=null
while :; do
    if ! state=$(read_health); then
        state=$(jq -cn --argjson baseline "$baseline" '{issues:["monitor_input_error"],next_baseline:$baseline}')
    fi
    change_key=$(jq -c '[.issues, .capture_run_id, .capture_id, .alert_session_id, .pcap_buffer_drops, .archive_enabled]' <<< "$state") || exit 2
    if [[ $change_key != "$previous" ]] || "$once"; then
        jq -c --arg time "$(date -u +%FT%TZ)" '
            del(.next_baseline) + {record_type:"capture_health", timestamp:$time}
        ' <<< "$state"
        previous=$change_key
    fi
    if "$once"; then
        if jq -e '.issues == []' <<< "$state" >/dev/null; then exit 0; else exit 1; fi
    fi
    baseline=$(jq -c '.next_baseline' <<< "$state") || exit 2
    sleep "$interval"
done
