#!/usr/bin/env bash
set -uo pipefail

usage() {
    printf '%s\n' 'Usage: bash watch-packrat-health.sh [--once]' \
        'Environment: PACKRAT_HEALTH_PORT (9477), PACKRAT_HEALTH_INTERVAL (15 seconds),' \
        'PACKRAT_ALERT_SESSION (optional tmux session), PACKRAT_DISK_PATH (/),' \
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

read_health() {
    local sample watcher=null disk=null free_kib
    sample=$(curl --disable --fail --silent --max-time 3 --noproxy '*' "http://127.0.0.1:$port/health") || sample=null
    if [[ -n $alert_session ]]; then
        watcher=false
        if [[ $(tmux display-message -p -t "=$alert_session:" '#{pane_dead}' 2>/dev/null) == 0 ]]; then
            watcher=true
        fi
    fi
    free_kib=$(LC_ALL=C df -Pk -- "$disk_path" 2>/dev/null | awk 'NR == 2 { print $4 }') || free_kib=
    if [[ $free_kib =~ ^[0-9]{1,15}$ ]]; then
        disk=$((10#$free_kib / 1024))
    fi
    printf '%s\n' "$sample" | jq -Rcse \
        --argjson watcher "$watcher" --argjson disk "$disk" --argjson min_free "$min_free" '
        (try fromjson catch null) as $health |
        (if ($health|type) == "object" then $health else {} end) as $h |
        {
            capture_active: ($h.capture_active // false),
            telemetry_fresh: ($h.telemetry_fresh // false),
            pcap_buffer_drops: ($h.pcap_buffer_drops // null),
            alert_saving: ($h.alert_saving // false),
            alert_watcher_alive: $watcher,
            archive_paused: ($h.archive_paused // false),
            disk_free_mib: $disk,
            issues: [
                if $h.status != "ok" then "health_unreachable"
                else
                    (if $h.telemetry_fresh != true then "telemetry_stale" else empty end),
                    (if $h.capture_active != true then "capture_inactive" else empty end),
                    (if $h.alert_save_failed == true then "alert_save_failed"
                     elif $h.alert_saving != true then "alert_saving_disabled" else empty end),
                    (if ($h.pcap_buffer_drops|type) == "number" then
                         if $h.pcap_buffer_drops > 0 then "pcap_buffer_drops" else empty end
                     else "pcap_stats_unavailable" end),
                    (if $h.archive_paused == true then "archive_paused" else empty end)
                end,
                (if $watcher == false then "alert_watcher_unavailable" else empty end),
                (if $disk == null then "disk_space_unknown"
                 elif $disk < $min_free then "disk_space_low" else empty end)
            ]
        }'
}

previous=
while :; do
    if ! state=$(read_health); then
        state='{"issues":["monitor_input_error"]}'
    fi
    issues=$(jq -c '.issues' <<< "$state") || exit 2
    if [[ $issues != "$previous" ]] || "$once"; then
        jq -c --arg time "$(date -u +%FT%TZ)" '. + {record_type:"capture_health", timestamp:$time}' <<< "$state"
        previous=$issues
    fi
    if "$once"; then
        if [[ $issues == '[]' ]]; then exit 0; else exit 1; fi
    fi
    sleep "$interval"
done
