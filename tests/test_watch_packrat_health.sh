#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
watch="$root/scripts/watch-packrat-health.sh"

export PACKRAT_HEALTH_PORT=9477 PACKRAT_ALERT_SESSION=packrat-alerts PACKRAT_MIN_FREE_MIB=512
export PACKRAT_FAKE_HEALTH='{"status":"ok","capture_active":true,"telemetry_fresh":true,"alert_saving":true,"pcap_buffer_drops":0}'
export PACKRAT_FAKE_DISK=1048576 PACKRAT_FAKE_PANE=0 PACKRAT_TEST_STEP=0

curl() {
    [[ ${*: -1} == 'http://127.0.0.1:9477/health' && $1 == --disable ]] || return 2
    if [[ $PACKRAT_FAKE_HEALTH == unreachable || $PACKRAT_TEST_STEP == 2 ]]; then return 22; fi
    printf '%s\n' "$PACKRAT_FAKE_HEALTH"
}

tmux() {
    [[ $* == 'display-message -p -t =packrat-alerts: #{pane_dead}' ]] || return 2
    printf '%s\n' "$PACKRAT_FAKE_PANE"
}

df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf '/dev/fake 2000000 100000 %s 5%% /\n' "$PACKRAT_FAKE_DISK"
}

sleep() {
    PACKRAT_TEST_STEP=$((PACKRAT_TEST_STEP + 1))
    export PACKRAT_TEST_STEP
    if (( PACKRAT_TEST_STEP == 4 )); then exit 0; fi
}

export -f curl tmux df sleep
bash -n "$watch"

bash "$watch" --once | jq -e '
    .record_type == "capture_health" and .issues == []
    and .pcap_buffer_drops == 0 and .alert_watcher_alive == true
' >/dev/null

degraded='{"status":"ok","capture_active":false,"telemetry_fresh":false,"alert_saving":false,"alert_save_failed":true,"archive_paused":true}'
status=0
output=$(PACKRAT_FAKE_HEALTH="$degraded" PACKRAT_FAKE_PANE=1 PACKRAT_FAKE_DISK=512 bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == [
    "telemetry_stale","capture_inactive","alert_save_failed","pcap_stats_unavailable",
    "archive_paused","alert_watcher_unavailable","disk_space_low"
] and .pcap_buffer_drops == null' <<< "$output" >/dev/null

status=0
output=$(PACKRAT_FAKE_HEALTH=unreachable bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == ["health_unreachable"]' <<< "$output" >/dev/null

status=0
output=$(PACKRAT_FAKE_HEALTH='{"status":"ok","capture_active":true,"telemetry_fresh":true,"alert_saving":true,"pcap_buffer_drops":12}' bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == ["pcap_buffer_drops"] and .pcap_buffer_drops == 12' <<< "$output" >/dev/null

status=0
PACKRAT_HEALTH_PORT='9477/path' bash "$watch" --once >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

bash "$watch" | jq -se 'map(.issues) == [[], ["health_unreachable"], []]' >/dev/null
printf '%s\n' 'Packrat health watcher tests passed'
