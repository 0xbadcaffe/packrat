#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
watch="$root/scripts/watch-packrat-health.sh"

export PACKRAT_HEALTH_PORT=9477 PACKRAT_ALERT_SESSION=packrat-alerts PACKRAT_MIN_FREE_MIB=512 PACKRAT_ALERT_PIPELINE=0
export PACKRAT_FAKE_HEALTH='{"status":"ok","capture_active":true,"telemetry_fresh":true,"alert_saving":true,"pcap_buffer_drops":0}'
export PACKRAT_FAKE_DISK=1048576 PACKRAT_FAKE_PANE=0 PACKRAT_TEST_STEP=0

curl() {
    [[ ${*: -1} == 'http://127.0.0.1:9477/health' && $1 == --disable ]] || return 2
    if [[ -n ${PACKRAT_FAKE_SAMPLES:-} ]]; then
        jq -ce --argjson n "$PACKRAT_TEST_STEP" '.[$n] | objects' <<< "$PACKRAT_FAKE_SAMPLES"
        return
    fi
    if [[ $PACKRAT_FAKE_HEALTH == unreachable || $PACKRAT_TEST_STEP == 2 ]]; then return 22; fi
    printf '%s\n' "$PACKRAT_FAKE_HEALTH"
}

tmux() {
    [[ $* == 'display-message -p -t =packrat-alerts: #{pane_dead} #{pane_pid}' ]] || return 2
    printf '%s %s\n' "$PACKRAT_FAKE_PANE" 91
}

ps() {
    [[ $* == '-e -o pid= -o ppid= -o stat= -o comm=' ]] || return 2
    printf '%s\n' "$PACKRAT_FAKE_PROCESSES"
}

df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf '/dev/fake 2000000 100000 %s 5%% /\n' "$PACKRAT_FAKE_DISK"
}

sleep() {
    PACKRAT_TEST_STEP=$((PACKRAT_TEST_STEP + 1))
    export PACKRAT_TEST_STEP
    if (( PACKRAT_TEST_STEP == ${PACKRAT_FAKE_STEPS:-4} )); then exit 0; fi
}

export -f curl tmux ps df sleep
bash -n "$watch"

bash "$watch" --once | jq -e '
    .record_type == "capture_health" and .issues == []
    and .pcap_buffer_drops == 0 and .alert_watcher_alive == true and .alert_watcher_pipeline_alive == null
' >/dev/null

pipeline=$'91 2 Ss bash\n92 91 S sudo\n93 92 S sudo\n94 93 S tail'
PACKRAT_ALERT_PIPELINE=1 PACKRAT_FAKE_PROCESSES="$pipeline"$'\n95 91 S jq' \
    bash "$watch" --once | jq -e '
    .issues == [] and .alert_watcher_alive == true and .alert_watcher_pipeline_alive == true
' >/dev/null

for parser in '95 2 S jq' '95 91 Z jq' '95 91 T jq'; do
    status=0
    output=$(PACKRAT_ALERT_PIPELINE=1 PACKRAT_FAKE_PROCESSES="$pipeline"$'\n'"$parser" \
        bash "$watch" --once) || status=$?
    [[ $status == 1 ]]
    jq -e '.issues == ["alert_watcher_pipeline_inactive"] and .alert_watcher_alive == false
        and .alert_watcher_pipeline_alive == false' <<< "$output" >/dev/null
done

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

samples=$(jq -cn '
    def sample($id;$drops):
        {status:"ok",telemetry_fresh:true,capture_active:true,alert_saving:true,
         capture_run_id:$id,pcap_buffer_drops:$drops};
    "000000000000000a" as $a | "000000000000000b" as $b |
    [
        sample($a;4), sample($a;4), sample($a;7),
        null, sample($a;12),
        sample($b;20), sample($b;1), sample($b;3)
    ]
')
PACKRAT_FAKE_STEPS=8 PACKRAT_FAKE_SAMPLES="$samples" bash "$watch" | jq -se '
    length == 7
    and map(.pcap_buffer_drops) == [4, 7, null, 12, 20, 1, 3]
    and map(.pcap_buffer_drops_delta) == [null, 3, null, 5, null, null, 2]
    and .[2].issues == ["health_unreachable"]
    and all(.[]; has("next_baseline") | not)
' >/dev/null

printf '%s\n' 'Packrat health watcher tests passed'
