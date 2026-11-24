#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
watch="$root/scripts/watch-packrat-health.sh"

export PACKRAT_HEALTH_PORT=9477 PACKRAT_ALERT_SESSION=packrat-alerts PACKRAT_MIN_FREE_MIB=512 PACKRAT_ALERT_PIPELINE=0
unset PACKRAT_ALERT_LOG PACKRAT_REQUIRE_ARCHIVE PACKRAT_HEALTH_INTERVAL PACKRAT_HEALTH_HEARTBEAT PACKRAT_HEALTH_STATE_FILE
unset PACKRAT_EXPECT_INTERFACE PACKRAT_EXPECT_TRAFFIC_SECS
unset PACKRAT_DISK_PATH PACKRAT_DISK_SUDO PACKRAT_ALERT_VERIFY_OPEN
unset PACKRAT_ALERT_CONTEXT_WATCHER
unset PACKRAT_ALERT_LOG_OWNER_UID
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

cat() {
    case $* in
        '-- /proc/94/cmdline')
            [[ -n ${PACKRAT_FAKE_TAIL_SOURCE:-} ]] || return 1
            printf '%s\0' /usr/bin/tail -n 0 "$PACKRAT_FAKE_TAIL_FOLLOW" -- "$PACKRAT_FAKE_TAIL_SOURCE" ;;
        '-- /proc/96/cmdline')
            printf '%s\0' bash "$PACKRAT_FAKE_CONTEXT_SCRIPT" ;;
        *) return 1 ;;
    esac
}

df() {
    [[ $* == "-Pk -- ${PACKRAT_FAKE_DISK_PATH:-/}" ]] || return 1
    [[ ${PACKRAT_TEST_DISK_PROTECTED:-0} == 0 ]] || return 1
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
    printf '/dev/fake 2000000 100000 %s 5%% /\n' "$PACKRAT_FAKE_DISK"
}

sudo() {
    [[ $1 == -n && $2 == -- ]] || return 1
    shift 2
    case $1 in
        df) shift; PACKRAT_TEST_DISK_PROTECTED=0 df "$@" ;;
        stat|find|readlink) PACKRAT_FAKE_FD_PROTECTED=0 "$@" ;;
        *) return 1 ;;
    esac
}

readlink() {
    [[ $1 == -- && ${PACKRAT_FAKE_FD_PROTECTED:-0} == 0 ]] || return 1
    case $2 in
        /proc/94/fd/1) printf '%s\n' 'pipe:[100]' ;;
        /proc/95/fd/0) printf '%s\n' "${PACKRAT_FAKE_PARSER_PIPE:-pipe:[100]}" ;;
        /proc/95/fd/1) printf '%s\n' 'pipe:[200]' ;;
        /proc/96/fd/0) printf '%s\n' "${PACKRAT_FAKE_CONTEXT_PIPE:-pipe:[200]}" ;;
        *) return 1 ;;
    esac
}

stat() {
    if [[ $1 == '--format=%f:%h:%u %d:%i' ]]; then
        [[ $# == 3 && $2 == -- && $3 == "$PACKRAT_ALERT_LOG" ]] || return 1
        [[ ${PACKRAT_FAKE_FD_PROTECTED:-0} == 0 && ${PACKRAT_FAKE_LOG_MISSING:-0} == 0 ]] || return 1
        printf '%s %s\n' "${PACKRAT_FAKE_LOG_METADATA:-8180:1:0}" "${PACKRAT_FAKE_LOG_ID:-20:150}"
    else
        command stat "$@"
    fi
}

find() {
    if [[ $1 == -L ]]; then
        [[ $2 == /proc/94/fd && ${PACKRAT_FAKE_FD_PROTECTED:-0} == 0 ]] || return 1
        printf '%s\n' "$PACKRAT_FAKE_OPEN_FDS"
    else
        command find "$@"
    fi
}

sleep() {
    SECONDS=$((SECONDS + $1))
    PACKRAT_TEST_STEP=$((PACKRAT_TEST_STEP + 1))
    export PACKRAT_TEST_STEP
    if (( PACKRAT_TEST_STEP == ${PACKRAT_FAKE_STEPS:-4} )); then exit 0; fi
}

export -f curl tmux ps cat df sudo stat find readlink sleep
bash -n "$watch"

bash "$watch" --once | jq -e '
    .record_type == "capture_health" and .event == "sample" and .issues == []
    and .pcap_buffer_drops == 0 and .alert_watcher_alive == true and .alert_watcher_pipeline_alive == null
    and .archive_enabled == null and .alert_watcher_log == null and .poll_interval_seconds == 15
    and .alert_log_storage == null and .flow_cache == null
    and .disk_path == "/"
    and .packets_total == null and .packets_since_last_poll == null
    and .expect_traffic_seconds == 0 and .packets_without_progress_seconds == null
' >/dev/null

for cache in '{"retained_summaries":8192,"summary_evictions":4,"extra":"private"}' '{"retained_summaries":-1,"summary_evictions":4}'; do
    sample=$(jq -c --argjson cache "$cache" '.flow_cache = $cache' <<< "$PACKRAT_FAKE_HEALTH")
    PACKRAT_FAKE_HEALTH="$sample" bash "$watch" --once | jq -e --argjson cache "$cache" '
        .issues == [] and .pcap_buffer_drops == 0 and
        .flow_cache == (if $cache.retained_summaries < 0 then null else {retained_summaries:8192,summary_evictions:4} end)
    ' >/dev/null
done

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

# shellcheck source=tests/support/watch_health_archive_cases.bash
source "$root/tests/support/watch_health_archive_cases.bash"

interface_samples=$(jq -c '
    [. + {capture_interface:"wlan1"},
     . + {capture_interface:"eth0"},
     . + {capture_interface:"wlan1\n"},
     . + {capture_interface:"wlan1"}]
' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_EXPECT_INTERFACE=wlan1 PACKRAT_FAKE_STEPS=4 PACKRAT_FAKE_SAMPLES="$interface_samples" \
    bash "$watch" | jq -se '
    map(.capture_interface) == ["wlan1","eth0",null,"wlan1"]
    and all(.[]; .expected_capture_interface == "wlan1")
    and map(.issues) == [[],["capture_interface_mismatch"],["capture_interface_unavailable"],[]]
' >/dev/null

log='/var/lib/packrat lab/alerts.jsonl'
export PACKRAT_FAKE_PROCESSES="$pipeline"$'\n95 91 S jq'
export PACKRAT_FAKE_DISK_PATH=${log%/*}
PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
    PACKRAT_FAKE_TAIL_SOURCE="$log" bash "$watch" --once | jq -e --arg log "$log" '
    .issues == [] and .alert_watcher_alive and .alert_watcher_pipeline_alive and .alert_watcher_source_matches
    and .alert_watcher_log == $log and .disk_path == "/var/lib/packrat lab"
    and .alert_log_storage == "private"
    and .alert_log_identity == null
    and (.alert_watcher_open_log_required | not)
' >/dev/null

for protected in 0 1; do
    PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
        PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_ALERT_VERIFY_OPEN=1 PACKRAT_FAKE_FD_PROTECTED=$protected \
        PACKRAT_FAKE_OPEN_FDS=$'11:34\n20:150' bash "$watch" --once |
        jq -e '.issues == [] and .alert_watcher_open_log_required
            and .alert_watcher_source_matches and .alert_log_storage == "private"
            and .alert_log_identity == "20:150"' >/dev/null
done

with_storage_log() {
    PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
        PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_ALERT_LOG_OWNER_UID="$1" bash "$watch" --once
}
(
    for metadata in '81a4:1:0' '8180:2:0' 'a1ff:1:0' '1180:1:0' '8180:1:1000'; do
        status=0
        output=$(PACKRAT_FAKE_LOG_METADATA="$metadata" with_storage_log 0) || status=$?
        [[ $status == 1 ]]
        jq -e '.issues == ["alert_log_storage_unsafe"] and .alert_log_storage == "unsafe"
            and .alert_watcher_alive' <<< "$output" >/dev/null
    done
    status=0
    output=$(PACKRAT_FAKE_LOG_MISSING=1 with_storage_log 0) || status=$?
    [[ $status == 1 ]]
    jq -e '.issues == ["alert_log_storage_unverified"] and .alert_log_storage == "unavailable"' \
        <<< "$output" >/dev/null
    status=0
    output=$(PACKRAT_FAKE_LOG_METADATA=malformed with_storage_log 0) || status=$?
    [[ $status == 1 ]]
    jq -e '.alert_log_storage == "unavailable"' <<< "$output" >/dev/null
    for invalid in +0 00 4294967296; do
        status=0
        with_storage_log "$invalid" >/dev/null 2>&1 || status=$?
        [[ $status == 2 ]]
    done
)

status=0
output=$(PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
    PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_ALERT_VERIFY_OPEN=1 PACKRAT_FAKE_OPEN_FDS=$'20:151\n21:150' \
    bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == ["alert_watcher_source_unverified"] and .alert_watcher_open_log_required
    and (.alert_watcher_source_matches | not) and .alert_log_identity == null' <<< "$output" >/dev/null
for parser_input in 'pipe:[101]' /dev/null; do
    status=0
    output=$(PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
        PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_ALERT_VERIFY_OPEN=1 PACKRAT_FAKE_OPEN_FDS=20:150 \
        PACKRAT_FAKE_PARSER_PIPE="$parser_input" bash "$watch" --once) || status=$?
    [[ $status == 1 ]]
    jq -e '.issues == ["alert_watcher_source_unverified"] and .alert_watcher_pipeline_alive
        and (.alert_watcher_source_matches | not)' <<< "$output" >/dev/null
done

(
    export PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F
    export PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_ALERT_VERIFY_OPEN=1 PACKRAT_FAKE_OPEN_FDS=20:150
    export PACKRAT_ALERT_CONTEXT_WATCHER='/home/rc/context watcher'
    export PACKRAT_FAKE_CONTEXT_SCRIPT="$PACKRAT_ALERT_CONTEXT_WATCHER"
    processes="$PACKRAT_FAKE_PROCESSES"
    export PACKRAT_FAKE_PROCESSES="$processes"$'\n96 91 S bash'
    bash "$watch" --once | jq -e '.issues == [] and .alert_socket_context_alive == true
        and .alert_watcher_alive and .alert_watcher_source_matches' >/dev/null
    for case in wrong_pipe wrong_script unrelated stopped; do
        status=0
        case $case in
            wrong_pipe) output=$(PACKRAT_FAKE_CONTEXT_PIPE='pipe:[201]' bash "$watch" --once) || status=$? ;;
            wrong_script) output=$(PACKRAT_FAKE_CONTEXT_SCRIPT=/other bash "$watch" --once) || status=$? ;;
            unrelated) output=$(PACKRAT_FAKE_PROCESSES="$processes"$'\n96 2 S bash' bash "$watch" --once) || status=$? ;;
            stopped) output=$(PACKRAT_FAKE_PROCESSES="$processes"$'\n96 91 T bash' bash "$watch" --once) || status=$? ;;
        esac
        [[ $status == 1 ]]
        jq -e '.issues == ["alert_socket_context_unverified"] and (.alert_socket_context_alive | not)
            and (.alert_watcher_alive | not) and .alert_watcher_source_matches' <<< "$output" >/dev/null
    done
    status=0
    PACKRAT_ALERT_VERIFY_OPEN=0 bash "$watch" --once >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
)

status=0
output=$(PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
    PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_TEST_DISK_PROTECTED=1 bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == ["disk_space_unknown"] and .disk_free_mib == null' <<< "$output" >/dev/null
PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
    PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_TEST_DISK_PROTECTED=1 PACKRAT_DISK_SUDO=1 \
    bash "$watch" --once | jq -e '.issues == [] and .disk_free_mib == 1024' >/dev/null
PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW=-F \
    PACKRAT_FAKE_TAIL_SOURCE="$log" PACKRAT_DISK_PATH=/mount PACKRAT_FAKE_DISK_PATH=/mount \
    bash "$watch" --once | jq -e '.issues == [] and .disk_path == "/mount"' >/dev/null

for mode in wrong_log descriptor missing_args; do
    source=$log
    follow=-F
    case $mode in
        wrong_log) source="$log.old" ;;
        descriptor) follow=-f ;;
        missing_args) source= ;;
    esac
    status=0
    output=$(PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG="$log" PACKRAT_FAKE_TAIL_FOLLOW="$follow" \
        PACKRAT_FAKE_TAIL_SOURCE="$source" bash "$watch" --once) || status=$?
    [[ $status == 1 ]]
    jq -e '.issues == ["alert_watcher_source_unverified"] and .alert_watcher_pipeline_alive
        and .alert_watcher_alive == false and .alert_watcher_source_matches == false' <<< "$output" >/dev/null
done
unset PACKRAT_FAKE_DISK_PATH

status=0
PACKRAT_ALERT_PIPELINE=1 PACKRAT_ALERT_LOG=alerts.jsonl bash "$watch" --once >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

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
unsupported=$(jq -c '. + {capture_link_type:113,capture_link_decodable:false}' <<< "$PACKRAT_FAKE_HEALTH")
output=$(PACKRAT_FAKE_HEALTH="$unsupported" bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == ["capture_link_unsupported"] and .capture_link_type == 113
   and .capture_link_decodable == false and .pcap_buffer_drops == 0' <<< "$output" >/dev/null

status=0
pressure=$(jq -c '.capture_queue = {depth:75,capacity:100,dispatch_waiting:true,analysis_packets_pending:8}' <<< "$PACKRAT_FAKE_HEALTH")
output=$(PACKRAT_FAKE_HEALTH="$pressure" bash "$watch" --once) || status=$?
[[ $status == 1 ]]
jq -e '.issues == ["capture_queue_high"] and .pcap_buffer_drops == 0
    and .capture_queue.analysis_packets_pending == 8' <<< "$output" >/dev/null

status=0
PACKRAT_HEALTH_PORT='9477/path' bash "$watch" --once >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

bash "$watch" | jq -se 'map(.issues) == [[], ["health_unreachable"], []]' >/dev/null

stable_samples=$(jq -c '[.,.,.,null,null,null,.]' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_HEALTH_INTERVAL=10 PACKRAT_HEALTH_HEARTBEAT=20 PACKRAT_FAKE_STEPS=7 \
    PACKRAT_FAKE_SAMPLES="$stable_samples" bash "$watch" | jq -se '
    map(.event) == ["initial","heartbeat","changed","heartbeat","changed"]
    and map(.issues) == [[],[],["health_unreachable"],["health_unreachable"],[]]
    and all(.[]; .poll_interval_seconds == 10)
' >/dev/null
PACKRAT_HEALTH_HEARTBEAT=0 PACKRAT_FAKE_STEPS=7 PACKRAT_FAKE_SAMPLES="$stable_samples" \
    bash "$watch" | jq -se 'map(.event) == ["initial","changed","changed"]' >/dev/null
status=0
PACKRAT_HEALTH_HEARTBEAT=-1 bash "$watch" --once >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

(
    state_dir=$(mktemp -d)
    trap 'rm -rf -- "$state_dir"' EXIT
    export PACKRAT_HEALTH_STATE_FILE="$state_dir/current state.json"
    umask 022
    stream=$(bash "$watch" --once)
    [[ $(<"$PACKRAT_HEALTH_STATE_FILE") == "$stream" ]]
    [[ $(stat --format=%a -- "$PACKRAT_HEALTH_STATE_FILE") == 600 ]]

    samples=$(jq -c '[., . + {capture_queue:{depth:5,capacity:100}}]' <<< "$PACKRAT_FAKE_HEALTH")
    PACKRAT_FAKE_STEPS=2 PACKRAT_FAKE_SAMPLES="$samples" PACKRAT_HEALTH_HEARTBEAT=0 \
        bash "$watch" | jq -se 'length == 1 and .[0].event == "initial" and .[0].capture_queue == null' >/dev/null
    jq -e '.event == "sample" and .capture_queue.depth == 5 and .issues == []' \
        "$PACKRAT_HEALTH_STATE_FILE" >/dev/null

    status=0
    stream=$(PACKRAT_FAKE_HEALTH=unreachable bash "$watch" --once) || status=$?
    [[ $status == 1 && $(<"$PACKRAT_HEALTH_STATE_FILE") == "$stream" ]]
    jq -e '.issues == ["health_unreachable"]' <<< "$stream" >/dev/null

    mkdir -- "$state_dir/destination"
    status=0
    PACKRAT_HEALTH_STATE_FILE="$state_dir/destination" bash "$watch" --once >"$state_dir/failed" 2>/dev/null || status=$?
    [[ $status == 2 && ! -s "$state_dir/failed" ]]
    [[ $(find "$state_dir" -maxdepth 1 -name '.packrat-health.*' -print -quit) == '' ]]
    status=0
    PACKRAT_HEALTH_STATE_FILE=relative bash "$watch" --once >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
)

samples=$(jq -cn '
    def sample($id;$drops):
        {status:"ok",telemetry_fresh:true,capture_active:true,alert_saving:true,
         capture_run_id:$id,pcap_buffer_drops:$drops,capture_queue_full_packets:($drops*2)};
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
    and map(.capture_queue_full_packets_delta) == [null,6,null,10,null,null,4] and .[2].issues == ["health_unreachable"]
    and (.[] | select(.pcap_buffer_drops == 1) | .issues | index("capture_queue_counter_regressed")) != null
    and all(.[]; has("next_baseline") | not)
' >/dev/null

queue_samples=$(jq -cn --argjson health "$PACKRAT_FAKE_HEALTH" '
    ($health + {capture_run_id:"000000000000000a",capture_queue_full_packets:0,
                capture_queue:{depth:1,capacity:100}}) as $base
    | [$base, ($base | .capture_queue_full_packets = 3),
       ($base | .capture_queue_full_packets = 3), $base]
')
PACKRAT_FAKE_STEPS=4 PACKRAT_FAKE_SAMPLES="$queue_samples" bash "$watch" | jq -se '
    map(.capture_queue_full_packets) == [0,3,3,0]
    and map(.capture_queue_full_packets_delta) == [null,3,0,null]
    and map(.issues) == [[],["capture_queue_packets_dropped"],[],["capture_queue_counter_regressed"]]
    and all(.[]; .pcap_buffer_drops == 0 and .capture_queue.depth == 1)
' >/dev/null

save_samples=$(jq -cn --argjson health "$PACKRAT_FAKE_HEALTH" '
    [$health, ($health + {alert_save_failures:0,alert_save_backlog_dropped:0}),
     ($health + {alert_save_failures:1,alert_save_backlog_dropped:0}),
     ($health + {alert_save_failures:1,alert_save_backlog_dropped:1}),
     ($health + {alert_save_failures:"invalid",alert_save_backlog_dropped:-1})]')
PACKRAT_FAKE_STEPS=5 PACKRAT_FAKE_SAMPLES="$save_samples" bash "$watch" | jq -se '
    map(.alert_save_failures) == [null,0,1,1,null]
    and map(.alert_save_backlog_dropped) == [null,0,0,1,null] and all(.[]; .issues == [])' >/dev/null

truncation_samples=$(jq -cn --argjson health "$PACKRAT_FAKE_HEALTH" '
    ($health + {capture_run_id:"000000000000000a"}) as $a
    | ($a | .capture_run_id = "000000000000000b") as $b
    | [$a, ($a | .capture_truncated_frames = 0),
       ($a | .capture_truncated_frames = 2), null, ($a | .capture_truncated_frames = 5),
       ($b | .capture_truncated_frames = 0)]
')
PACKRAT_FAKE_STEPS=6 PACKRAT_FAKE_SAMPLES="$truncation_samples" bash "$watch" | jq -se '
    map(.capture_truncated_frames) == [null,0,2,null,5,0]
    and map(.capture_truncated_frames_delta) == [null,null,2,null,3,null]
    and map(.issues) == [[],[],["capture_frames_truncated"],["health_unreachable"],["capture_frames_truncated"],[]]
    and all(.[] | select(.capture_truncated_frames != null); .pcap_buffer_drops == 0)
' >/dev/null

scopes=$(jq -c '
    . + {capture_run_id:"000000000000000a",pcap_buffer_drops:2,
        alert_session_id:"1234-567",capture_id:"00000000000000000000000000000001"} as $first |
    ($first | .capture_id = "00000000000000000000000000000002") as $second |
    [$first, $first, $second, ($second | .pcap_buffer_drops = 3)]
' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_FAKE_STEPS=4 PACKRAT_FAKE_SAMPLES="$scopes" bash "$watch" | jq -se '
    length == 3 and all(.[]; .alert_session_id == "1234-567")
    and map(.capture_id | .[-1:]) == ["1", "2", "2"]
    and map(.pcap_buffer_drops_delta) == [null, 0, 1]
' >/dev/null

packet_samples=$(jq -cn --argjson scopes "$scopes" '
    $scopes[0] as $first | $scopes[2] as $second
    | ($second | .capture_run_id = "000000000000000b") as $restarted
    | [($first | .packets_total = 10),
       ($first | .packets_total = 17),
       ($first | .packets_total = 17),
       ($second | .packets_total = 2),
       ($second | .packets_total = 5),
       null,
       ($second | .packets_total = 11),
       ($restarted | .packets_total = 17),
       ($restarted | .packets_total = 1)]
')
PACKRAT_FAKE_STEPS=9 PACKRAT_HEALTH_HEARTBEAT=1 PACKRAT_FAKE_SAMPLES="$packet_samples" bash "$watch" | jq -se '
    map(.packets_total) == [10,17,17,2,5,null,11,17,1]
    and map(.packets_since_last_poll) == [null,7,0,null,3,null,null,null,null]
    and .[5].issues == ["health_unreachable"]
    and all(.[] | select(.event == "heartbeat"); .issues == ["pcap_buffer_drops"])
' >/dev/null

traffic_samples=$(jq -cn --argjson scopes "$scopes" '
    ($scopes[0] | .pcap_buffer_drops = 0 | .packets_total = 10) as $first
    | ($first | .capture_id = $scopes[2].capture_id) as $second
    | [$first,$first,$first,$first,($first | .packets_total = 11),$first,
       $second,($second | del(.packets_total)),$second,$second,$second,null,$second]
')
PACKRAT_FAKE_STEPS=13 PACKRAT_HEALTH_INTERVAL=10 PACKRAT_HEALTH_HEARTBEAT=0 \
    PACKRAT_EXPECT_TRAFFIC_SECS=20 PACKRAT_FAKE_SAMPLES="$traffic_samples" bash "$watch" | jq -se '
    map(.issues) == [[],["capture_no_packet_progress"],[],["capture_packet_counter_regressed"],
        [],["capture_packet_counter_unavailable"],[],["capture_no_packet_progress"],["health_unreachable"],[]]
    and .[1].packets_without_progress_seconds >= 20 and .[1].packets_since_last_poll == 0
    and .[2].packets_without_progress_seconds == 0 and .[2].packets_since_last_poll == 1
    and .[3].packets_since_last_poll == null and .[4].packets_without_progress_seconds == null
    and .[6].packets_without_progress_seconds == null and .[9].packets_without_progress_seconds == null
    and all(.[]; .expect_traffic_seconds == 20)
' >/dev/null
PACKRAT_FAKE_STEPS=6 PACKRAT_HEALTH_INTERVAL=10 PACKRAT_HEALTH_HEARTBEAT=0 \
    PACKRAT_FAKE_SAMPLES="$traffic_samples" bash "$watch" | jq -se '
    length == 1 and .[0].issues == [] and .[0].expect_traffic_seconds == 0
' >/dev/null
for invalid in -1 08 1000000; do
    status=0
    PACKRAT_EXPECT_TRAFFIC_SECS="$invalid" bash "$watch" --once >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done

printf '%s\n' 'Packrat health watcher tests passed'
