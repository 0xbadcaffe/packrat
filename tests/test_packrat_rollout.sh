#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/packrat-rollout.sh
source "$root/scripts/packrat-rollout.sh"

(
    backup_dir=/backup
    stage_log=$(alert_log_for_session "$bridge_session")
    primary_log=$(alert_log_for_session "$main_session")
    [[ $stage_log == /backup/stage-data/packrat/alerts.jsonl ]]
    [[ $primary_log == "$data_dir/alerts.jsonl" ]]

    tmux() { printf '%s\n' "$*"; }
    [[ $(launch_capture "$bridge_session" /candidate) == \
        "new-session -d -s $bridge_session -c / -x 150 -y 40 sudo -n -H env XDG_DATA_HOME=/backup/stage-data /candidate --telemetry-listen $stage_health_addr" ]]
    [[ $(launch_capture "$main_session" /candidate) == \
        "new-session -d -s $main_session -c / -x 150 -y 40 sudo -n -H /candidate --telemetry-listen $health_addr" ]]

    sudo() {
        [[ $* == '-n ls -l /proc/42/fd' ]] || return 1
        printf 'l-wx------ 1 root root 64 6 -> %s\n' "$mock_fd"
    }
    mock_fd=$stage_log
    capture_file_open 42 "$stage_log"
    if capture_file_open 42 "$primary_log"; then exit 1; fi
    mock_fd="$stage_log.1"
    if capture_file_open 42 "$stage_log"; then exit 1; fi
    mock_fd="$stage_log (deleted)"
    if capture_file_open 42 "$stage_log"; then exit 1; fi
)

(
    backup_dir=/backup
    archive='/root/private packet archive'
    profile=("$installed" --telemetry-listen "$health_addr")
    read_launch_profile "${profile[@]}" --archive-max-mib 32 --archive "$archive" --archive-max-frames 4096
    [[ $archive_path == "$archive" ]]
    [[ $(archive_for_session "$bridge_session") == /backup/stage-data/packet-archive ]]
    [[ $(archive_for_session "$main_session") == "$archive" ]]
    [[ "${archive_limits[*]}" == '--archive-max-mib 32 --archive-max-frames 4096' ]]

    tmux() { printf '<%s>\n' "$@"; }
    [[ $(launch_capture "$main_session" /candidate) == *$'<--archive>\n<'"$archive"$'>\n<--archive-max-mib>\n<32>\n<--archive-max-frames>\n<4096>' ]]
    stage_command=$(launch_capture "$bridge_session" /candidate)
    [[ $stage_command != *"$archive"* ]]
    [[ $stage_command == *$'<--telemetry-listen>\n<'"$stage_health_addr"$'>\n<--archive>\n</backup/stage-data/packet-archive>\n<--archive-max-mib>\n<32>\n<--archive-max-frames>\n<4096>' ]]

    capture_file_open() {
        [[ $1 == 42 && ( $2 == "$(alert_log_for_session "$bridge_session")" ||
            $2 == "$mock_open_archive" ) ]]
    }
    mock_open_archive="$archive/packets.bin"
    if capture_storage_ready 42 "$bridge_session"; then exit 1; fi
    mock_open_archive=/backup/stage-data/packet-archive/packets.bin
    capture_storage_ready 42 "$bridge_session"

    curl() {
        [[ ${*: -1} == "http://$expected_addr/health" ]] || return 1
        printf '%s\n' "$sample"
    }
    expected_addr=$health_addr
    interface=wlan1
    sample='{"status":"ok","service":"packrat","telemetry_fresh":true,"capture_active":true,
        "alert_saving":true,"pcap_buffer_drops":0,"archive_paused":true,"capture_interface":"wlan1",
        "capture_run_id":"0000000000000001","capture_id":"00000000000000000000000000000002"}'
    if capture_health_sample; then exit 1; fi
    sample=$(jq -c '.archive_paused = false' <<< "$sample")
    if capture_health_sample; then exit 1; fi
    sample=$(jq -c '.archive_enabled = true' <<< "$sample")
    [[ $(capture_health_sample) == legacy ]]
    expected_addr=$stage_health_addr
    [[ $(capture_health_sample "$stage_health_addr" true) == legacy ]]
    good=$sample
    for update in '.service = "other"' '.capture_interface = "eth0"' 'del(.capture_interface)' \
        '.capture_id = "invalid"' '.capture_run_id = null' '.pcap_buffer_drops = 1'; do
        sample=$(jq -c "$update" <<< "$good")
        if capture_health_sample "$stage_health_addr" true; then exit 1; fi
    done
    expected_addr=$health_addr
    sample=$(jq -c 'del(.capture_interface) | .pcap_buffer_drops = 1' <<< "$good")
    [[ $(capture_health_sample) == legacy ]]
    sample=$(jq -c '.capture_interface = "eth0"' <<< "$good")
    if capture_health_sample; then exit 1; fi
    sample=$good
    sample=$(jq -c '.pcap_buffer_drops = "0"' <<< "$sample")
    if capture_health_sample; then exit 1; fi

    packet_count() { printf '%s\n' 12; }
    sample=$good
    [[ $(capture_progress_sample "$main_session" "$health_addr" false) == '12 legacy' ]]
    sample=$(jq -c '.packets_total = 42' <<< "$good")
    [[ $(capture_progress_sample "$main_session" "$health_addr" false) == \
        '42 0000000000000001:00000000000000000000000000000002' ]]
    for update in '.packets_total = null' '.packets_total = -1' '.packets_total = "42"' \
        '.packets_total = 4.2' '.capture_interface = null' '.capture_id = null'; do
        sample=$(jq -c ".packets_total = 42 | $update" <<< "$good")
        if capture_progress_sample "$main_session" "$health_addr" false; then exit 1; fi
    done

    if read_launch_profile "${profile[@]}" --archive relative; then exit 1; fi
    if read_launch_profile "${profile[@]}" --archive "$archive" --archive /other; then exit 1; fi
    if read_launch_profile "${profile[@]}" --archive "$archive" --archive-max-mib; then exit 1; fi
    if read_launch_profile "${profile[@]}" --archive-max-mib 32; then exit 1; fi
    if read_launch_profile "${profile[@]}" --archive "$archive" --simulation; then exit 1; fi
    if read_launch_profile "${profile[@]}" --archive "$archive" --archive-max-frames 0; then exit 1; fi
    read_launch_profile "${profile[@]}"
    [[ -z $archive_path && ${#archive_limits[@]} == 0 ]]
)

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
data_dir=$scratch

(
    health_state="$scratch/health.json"
    date() { printf '%s\n' 1700000000; }
    scope='{"pid":"42","capture_id":"00000000000000000000000000000002",
        "capture_run_id":"0000000000000001","alert_session_id":"1700000000-42"}'
    sample=$(jq -c --arg log "$data_dir/alerts.jsonl" '
        del(.pid) + {record_type:"capture_health",timestamp:"2023-11-14T22:13:10Z",
            poll_interval_seconds:15,capture_active:true,telemetry_fresh:true,
            alert_watcher_alive:true,alert_watcher_pipeline_alive:true,
            alert_watcher_source_matches:true,alert_watcher_log:$log}
    ' <<< "$scope")
    printf '%s\n' "$sample" >"$health_state"
    alert_watcher_ready "$scope"
    for update in '.alert_watcher_pipeline_alive = false' '.alert_watcher_source_matches = false' \
        '.alert_watcher_log += ".old"' '.capture_id = "00000000000000000000000000000003"' \
        '.alert_session_id = "1700000000-43"' '.timestamp = "2023-11-14T22:12:29Z"' \
        'del(.poll_interval_seconds)'; do
        jq -c "$update" <<< "$sample" >"$health_state"
        if alert_watcher_ready "$scope"; then exit 1; fi
    done
)

(
    interface=wlan1
    tick=0
    phase=recover
    sleep() { tick=$((tick + 1)); }
    capture_progress_sample() {
        [[ $* == "$bridge_session $stage_health_addr true" ]] || return 1
        [[ $phase != recover || $tick != 1 ]] || return 1
        local scope=first
        if [[ $phase == restarted && $tick -ge 2 ]]; then scope=second; fi
        if [[ $phase == idle ]]; then
            printf '9 %s\n' "$scope"
        elif [[ $phase == reset && $tick == 1 ]]; then
            printf '8 %s\n' "$scope"
        else
            printf '%s %s\n' "$tick" "$scope"
        fi
    }
    capture_pid() {
        if [[ $phase == changed && $tick -ge 2 ]]; then printf '%s\n' 43; else printf '%s\n' 42; fi
    }
    capture_storage_ready() { return 0; }
    verify_capture_progress "$bridge_session" /candidate true >"$scratch/progress"
    [[ $tick == 4 && $(<"$scratch/progress") == *'from 2 to 4 across 3 healthy samples' ]]
    phase=reset
    tick=0
    verify_capture_progress "$bridge_session" /candidate true >"$scratch/progress"
    [[ $tick == 4 && $(<"$scratch/progress") == *'from 2 to 4 across 3 healthy samples' ]]
    phase=changed
    tick=0
    verify_capture_progress "$bridge_session" /candidate true >"$scratch/progress"
    [[ $tick == 4 && $(<"$scratch/progress") == *'from 2 to 4 across 3 healthy samples' ]]
    phase=restarted
    tick=0
    verify_capture_progress "$bridge_session" /candidate true >"$scratch/progress"
    [[ $tick == 4 && $(<"$scratch/progress") == *'from 2 to 4 across 3 healthy samples' ]]
    phase=idle
    tick=0
    if verify_capture_progress "$bridge_session" /candidate true; then exit 1; fi
    [[ $tick == 30 ]]
)

(
    tmux() {
        case $1 in
            has-session) return 0 ;;
            display-message) printf '%s\n' 0 ;;
            send-keys) touch -- "$scratch/signaled"; return 2 ;;
            *) return 2 ;;
        esac
    }
    capture_pid() { printf '%s\n' 43; }
    if stop_capture "$main_session" "$installed" 42; then exit 1; fi
    [[ ! -e $scratch/signaled ]]
)

sudo() {
    [[ $1 == -n && $2 == stat ]] || return 1
    shift
    command "$@"
}

(
    backup_dir="$scratch/staging"
    log=$(alert_log_for_session "$bridge_session")
    mkdir -p -- "${log%/*}"
    sudo() {
        [[ $1 == -n && ( $2 == stat || $2 == test ) ]] || return 1
        shift
        "$@"
    }
    if stage_alert_log_size; then exit 1; fi
    touch -- "$log"
    [[ $(stage_alert_log_size) == 0 ]]
    printf '%s\n' "synthetic finding" >"$log"
    [[ $(stage_alert_log_size) == 18 ]]
)

printf '%s\n' 'initial alert' >"$data_dir/alerts.jsonl"
stamp=$(primary_alert_log_stamp)
[[ $(primary_alert_log_stamp) == "$stamp" ]]
printf '%s\n' 'new alert' >>"$data_dir/alerts.jsonl"
[[ $(primary_alert_log_stamp) != "$stamp" ]]
stamp=$(primary_alert_log_stamp)
cp -p -- "$data_dir/alerts.jsonl" "$data_dir/replacement"
mv -T -- "$data_dir/replacement" "$data_dir/alerts.jsonl"
[[ $(primary_alert_log_stamp) != "$stamp" ]]

(
    backup_reserve_mib=1
    test_mount=$data_dir
    sudo() {
        case $* in
            "-n test -d $data_dir/backups") [[ -d $data_dir/backups ]] ;;
            "-n env LC_ALL=C df -Pk -- $test_mount")
                printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
                printf '/dev/test 99999 10 %s 1%% /\n' "$free"
                ;;
            "-n stat --format=%s -- $installed $data_dir/alerts.jsonl") printf '%s\n' "$test_sizes" ;;
            *) return 1 ;;
        esac
    }
    test_sizes=$'1025\n2048'
    free=1028
    backup_space_ready
    test_mount="$data_dir/backups"
    mkdir -- "$test_mount"
    backup_space_ready
    free=1027
    if backup_space_ready; then exit 1; fi
    free=1028
    test_sizes=unexpected
    if backup_space_ready; then exit 1; fi
)

prepare_backup_and_stage() {
    trace+=("backup")
    backup_dir=/backup
    stage_binary=/candidate
    [[ $scenario != backup_fail ]]
}

primary_capture_stamp() {
    [[ $primary_stamp != unavailable ]] || return 1
    printf '{"pid":"42","capture_id":"%s"}\n' "$primary_stamp"
}

start_capture() {
    local session=$1 binary=$2 require_zero=${3:-true}
    trace+=("start:$session:$binary")
    if [[ $require_zero == false ]]; then trace+=("allow-existing-drops"); fi
    if [[ $session == "$bridge_session" ]]; then
        case $scenario in
            new_alert) printf '%s\n' 'new finding in primary' >>"$data_dir/alerts.jsonl" ;;
            log_disappears) mv -- "$data_dir/alerts.jsonl" "$data_dir/alerts.saved" ;;
            primary_changed) primary_stamp=other ;;
            primary_disappears) primary_stamp=unavailable ;;
        esac
        [[ $scenario != stage_fail ]]
    else
        main_starts=$((main_starts + 1))
        if [[ $scenario == rollback_fail ]]; then return 1; fi
        [[ $scenario != health_fail || $main_starts == 2 ]]
    fi
}

stop_capture() {
    trace+=("stop:$1:$2")
    if [[ $primary_cutover == true && $1 == "$main_session" ]]; then
        primary_cutover=false
        [[ ${3-} == 42 ]] || return 2
    fi
    [[ $scenario != cannot_stop ]]
}

replace_installed() {
    trace+=("install:$1")
    [[ $scenario != install_fail || $1 == /backup/packrat ]]
}

retire_bridge() { trace+=("retire-stage"); }
alert_watcher_ready() { [[ $scenario != watcher_lost_before_cutover ]]; }
await_primary_watcher() { [[ $scenario != watcher_lost_after_cutover ]]; }
stage_alert_log_size() {
    case $scenario in
        staged_finding) printf '%s\n' 512 ;;
        staged_log_missing) return 1 ;;
        *) printf '%s\n' 0 ;;
    esac
}

run_scenario() {
    scenario=$1
    local expected=$2 actual=0
    shift 2
    local -a trace=()
    local main_starts=0
    local primary_cutover=true
    local primary_stamp=original
    if [[ $scenario == primary_missing ]]; then primary_stamp=unavailable; fi
    rollout >/dev/null 2>&1 || actual=$?
    [[ $actual == "$expected" ]]
    if [[ "${trace[*]}" != "$*" ]]; then
        printf 'Unexpected %s trace: %s\n' "$scenario" "${trace[*]}" >&2
        return 1
    fi
}

run_scenario backup_fail 1 backup
run_scenario stage_fail 1 backup start:packrat-stage:/candidate retire-stage
run_scenario new_alert 1 backup start:packrat-stage:/candidate retire-stage
run_scenario log_disappears 1 backup start:packrat-stage:/candidate retire-stage
run_scenario log_missing 1
mv -- "$data_dir/alerts.saved" "$data_dir/alerts.jsonl"
run_scenario primary_missing 1
run_scenario primary_changed 1 backup start:packrat-stage:/candidate retire-stage
run_scenario primary_disappears 1 backup start:packrat-stage:/candidate retire-stage
run_scenario watcher_lost_before_cutover 1 backup start:packrat-stage:/candidate retire-stage
run_scenario staged_finding 1 backup start:packrat-stage:/candidate retire-stage
run_scenario staged_log_missing 1 backup start:packrat-stage:/candidate retire-stage
run_scenario cannot_stop 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat
run_scenario success 0 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat retire-stage
run_scenario watcher_lost_after_cutover 1 backup start:packrat-stage:/candidate \
    stop:packrat:/usr/local/bin/packrat install:/candidate start:packrat:/usr/local/bin/packrat
run_scenario install_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate stop:packrat:/usr/local/bin/packrat install:/backup/packrat \
    start:packrat:/usr/local/bin/packrat allow-existing-drops retire-stage
run_scenario health_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops retire-stage
run_scenario rollback_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops

rc=0
bash "$root/scripts/packrat-rollout.sh" --deploy /missing 'invalid/interface' >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]]
printf '%s\n' 'Packrat rollout tests passed'
