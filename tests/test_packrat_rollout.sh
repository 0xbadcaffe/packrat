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
        "new-session -d -s $bridge_session -c / -x 150 -y 40 sudo -n -H env XDG_DATA_HOME=/backup/stage-data /candidate" ]]
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
    [[ $stage_command == *$'<--archive>\n</backup/stage-data/packet-archive>\n<--archive-max-mib>\n<32>\n<--archive-max-frames>\n<4096>' ]]

    capture_file_open() {
        [[ $1 == 42 && ( $2 == "$(alert_log_for_session "$bridge_session")" ||
            $2 == "$mock_open_archive" ) ]]
    }
    mock_open_archive="$archive/packets.bin"
    if capture_storage_ready 42 "$bridge_session"; then exit 1; fi
    mock_open_archive=/backup/stage-data/packet-archive/packets.bin
    capture_storage_ready 42 "$bridge_session"

    curl() { printf '%s\n' "$sample"; }
    sample='{"status":"ok","telemetry_fresh":true,"capture_active":true,"alert_saving":true,"pcap_buffer_drops":0,"archive_paused":true}'
    if health_ready; then exit 1; fi
    sample=$(jq -c '.archive_paused = false' <<< "$sample")
    health_ready

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
sudo() {
    [[ $1 == -n && $2 == stat ]] || return 1
    shift
    command "$@"
}

printf '%s\n' 'initial alert' >"$data_dir/alerts.jsonl"
stamp=$(primary_alert_log_stamp)
[[ $(primary_alert_log_stamp) == "$stamp" ]]
printf '%s\n' 'new alert' >>"$data_dir/alerts.jsonl"
[[ $(primary_alert_log_stamp) != "$stamp" ]]
stamp=$(primary_alert_log_stamp)
cp -p -- "$data_dir/alerts.jsonl" "$data_dir/replacement"
mv -T -- "$data_dir/replacement" "$data_dir/alerts.jsonl"
[[ $(primary_alert_log_stamp) != "$stamp" ]]

prepare_backup_and_stage() {
    trace+=("backup")
    backup_dir=/backup
    stage_binary=/candidate
    [[ $scenario != backup_fail ]]
}

start_capture() {
    local session=$1 binary=$2
    trace+=("start:$session:$binary")
    if [[ $session == "$bridge_session" ]]; then
        case $scenario in
            new_alert) printf '%s\n' 'new finding in primary' >>"$data_dir/alerts.jsonl" ;;
            log_disappears) mv -- "$data_dir/alerts.jsonl" "$data_dir/alerts.saved" ;;
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
    [[ $scenario != cannot_stop ]]
}

replace_installed() {
    trace+=("install:$1")
    [[ $scenario != install_fail || $1 == /backup/packrat ]]
}

retire_bridge() { trace+=("retire-stage"); }

run_scenario() {
    scenario=$1
    local expected=$2 actual=0
    shift 2
    local -a trace=()
    local main_starts=0
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
run_scenario cannot_stop 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat
run_scenario success 0 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat retire-stage
run_scenario install_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate stop:packrat:/usr/local/bin/packrat install:/backup/packrat \
    start:packrat:/usr/local/bin/packrat retire-stage
run_scenario health_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat retire-stage
run_scenario rollback_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat

rc=0
bash "$root/scripts/packrat-rollout.sh" --deploy /missing 'invalid/interface' >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]]
printf '%s\n' 'Packrat rollout tests passed'
