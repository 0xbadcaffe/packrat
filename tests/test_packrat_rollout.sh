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
    alerts_ready 42 "$stage_log"
    if alerts_ready 42 "$primary_log"; then exit 1; fi
    mock_fd="$stage_log.1"
    if alerts_ready 42 "$stage_log"; then exit 1; fi
    mock_fd="$stage_log (deleted)"
    if alerts_ready 42 "$stage_log"; then exit 1; fi
)

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
