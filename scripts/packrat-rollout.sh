#!/usr/bin/env bash
# Supervised rollout for one Linux tmux capture host. No remote execution.
set -uo pipefail

installed=/usr/local/bin/packrat
data_dir=/root/.local/share/packrat
main_session=packrat
bridge_session=packrat-stage
health_addr=127.0.0.1:9477
backup_dir=
stage_binary=

error() { printf '%s\n' "$*" >&2; }

pane() {
    tmux capture-pane -p -t "=$1:"
}

packet_count() {
    pane "$1" | awk -v iface="$interface" '
        /capturing/ {
            for (i=1; i+3<=NF; i++)
                if ($i == "iface:" && $(i+1) == iface && $(i+2) ~ /^[0-9]+$/ && $(i+3) == "pkts") {
                    print $(i+2); exit
                }
        }'
}

capture_pid() {
    local session=$1 executable=$2 root pid children found=
    local -a todo
    root=$(tmux display-message -p -t "=$session:" '#{pane_pid}') || return 1
    [[ $root =~ ^[1-9][0-9]*$ ]] || return 1
    todo=("$root")
    while (( ${#todo[@]} )); do
        pid=${todo[0]}
        todo=("${todo[@]:1}")
        if [[ $(sudo -n readlink "/proc/$pid/exe" 2>/dev/null) == "$executable" ]]; then
            [[ -z $found ]] || return 1
            found=$pid
        fi
        children=$(pgrep -P "$pid") || children=
        while read -r pid; do
            [[ $pid =~ ^[1-9][0-9]*$ ]] && todo+=("$pid")
        done <<< "$children"
    done
    [[ -n $found ]] || return 1
    printf '%s\n' "$found"
}

health_ready() {
    curl --disable --fail --silent --noproxy '*' --max-time 3 "http://$health_addr/health" |
        jq -e '.status == "ok" and .telemetry_fresh and .capture_active and .alert_saving
            and (.alert_save_failed | not) and (.pcap_buffer_drops != null)' >/dev/null
}

alerts_ready() {
    sudo -n ls -l "/proc/$1/fd" | awk -v suffix=" -> $2" '
        substr($0, length($0) - length(suffix) + 1) == suffix { found=1 }
        END { exit !found }'
}

alert_log_for_session() {
    if [[ $1 == "$bridge_session" ]]; then
        printf '%s\n' "$backup_dir/stage-data/packrat/alerts.jsonl"
    else
        printf '%s\n' "$data_dir/alerts.jsonl"
    fi
}

preflight() {
    local pid
    local -a current_args
    [[ -f $candidate && -x $candidate ]] || { error "Candidate is not executable"; return 1; }
    [[ -d /sys/class/net/$interface ]] || { error "No such network interface: $interface"; return 1; }
    sudo -n true || return 1
    "$candidate" --help | grep -F -- '--telemetry-listen' >/dev/null || return 1
    [[ $(tmux display-message -p -t "=$main_session:" '#{session_attached}') == 0 ]] ||
        { error "The capture session is missing or has an attached operator"; return 1; }
    if tmux has-session -t "=$bridge_session" 2>/dev/null; then
        error "A staging session already exists; inspect it before another rollout"
        return 1
    fi
    pid=$(capture_pid "$main_session" "$installed") || { error "Cannot identify installed capture"; return 1; }
    mapfile -d '' -t current_args < "/proc/$pid/cmdline" || return 1
    if [[ ${#current_args[@]} != 3 || ${current_args[0]-} != "$installed" ||
          ${current_args[1]-} != --telemetry-listen || ${current_args[2]-} != "$health_addr" ]]; then
        error "Current capture uses a different launch profile; refusing to drop its options"
        return 1
    fi
    [[ $(packet_count "$main_session") =~ ^[0-9]+$ ]] || {
        error "Current capture is not on $interface"
        return 1
    }
    health_ready || { error "Current capture telemetry or alert logging is unhealthy"; return 1; }
    alerts_ready "$pid" "$(alert_log_for_session "$main_session")" &&
        sudo -n test -f "$data_dir/alerts.jsonl"
}

prepare_backup_and_stage() {
    sudo -n install -d -o root -g root -m 0700 "$data_dir/backups" || return 1
    backup_dir=$(sudo -n mktemp -d "$data_dir/backups/rollout.XXXXXXXX") || return 1
    sudo -n install -o root -g root -m 0700 "$installed" "$backup_dir/packrat" || return 1
    sudo -n install -o root -g root -m 0600 "$data_dir/alerts.jsonl" "$backup_dir/alerts.jsonl" || return 1
    stage_binary=$(sudo -n mktemp /usr/local/bin/.packrat-stage.XXXXXXXX) || return 1
    sudo -n install -o root -g root -m 0755 "$candidate" "$stage_binary" || return 1
    cmp -s "$candidate" "$stage_binary"
}

replace_installed() {
    local source=$1 replacement
    replacement=$(sudo -n mktemp /usr/local/bin/.packrat-install.XXXXXXXX) || return 1
    if sudo -n install -o root -g root -m 0755 "$source" "$replacement" &&
       sudo -n cmp -s "$source" "$replacement" &&
       sudo -n mv -T "$replacement" "$installed"; then
        return 0
    fi
    sudo -n rm -f -- "$replacement"
    return 1
}

launch_capture() {
    local session=$1 executable=$2
    case $session in
        "$main_session")
            tmux new-session -d -s "$session" -c / -x 150 -y 40 \
                sudo -n -H "$executable" --telemetry-listen "$health_addr"
            ;;
        "$bridge_session")
            [[ -n $backup_dir ]] || return 1
            tmux new-session -d -s "$session" -c / -x 150 -y 40 \
                sudo -n -H env "XDG_DATA_HOME=$backup_dir/stage-data" "$executable"
            ;;
        *) return 1 ;;
    esac
}

start_capture() {
    local session=$1 executable=$2 index attempt count pid log baseline=
    log=$(alert_log_for_session "$session")
    index=$(printf '%s\n' /sys/class/net/* | LC_ALL=C sort |
        awk -F / -v iface="$interface" '$NF == iface { print NR-1 }')
    [[ $index =~ ^[0-9]+$ ]] || return 1
    launch_capture "$session" "$executable" || return 1
    for attempt in {1..10}; do
        if pane "$session" | grep -F 'Select network interface' >/dev/null; then break; fi
        sleep 1
    done
    pane "$session" | grep -F 'Select network interface' >/dev/null || return 1
    for ((attempt=0; attempt<index; attempt++)); do
        tmux send-keys -t "=$session:" Down || return 1
    done
    tmux send-keys -t "=$session:" Enter || return 1
    for attempt in {1..30}; do
        count=$(packet_count "$session")
        if [[ $count =~ ^[0-9]+$ ]]; then
            if [[ -n $baseline ]] && (( count > baseline )); then
                pid=$(capture_pid "$session" "$executable") || return 1
                if alerts_ready "$pid" "$log" && { [[ $session != "$main_session" ]] || health_ready; }; then
                    printf '%s: %s packet count increased to %s\n' "$session" "$interface" "$count"
                    return 0
                fi
            elif [[ -z $baseline ]]; then
                baseline=$count
            fi
        fi
        sleep 1
    done
    return 1
}

stop_capture() {
    local session=$1 executable=$2 pid
    if ! tmux has-session -t "=$session" 2>/dev/null; then return 0; fi
    [[ $(tmux display-message -p -t "=$session:" '#{session_attached}') == 0 ]] || return 1
    pid=$(capture_pid "$session" "$executable") || return 1
    tmux send-keys -t "=$session:" Escape C-c || return 1
    sleep 2
    if sudo -n kill -0 "$pid" 2>/dev/null; then
        [[ $(capture_pid "$session" "$executable") == "$pid" ]] || return 1
        sudo -n kill -TERM "$pid" || return 1
        sleep 1
    fi
    if sudo -n kill -0 "$pid" 2>/dev/null; then return 1; fi
    if tmux has-session -t "=$session" 2>/dev/null; then
        tmux kill-session -t "=$session" || return 1
    fi
}

retire_bridge() {
    stop_capture "$bridge_session" "$stage_binary" || return 1
    sudo -n rm -f -- "$stage_binary"
}

rollout() {
    prepare_backup_and_stage || { error "Backup or staging failed; current capture not stopped"; return 1; }
    printf 'Rollback binary: %s/packrat\n' "$backup_dir"
    printf 'Staging alert log: %s\n' "$(alert_log_for_session "$bridge_session")"
    if ! start_capture "$bridge_session" "$stage_binary"; then
        error "Candidate did not pass staging; current capture was not stopped"
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! stop_capture "$main_session" "$installed"; then
        error "Could not stop the current capture; verified staging capture left running"
        return 1
    fi
    if replace_installed "$stage_binary" && start_capture "$main_session" "$installed"; then
        retire_bridge || { error "Replacement is live; inspect the staging session"; return 1; }
        printf '%s\n' 'Rollout verified'
        return 0
    fi
    error "Replacement failed health checks; attempting rollback"
    if stop_capture "$main_session" "$installed" &&
       replace_installed "$backup_dir/packrat" &&
       start_capture "$main_session" "$installed"; then
        retire_bridge || error "Rollback is live; inspect the staging session"
        error "Previous capture restored; rollout failed"
    else
        error "Rollback could not be verified; staging capture left running"
    fi
    return 1
}

main() {
    if (( $# != 3 )) || [[ $1 != --check && $1 != --deploy ]]; then
        error 'Usage: bash packrat-rollout.sh --check|--deploy BUILT_PACKRAT INTERFACE'
        return 2
    fi
    mode=$1 candidate=$2 interface=$3
    [[ $interface =~ ^[A-Za-z0-9_.-]+$ ]] || { error "Invalid interface name"; return 2; }
    candidate=$(realpath -- "$candidate") || return 2
    if [[ $mode == --deploy ]]; then
        mkdir -p "$HOME/.cache" || return 1
        exec 9>"$HOME/.cache/packrat-rollout.lock" || return 1
        flock -n 9 || { error "Another rollout is in progress"; return 1; }
    fi
    preflight || return 1
    if [[ $mode == --check ]]; then
        printf 'Preflight passed for %s; no changes made\n' "$interface"
    elif cmp -s "$candidate" "$installed"; then
        printf '%s\n' 'Candidate is already installed; capture unchanged'
    else
        rollout
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
