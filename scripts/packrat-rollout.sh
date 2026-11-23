#!/usr/bin/env bash
# Supervised rollout for one Linux tmux capture host. No remote execution.
set -uo pipefail

rollout_script=$(realpath -- "${BASH_SOURCE[0]}") || exit 1
# shellcheck source=scripts/packrat-rollout-profile.sh
source "${rollout_script%/*}/packrat-rollout-profile.sh" || exit 1
# shellcheck source=scripts/packrat-rollout-release.sh
source "${rollout_script%/*}/packrat-rollout-release.sh" || exit 1

installed=/usr/local/bin/packrat
data_dir=/root/.local/share/packrat
main_session=packrat
bridge_session=packrat-stage
health_addr=127.0.0.1:9477
stage_health_addr=127.0.0.1:9478
health_state=${PACKRAT_ROLLOUT_HEALTH_STATE:-"$HOME/.cache/packrat-health/latest.json"}
triage_state=${PACKRAT_ROLLOUT_TRIAGE_STATE:-}
triage_check=${PACKRAT_ROLLOUT_TRIAGE_CHECK:-"$HOME/.local/bin/packrat-watch-triage"}
triage_journal_required=${PACKRAT_ROLLOUT_REQUIRE_TRIAGE_JOURNAL:-0}
allow_historical_drops=${PACKRAT_ROLLOUT_ALLOW_HISTORICAL_DROPS:-0}
backup_reserve_mib=${PACKRAT_ROLLOUT_BACKUP_RESERVE_MIB:-512}
backup_dir=
stage_binary=
archive_path=
archive_flag=--archive
archive_limits=() archive_rule_args=() vlan_policy_args=()
enable_alert_evidence=false

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

capture_health_sample() {
    local address=${1:-$health_addr} require_fresh_capture=${2:-false}
    curl --disable --fail --silent --noproxy '*' --max-time 3 "http://$address/health" |
        jq -er --arg archive "$archive_path" --arg interface "$interface" --argjson fresh "$require_fresh_capture" \
            --argjson evidence_only "$([[ $archive_flag == --archive-alert-evidence ]] && printf true || printf false)" '
            def scoped:
                .capture_interface == $interface
                and (.capture_run_id | type == "string" and test("\\A[0-9a-f]{16}\\z"))
                and (.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"));
            select(.status == "ok" and .service == "packrat"
            and .telemetry_fresh == true and .capture_active == true and .alert_saving == true
            and (.alert_save_failed | not)
            and .capture_link_decodable != false
            and (.pcap_buffer_drops | type == "number" and . >= 0 and . <= 4294967295 and floor == .)
            and (if $fresh then .pcap_buffer_drops == 0 and scoped
                 else .capture_interface == null or .capture_interface == $interface end)
            and ($archive == "" or (.archive_enabled == true and .archive_paused == false
                and (if $evidence_only then .archive_alert_evidence_only == true
                     else .archive_alert_evidence_only != true end))))
            | if has("packets_total") then
                select(scoped and (.packets_total | type == "number" and . >= 0
                    and . <= 9007199254740991 and floor == .))
                | "\(.packets_total) \(.capture_run_id):\(.capture_id)"
              else "legacy" end
        '
}

capture_progress_sample() {
    local session=$1 health_row count
    health_row=$(capture_health_sample "$2" "$3") || return 1
    if [[ $health_row == legacy ]]; then
        count=$(packet_count "$session") || return 1
        [[ $count =~ ^(0|[1-9][0-9]{0,17})$ ]] || return 1
        health_row="$count legacy"
    fi
    printf '%s\n' "$health_row"
}

capture_file_open() {
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

private_alert_log_stat() {
    local row
    row=$(sudo -n stat --format="%f:%h:%u $2" -- "$1") || return 1
    [[ $row =~ ^([0-9a-fA-F]{1,8}):1:0\ (.+)$ ]] || return 1
    (( (16#${BASH_REMATCH[1]} & 0170077) == 0100000 )) || return 1
    printf '%s\n' "${BASH_REMATCH[2]}"
}
primary_alert_log_stamp() { private_alert_log_stat "$data_dir/alerts.jsonl" '%d:%i:%s:%y:%z'; }
primary_alert_log_identity() { private_alert_log_stat "$data_dir/alerts.jsonl" '%d:%i'; }
stage_alert_log_size() { private_alert_log_stat "$(alert_log_for_session "$bridge_session")" '%s'; }

primary_capture_stamp() {
    local pid
    pid=$(capture_pid "$main_session" "$installed") || return 1
    curl --disable --fail --silent --noproxy '*' --max-time 3 "http://$health_addr/health" |
        jq -ce --arg pid "$pid" '
            select(.service == "packrat" and .status == "ok"
                and .telemetry_fresh == true and .capture_active == true)
            | {pid:$pid, capture_run_id, capture_id, alert_session_id}
        '
}

triage_watcher_ready() {
    [[ -n $triage_state ]] || return 0
    local check code=0 drops=${2:-0}
    check=$(timeout 5s "$triage_check" --check "$triage_state") || code=$?
    jq -se --argjson scope "$1" --argjson require_journal "$triage_journal_required" \
        --argjson drops "$drops" --argjson code "$code" --arg archive "$archive_candidate" \
        --argjson after "${triage_after:-0}" '
        length == 1 and (.[0] |
            (($code == 0 and .status == "current") or ($code == 1 and $drops > 0
                and .status == "triage_unhealthy" and .historical_drop_total == $drops)) and
            .capture_id == $scope.capture_id and .session_id == $scope.alert_session_id and
            ($archive == "" or (.poll_started_at | type == "number" and . > $after)) and
            ($require_journal == 0 or (.journal_status == "current" and .journal_pending_events == 0)))
    ' <<< "$check" >/dev/null
}

alert_watcher_ready() {
    local capture_stamp=$1 identity latest_identity drops
    [[ -f $health_state ]] || return 1
    identity=$(primary_alert_log_identity) && [[ $identity =~ ^[0-9]{1,20}:[0-9]{1,20}$ ]] || return 1
    if ! drops=$(head -c 65537 -- "$health_state" |
        jq -Rse --argjson scope "$capture_stamp" --arg log "$data_dir/alerts.jsonl" --arg identity "$identity" \
            --argjson now "$(date -u +%s)" --argjson allow "${2:-0}" '
            select(utf8bytelength <= 65536) | fromjson | objects
            | . as $sample
            | (.timestamp | fromdateiso8601) as $observed
            | (.poll_interval_seconds | select(
                type == "number" and floor == . and . >= 1 and . <= 999999
              )) as $interval
            | select($sample.record_type == "capture_health"
              and $now >= $observed and $now - $observed <= $interval * 3 + 5
              and $sample.capture_active == true and $sample.telemetry_fresh == true
              and ($scope.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"))
              and ($scope.capture_run_id | type == "string" and test("\\A[0-9a-f]{16}\\z"))
              and ($scope.alert_session_id | type == "string" and test("\\A[0-9]+-[0-9]+\\z"))
              and $sample.capture_id == $scope.capture_id
              and $sample.capture_run_id == $scope.capture_run_id
              and $sample.alert_session_id == $scope.alert_session_id
              and $sample.alert_watcher_alive == true
              and $sample.alert_watcher_pipeline_alive == true
              and $sample.alert_watcher_source_matches == true
              and $sample.alert_watcher_open_log_required == true
              and $sample.alert_log_identity == $identity
              and $sample.alert_watcher_log == $log and $sample.alert_log_storage == "private")
            | if $allow == 0 or (.issues == [] and .pcap_buffer_drops == 0) then 0
              elif .issues == ["pcap_buffer_drops"] and .pcap_buffer_drops_delta == 0
              then .pcap_buffer_drops | select(type == "number" and . > 0 and . <= 4294967295 and floor == .)
              else empty end
        ' 2>/dev/null); then
        return 1
    fi
    if (( drops > 0 )) && ! curl --disable --fail --silent --noproxy '*' --max-time 3 "http://$health_addr/health" |
        jq -e --argjson scope "$capture_stamp" --argjson drops "$drops" '
            .capture_id == $scope.capture_id and .capture_run_id == $scope.capture_run_id and
            .alert_session_id == $scope.alert_session_id and .pcap_buffer_drops == $drops and
            .status == "ok" and .telemetry_fresh == true and .capture_active == true
        ' >/dev/null; then return 1; fi
    latest_identity=$(primary_alert_log_identity) && [[ $latest_identity == "$identity" ]] &&
        triage_watcher_ready "$capture_stamp" "$drops"
}

await_primary_watcher() {
    local stamp attempt limit=30
    if [[ -n $triage_state ]]; then limit=90; fi
    for ((attempt=0; attempt<limit; attempt++)); do
        if stamp=$(primary_capture_stamp) && alert_watcher_ready "$stamp" "${1:-0}"; then return 0; fi
        sleep 1
    done
    return 1
}

preflight() {
    local pid
    local -a current_args
    [[ -f $candidate && -x $candidate ]] || { error "Candidate is not executable"; return 1; }
    [[ -d /sys/class/net/$interface ]] || { error "No such network interface: $interface"; return 1; }
    sudo -n true || return 1
    [[ $(tmux display-message -p -t "=$main_session:" '#{session_attached}') == 0 ]] ||
        { error "The capture session is missing or has an attached operator"; return 1; }
    if tmux has-session -t "=$bridge_session" 2>/dev/null; then
        error "A staging session already exists; inspect it before another rollout"
        return 1
    fi
    pid=$(capture_pid "$main_session" "$installed") || { error "Cannot identify installed capture"; return 1; }
    mapfile -d '' -t current_args < "/proc/$pid/cmdline" || return 1
    if ! read_launch_profile "${current_args[@]}"; then
        error "Current capture uses a different launch profile; refusing to drop its options"
        return 1
    fi
    if ! (apply_requested_profile && candidate_supports_profile); then
        error "Candidate cannot use the requested capture profile"
        return 1
    fi
    capture_progress_sample "$main_session" "$health_addr" false >/dev/null ||
        { error "Cannot verify current capture progress on $interface"; return 1; }
    capture_storage_ready "$pid" "$main_session" || return 1
    primary_alert_log_stamp >/dev/null || { error "Primary alert log is not a private, root-owned regular file with one link"; return 1; }
    local stamp
    if ! stamp=$(primary_capture_stamp) || ! alert_watcher_ready "$stamp" "$allow_historical_drops"; then
        error "Cannot verify primary alert monitoring; check $health_state and any configured triage state"
        return 1
    fi
}

launch_capture() {
    local session=$1 executable=$2 archive
    local -a archive_args=("${vlan_policy_args[@]}")
    archive=$(archive_for_session "$session")
    if [[ -n $archive ]]; then archive_args+=("$archive_flag" "$archive" "${archive_limits[@]}" "${archive_rule_args[@]}"); fi
    case $session in
        "$main_session")
            tmux new-session -d -s "$session" -c / -x 150 -y 40 \
                sudo -n -H "$executable" --telemetry-listen "$health_addr" "${archive_args[@]}"
            ;;
        "$bridge_session")
            [[ -n $backup_dir ]] || return 1
            tmux new-session -d -s "$session" -c / -x 150 -y 40 \
                sudo -n -H env "XDG_DATA_HOME=$backup_dir/stage-data" "$executable" \
                    --telemetry-listen "$stage_health_addr" "${archive_args[@]}"
            ;;
        *) return 1 ;;
    esac
}

start_capture() {
    local session=$1 executable=$2 require_fresh_capture=${3:-true}
    local index attempt
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
    verify_capture_progress "$session" "$executable" "$require_fresh_capture"
}

verify_capture_progress() {
    local session=$1 executable=$2 require_fresh_capture=$3
    local attempt sample count scope pid address=$health_addr
    local stable=0 first_count=0 last_count=0 stable_pid='' stable_scope=''
    if [[ $session == "$bridge_session" ]]; then address=$stage_health_addr; fi
    for attempt in {1..30}; do
        if sample=$(capture_progress_sample "$session" "$address" "$require_fresh_capture") &&
           read -r count scope <<< "$sample" &&
           pid=$(capture_pid "$session" "$executable") &&
           capture_storage_ready "$pid" "$session"; then
            if [[ $pid != "$stable_pid" || $scope != "$stable_scope" ]] ||
                (( stable == 0 || count < last_count )); then
                stable=0
                stable_pid=$pid
                stable_scope=$scope
                first_count=$count
            fi
            last_count=$count
            stable=$((stable + 1))
            if (( stable >= 3 && count > first_count )); then
                printf '%s: %s packet count increased from %s to %s across %s healthy samples\n' \
                    "$session" "$interface" "$first_count" "$count" "$stable"
                return 0
            fi
        else
            stable=0
        fi
        sleep 1
    done
    return 1
}

stop_capture() {
    local session=$1 executable=$2 expected_pid=${3:-} pid
    if ! tmux has-session -t "=$session" 2>/dev/null; then
        [[ -z $expected_pid ]]
        return
    fi
    [[ $(tmux display-message -p -t "=$session:" '#{session_attached}') == 0 ]] || return 1
    pid=$(capture_pid "$session" "$executable") || return 1
    [[ -z $expected_pid || $pid == "$expected_pid" ]] || return 1
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
    local alert_log_before alert_log_now primary_before primary_now primary_pid stage_size
    local original_archive_path=$archive_path original_archive_flag=$archive_flag
    local -a original_archive_limits=("${archive_limits[@]}")
    alert_log_before=$(primary_alert_log_stamp) && [[ -n $alert_log_before ]] ||
        { error "Cannot check the primary alert log; current capture not stopped"; return 1; }
    if ! primary_before=$(primary_capture_stamp) ||
       ! primary_pid=$(jq -er '.pid | strings | select(test("^[1-9][0-9]*$"))' <<< "$primary_before"); then
        error "Cannot verify the primary capture identity; current capture not stopped"
        return 1
    fi
    apply_requested_profile || { error "Archive profile changed; current capture not stopped"; return 1; }
    prepare_backup_and_stage || { error "Backup or staging failed; current capture not stopped"; return 1; }
    printf 'Rollback binary: %s/packrat\n' "$backup_dir"
    printf 'Staging alert log: %s\n' "$(alert_log_for_session "$bridge_session")"
    if [[ -n $archive_path ]]; then
        printf 'Staging packet archive: %s\n' "$(archive_for_session "$bridge_session")"
    fi
    if ! start_capture "$bridge_session" "$stage_binary"; then
        error "Candidate did not pass staging; current capture was not stopped"
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! alert_log_now=$(primary_alert_log_stamp) || [[ $alert_log_now != "$alert_log_before" ]]; then
        error "Primary alert log changed or is unavailable; review its evidence before retrying. Current capture not stopped."
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! primary_now=$(primary_capture_stamp) || [[ $primary_now != "$primary_before" ]]; then
        error "Primary capture changed or is unavailable; stage not promoted. Current capture not stopped."
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! alert_watcher_ready "$primary_now" "$allow_historical_drops"; then
        error "Could not verify primary alert monitoring; current capture not stopped"
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! stage_size=$(stage_alert_log_size) || [[ ! $stage_size =~ ^[0-9]+$ ]]; then
        error "Cannot verify the staging alert log; current capture not stopped"
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if [[ $stage_size != 0 ]]; then
        error "Staging recorded alert data; review the staging alert log before retrying. Current capture not stopped."
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if "$enable_alert_evidence" && ! sudo -n mkdir -m 0700 -- "$archive_path"; then
        error "Could not reserve the private packet archive; current capture not stopped"
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! alert_log_now=$(primary_alert_log_stamp) || [[ $alert_log_now != "$alert_log_before" ]]; then
        error "Primary alert log changed during the final cutover checks; current capture not stopped"
        if "$enable_alert_evidence"; then
            sudo -n rmdir -- "$archive_path" || error "Inspect the reserved archive before retrying"
        fi
        retire_bridge || error "Inspect $bridge_session before retrying"
        return 1
    fi
    if ! stop_capture "$main_session" "$installed" "$primary_pid"; then
        error "Could not stop the current capture; verified staging capture left running"
        return 1
    fi
    if replace_installed "$stage_binary" && start_capture "$main_session" "$installed"; then
        if ! await_primary_watcher; then
            if ! companion_update_selected; then
                error "Replacement is live but alert monitoring could not be verified; staging capture left running"
                return 1
            fi
            error "Replacement alert monitoring could not be verified; companions not promoted"
        elif promote_companions; then
            retire_bridge || { error "Replacement is live; inspect the staging session"; return 1; }
            printf '%s\n' 'Rollout verified'
            return 0
        else
            error "Companion installation failed; inspect rollback files under $backup_dir"
        fi
    fi
    error "Replacement failed health checks; attempting rollback"
    archive_path=$original_archive_path archive_flag=$original_archive_flag
    archive_limits=("${original_archive_limits[@]}")
    if stop_capture "$main_session" "$installed" &&
       replace_installed "$backup_dir/packrat" &&
       start_capture "$main_session" "$installed" false; then
        if await_primary_watcher; then
            retire_bridge || error "Rollback is live; inspect the staging session"
        else
            error "Rollback is live but alert monitoring could not be verified; staging capture left running"
        fi
        error "Previous capture restored; rollout failed"
    else
        error "Rollback could not be verified; staging capture left running"
    fi
    return 1
}

main() {
    if (( $# < 3 || $# > 4 )) || [[ $1 != --check && $1 != --deploy ]] ||
       [[ $# == 4 && $4 != --enable-alert-evidence ]]; then
        error 'Usage: bash packrat-rollout.sh --check|--deploy BUILT_PACKRAT INTERFACE [--enable-alert-evidence]'
        error 'The opt-in enables a new private archive for HIGH/CRITICAL evidence only (64 MiB packet bytes, 8192 frames).'
        error 'Set PACKRAT_ROLLOUT_HEALTH_STATE to override the watcher snapshot path.'
        error 'Set PACKRAT_ROLLOUT_ANALYZER to stage and promote a matching packrat-analyze binary.'
        error 'Set PACKRAT_ROLLOUT_ARCHIVE to stage and promote a matching packrat-archive binary.'
        error 'Set PACKRAT_ROLLOUT_TRIAGE_STATE to require fresh triage for the same capture.'
        error 'PACKRAT_ROLLOUT_TRIAGE_CHECK overrides the triage watcher executable.'
        error 'PACKRAT_ROLLOUT_REQUIRE_TRIAGE_JOURNAL=1 requires healthy journal writes and no backlog.'
        error 'PACKRAT_ROLLOUT_ALLOW_HISTORICAL_DROPS=1 allows replacing a capture with verified past drops only.'
        error 'The health watcher must run with PACKRAT_ALERT_VERIFY_OPEN=1 and verify the current alert log.'
        error 'PACKRAT_ROLLOUT_BACKUP_RESERVE_MIB sets free space to leave after backing up (default: 512).'
        return 2
    fi
    mode=$1 candidate=$2 interface=$3
    if [[ ! $allow_historical_drops =~ ^[01]$ || ( $allow_historical_drops == 1 && $triage_journal_required != 1 ) ]]; then
        error 'The historical-drop override requires PACKRAT_ROLLOUT_REQUIRE_TRIAGE_JOURNAL=1.'
        return 2
    fi
    if [[ ! $triage_journal_required =~ ^[01]$ || ( $triage_journal_required == 1 && -z $triage_state ) ]]; then
        error 'Journal verification requires PACKRAT_ROLLOUT_REQUIRE_TRIAGE_JOURNAL=0 or 1, and a triage state when enabled.'
        return 2
    fi
    if [[ ${4-} == --enable-alert-evidence ]]; then enable_alert_evidence=true; fi
    [[ $interface =~ ^[A-Za-z0-9_.-]+$ ]] || { error "Invalid interface name"; return 2; }
    candidate=$(realpath -- "$candidate") || return 2
    if [[ $mode == --deploy ]]; then
        mkdir -p "$HOME/.cache" || return 1
        exec 9>"$HOME/.cache/packrat-rollout.lock" || return 1
        flock -n 9 || { error "Another rollout is in progress"; return 1; }
    fi
    companion_candidates_ready || { error "Companion candidate or installed rollback binary is not usable"; return 1; }
    preflight || return 1
    if ! backup_space_ready; then
        error "Insufficient or unverified free space for the alert log and rollback backup; current capture not stopped"
        return 1
    fi
    if [[ $mode == --check ]]; then
        printf 'Preflight passed for %s; no changes made\n' "$interface"
    elif ! "$enable_alert_evidence" && cmp -s "$candidate" "$installed"; then
        update_companions_only
    else
        rollout
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
