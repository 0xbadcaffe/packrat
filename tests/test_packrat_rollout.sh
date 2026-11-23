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
        "capture_queue_full_packets":0,"capture_truncated_frames":0,
        "capture_run_id":"0000000000000001","capture_id":"00000000000000000000000000000002"}'
    if capture_health_sample; then exit 1; fi
    sample=$(jq -c '.archive_paused = false' <<< "$sample")
    if capture_health_sample; then exit 1; fi
    sample=$(jq -c '.archive_enabled = true' <<< "$sample")
    [[ $(capture_health_sample) == legacy ]]
    expected_addr=$stage_health_addr
    [[ $(capture_health_sample "$stage_health_addr" true) == legacy ]]
    good=$sample
    sample=$(jq -c '. + {capture_link_type:113,capture_link_decodable:false}' <<< "$good")
    if capture_health_sample "$stage_health_addr" true; then exit 1; fi
    sample=$(jq -c '. + {capture_link_type:1,capture_link_decodable:true}' <<< "$good")
    [[ $(capture_health_sample "$stage_health_addr" true) == legacy ]]
    for update in '.service = "other"' '.capture_interface = "eth0"' 'del(.capture_interface)' \
        '.capture_id = "invalid"' '.capture_run_id = null' '.pcap_buffer_drops = 1' \
        '.capture_queue_full_packets = 1' '.capture_truncated_frames = 1' 'del(.capture_queue_full_packets)' \
        '.capture_truncated_frames = "0"'; do
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
    if read_launch_profile "${profile[@]}" --archive "$archive" --archive-alert-evidence /other; then exit 1; fi
    rule=tcp.payload_after_observed_reset
    if read_launch_profile "${profile[@]}" --archive "$archive" --archive-evidence-rule "$rule"; then exit 1; fi
    if read_launch_profile "${profile[@]}" --archive-alert-evidence "$archive" --archive-evidence-rule "$rule" --archive-evidence-rule "$rule"; then exit 1; fi
    read_launch_profile "${profile[@]}" --archive-alert-evidence "$archive" --archive-max-frames 4096 --archive-evidence-rule "$rule"
    [[ $(launch_capture "$main_session" /candidate) == *$'<--archive-alert-evidence>\n<'"$archive"$'>\n<--archive-max-frames>\n<4096>\n<--archive-evidence-rule>\n<'"$rule>" ]]
    [[ $(launch_capture "$bridge_session" /candidate) == *$'<--archive-alert-evidence>\n</backup/stage-data/packet-archive>'*$'<--archive-evidence-rule>\n<'"$rule>" ]]
    sample=$good
    if capture_health_sample; then exit 1; fi
    sample=$(jq -c '.archive_alert_evidence_only = true' <<< "$good")
    [[ $(capture_health_sample) == legacy ]]
    if read_launch_profile "${profile[@]}" --single-tag-interface --archive; then exit 1; fi
    read_launch_profile "${profile[@]}" --single-tag-interface 'Access Link' --archive "$archive"
    [[ $(launch_capture "$main_session" /candidate) == *$'<--single-tag-interface>\n<Access Link>\n<--archive>'* ]]
    [[ $(launch_capture "$bridge_session" /candidate) == *$'<--single-tag-interface>\n<Access Link>\n<--archive>'* ]]
    read_launch_profile "${profile[@]}"
    [[ -z $archive_path && $archive_flag == --archive && ${#archive_limits[@]} == 0 && ${#vlan_policy_args[@]} == 0 ]]
)

scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
data_dir=$scratch
test_evidence_profile_opt_in() {
    local enable_alert_evidence=true archive_path='' archive_flag=--archive
    local -a archive_limits=()
    sudo() {
        shift
        if [[ $1 == stat ]]; then
            printf '%s:0\n' "${mock_mode:-41c0}"
        else
            command "$@"
        fi
    }
    (apply_requested_profile
     [[ $archive_path == "$data_dir/alert-evidence-archive" && $archive_flag == --archive-alert-evidence ]]
     [[ "${archive_limits[*]}" == '--archive-max-mib 64 --archive-max-frames 8192' ]])
    [[ -z $archive_path && ! -e $data_dir/alert-evidence-archive ]]
    if mock_mode=41ff apply_requested_profile; then exit 1; fi
    ln -s -- "$data_dir/missing" "$data_dir/alert-evidence-archive"
    if apply_requested_profile; then exit 1; fi
    unlink -- "$data_dir/alert-evidence-archive"
    archive_path=/already/archiving
    if apply_requested_profile; then exit 1; fi
}
test_evidence_profile_opt_in 2>"$scratch/profile-errors"
# shellcheck source=tests/support/rollout_counter_cases.bash
source "$root/tests/support/rollout_counter_cases.bash"
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
    [[ $1 == -n ]] || return 1
    case $2 in
        test|realpath) shift; command "$@"; return ;;
        mkdir) trace+=("reserve:${*: -1}"); [[ $scenario != evidence_reservation_lost ]]; return ;;
        stat) ;;
        *) return 1 ;;
    esac
    if [[ $3 == --format=%f:%u ]]; then printf '%s\n' '41c0:0'; return; fi
    if [[ ${3-} == --format=%f:%h:%u\ * ]]; then
        local format=${3#--format=}
        command stat --format="${format//%u/${PACKRAT_TEST_LOG_UID:-0}}" "${@:4}"
        return
    fi
    shift
    command "$@"
}

(
    backup_dir="$scratch/staging"
    log=$(alert_log_for_session "$bridge_session")
    mkdir -p -- "${log%/*}"
    if stage_alert_log_size 2>/dev/null; then exit 1; fi
    touch -- "$log"
    chmod 0600 -- "$log"
    [[ $(stage_alert_log_size) == 0 ]]
    printf '%s\n' "synthetic finding" >"$log"
    [[ $(stage_alert_log_size) == 18 ]]
    chmod 0644 -- "$log"
    if stage_alert_log_size; then exit 1; fi
)

printf '%s\n' 'initial alert' >"$data_dir/alerts.jsonl"
chmod 0600 -- "$data_dir/alerts.jsonl"
stamp=$(primary_alert_log_stamp)
[[ $(primary_alert_log_stamp) == "$stamp" ]]
printf '%s\n' 'new alert' >>"$data_dir/alerts.jsonl"
[[ $(primary_alert_log_stamp) != "$stamp" ]]
stamp=$(primary_alert_log_stamp)
cp -p -- "$data_dir/alerts.jsonl" "$data_dir/replacement"
mv -T -- "$data_dir/replacement" "$data_dir/alerts.jsonl"
[[ $(primary_alert_log_stamp) != "$stamp" ]]

(
    log="$data_dir/alerts.jsonl"
    if PACKRAT_TEST_LOG_UID=1000 primary_alert_log_stamp; then exit 1; fi
    ln -- "$log" "$data_dir/alias"
    if primary_alert_log_stamp; then exit 1; fi
    rm -- "$data_dir/alias"
    mv -- "$log" "$data_dir/original"
    ln -s -- "$data_dir/original" "$log"
    if primary_alert_log_stamp; then exit 1; fi
    rm -- "$log"
    mv -- "$data_dir/original" "$log"
)

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

test_backup_copies() {
    local data_dir="$scratch/backup-fixture"
    local installed="$data_dir/installed" backup_dir='' corrupt=''
    mkdir -p -- "$data_dir"
    printf '%s\n' original >"$installed"
    printf '%s\n' alert >"$data_dir/alerts.jsonl"
    sudo() {
        [[ $1 == -n ]] || return 1
        shift
        case $1 in
            install)
                if [[ $2 == -d ]]; then
                    mkdir -p -- "${*: -1}"
                else
                    command cp -- "${@: -2}" || return 1
                    if [[ -n $corrupt && ${*: -1} == */rollout.*/"$corrupt" ]]; then
                        printf '%s\n' damaged >"${*: -1}"
                    fi
                fi
                ;;
            mktemp|cmp) command "$@" ;;
            *) return 1 ;;
        esac
    }
    for corrupt in packrat alerts.jsonl; do
        if create_rollout_backup 2>/dev/null; then exit 1; fi
    done
    corrupt=
    create_rollout_backup
    cmp -s "$installed" "$backup_dir/packrat"
    cmp -s "$data_dir/alerts.jsonl" "$backup_dir/alerts.jsonl"
}

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
    if "$enable_alert_evidence"; then
        if [[ $require_zero == false ]]; then
            [[ -z $archive_path && $archive_flag == --archive && ${#archive_limits[@]} == 0 ]] || return 2
            trace+=("original-profile")
        else
            [[ $archive_path == "$data_dir/alert-evidence-archive" && $archive_flag == --archive-alert-evidence ]] || return 2
            trace+=("evidence-profile")
        fi
    fi
    if [[ $require_zero == false ]]; then trace+=("allow-existing-drops"); fi
    if [[ $session == "$bridge_session" ]]; then
        case $scenario in
            new_alert) printf '%s\n' 'new finding in primary' >>"$data_dir/alerts.jsonl" ;;
            log_permission_changed) chmod 0644 -- "$data_dir/alerts.jsonl" ;;
            log_disappears) mv -- "$data_dir/alerts.jsonl" "$data_dir/alerts.saved" ;;
            primary_changed) primary_stamp=other ;;
            primary_disappears) primary_stamp=unavailable ;;
        esac
        [[ $scenario != stage_fail ]]
    else
        main_starts=$((main_starts + 1))
        if [[ $scenario == rollback_fail ]]; then return 1; fi
        [[ ( $scenario != health_fail && $scenario != evidence_health_fail ) || $main_starts == 2 ]]
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
write_capture_receipt() { [[ $scenario != receipt_fail ]]; }
capture_health_sample() { [[ $* == "$stage_health_addr true" && $scenario != stage_loss_before_cutover ]]; }
alert_watcher_ready() {
    if [[ $scenario == last_moment_alert ]]; then printf '%s\n' late >>"$data_dir/alerts.jsonl"; fi
    [[ $scenario != watcher_lost_before_cutover ]]
}
await_primary_watcher() { [[ $scenario != watcher_lost_after_cutover && ( $scenario != analyzer_watcher_fail || $main_starts != 1 ) ]]; }
promote_companions() { if [[ $scenario == analyzer_* ]]; then trace+=("analyzer"); [[ $scenario == analyzer_success ]]; fi; }
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
    local archive_path='' archive_flag=--archive enable_alert_evidence=false analyzer_candidate=''
    local -a archive_limits=()
    if [[ $scenario == evidence_* ]]; then enable_alert_evidence=true; fi
    if [[ $scenario == primary_missing ]]; then primary_stamp=unavailable; elif [[ $scenario == analyzer_* ]]; then analyzer_candidate=/candidate-analyzer; fi
    rollout >"$scratch/rollout-output" 2>&1 || actual=$?
    if [[ $actual != "$expected" ]]; then
        printf 'Unexpected %s exit: got %s, expected %s\n' "$scenario" "$actual" "$expected" >&2
        return 1
    fi
    if [[ $scenario == receipt_fail ]]; then
        grep -Fq 'Replacement remains live; rollout was not verified' "$scratch/rollout-output"
        if grep -Fxq 'Rollout verified' "$scratch/rollout-output"; then return 1; fi
    fi
    if [[ "${trace[*]}" != "$*" ]]; then
        printf 'Unexpected %s trace: %s\n' "$scenario" "${trace[*]}" >&2
        return 1
    fi
}

run_scenario backup_fail 1 backup
run_scenario stage_fail 1 backup start:packrat-stage:/candidate retire-stage
run_scenario new_alert 1 backup start:packrat-stage:/candidate retire-stage
run_scenario log_permission_changed 1 backup start:packrat-stage:/candidate retire-stage
chmod 0600 -- "$data_dir/alerts.jsonl"
run_scenario log_disappears 1 backup start:packrat-stage:/candidate retire-stage
run_scenario log_missing 1
mv -- "$data_dir/alerts.saved" "$data_dir/alerts.jsonl"
run_scenario primary_missing 1
run_scenario primary_changed 1 backup start:packrat-stage:/candidate retire-stage
run_scenario primary_disappears 1 backup start:packrat-stage:/candidate retire-stage
run_scenario watcher_lost_before_cutover 1 backup start:packrat-stage:/candidate retire-stage
run_scenario last_moment_alert 1 backup start:packrat-stage:/candidate retire-stage
run_scenario staged_finding 1 backup start:packrat-stage:/candidate retire-stage
run_scenario staged_log_missing 1 backup start:packrat-stage:/candidate retire-stage
run_scenario stage_loss_before_cutover 1 backup start:packrat-stage:/candidate retire-stage
run_scenario cannot_stop 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat
run_scenario success 0 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat retire-stage
run_scenario receipt_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
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
run_scenario evidence_success 0 backup start:packrat-stage:/candidate evidence-profile \
    "reserve:$data_dir/alert-evidence-archive" stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat evidence-profile retire-stage
run_scenario evidence_reservation_lost 1 backup start:packrat-stage:/candidate evidence-profile \
    "reserve:$data_dir/alert-evidence-archive" retire-stage
run_scenario evidence_health_fail 1 backup start:packrat-stage:/candidate evidence-profile \
    "reserve:$data_dir/alert-evidence-archive" stop:packrat:/usr/local/bin/packrat install:/candidate \
    start:packrat:/usr/local/bin/packrat evidence-profile stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat original-profile allow-existing-drops retire-stage

rc=0
bash "$root/scripts/packrat-rollout.sh" --deploy /missing 'invalid/interface' >/dev/null 2>&1 || rc=$?
[[ $rc == 2 ]]
# shellcheck source=tests/support/rollout_release_cases.bash
source "$root/tests/support/rollout_release_cases.bash"
test_backup_copies
printf '%s\n' 'Packrat rollout tests passed'
