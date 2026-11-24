#!/usr/bin/env bash

analyzer_candidate=${PACKRAT_ROLLOUT_ANALYZER:-}
archive_candidate=${PACKRAT_ROLLOUT_ARCHIVE:-}
baseline_recorder=${PACKRAT_ROLLOUT_BASELINE_RECORDER-"$HOME/.local/bin/packrat-watch-baseline"}
installed_analyzer=/usr/local/bin/packrat-analyze
installed_archive=/usr/local/bin/packrat-archive
companion_tools=(analyzer archive)
companion_update_selected() { [[ -n $analyzer_candidate || -n $archive_candidate ]]; }

primary_capture_stamp() {
    local pid
    pid=$(capture_pid "$main_session" "$installed") || return 1
    curl --disable --fail --silent --noproxy '*' --max-time 3 "http://$health_addr/health" |
        jq -ce --arg pid "$pid" '
            def optional_count: . == null or (type == "number" and . >= 0 and . <= 9007199254740991 and floor == .);
            select(.service == "packrat" and .status == "ok" and .telemetry_fresh == true and .capture_active == true
                and .alert_saving == true and (.alert_save_failed | not)
                and (.alert_save_failures | optional_count) and (.alert_save_backlog_dropped | optional_count))
            | {pid:$pid, capture_run_id, capture_id, alert_session_id, alert_save_failures, alert_save_backlog_dropped}
        '
}

identify_capture_build() {
    local before after pid running installed_hash progress packets scope timestamp
    before=$(primary_capture_stamp) || return 1
    pid=$(jq -er '.pid | strings | select(test("\\A[1-9][0-9]*\\z"))' <<< "$before") || return 1
    running=$(sudo -n sha256sum -- "/proc/$pid/exe") || return 1
    installed_hash=$(sha256sum -- "$installed") || return 1
    running=${running%% *} installed_hash=${installed_hash%% *}
    [[ $running =~ ^[0-9a-f]{64}$ && $running == "$installed_hash" ]] || return 1
    progress=$(capture_progress_sample "$main_session" "$health_addr" false) || return 1
    read -r packets scope <<< "$progress"
    [[ $packets =~ ^(0|[1-9][0-9]{0,15})$ ]] || return 1
    jq -e --arg scope "$scope" '($scope == (.capture_run_id + ":" + .capture_id))' <<< "$before" >/dev/null || return 1
    alert_watcher_ready "$before" || return 1
    after=$(primary_capture_stamp) || return 1
    [[ $before == "$after" ]] || return 1
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ) || return 1
    jq -c --arg interface "$interface" --arg sha256 "$running" --arg observed_at "$timestamp" \
        --argjson packets "$packets" '{record_type:"verified_capture_build",observed_at:$observed_at,
         interface:$interface,scope:{capture_id,session_id:.alert_session_id},capture_run_id,packets:$packets,sha256:$sha256}' <<< "$before"
}

write_capture_receipt() {
    local proof staged receipt="$backup_dir/verified-capture.json"
    proof=$(identify_capture_build) || return 1
    staged=$(sudo -n mktemp "$backup_dir/.verified-capture.XXXXXXXX") || return 1
    if ! printf '%s\n' "$proof" | sudo -n tee "$staged" >/dev/null ||
       ! sudo -n mv -fT -- "$staged" "$receipt"; then
        sudo -n rm -f -- "$staged"
        return 1
    fi
    printf 'Verified capture receipt: %s\n' "$receipt"
}

record_pre_cutover_baseline() (
    [[ -n $triage_state && -n $baseline_recorder && -x $baseline_recorder ]] || return 0
    local capture_stamp=$1 scratch hash receipt="$backup_dir/before-baseline.json"
    hash=$(sudo -n sha256sum -- "$backup_dir/packrat") || return 1
    hash=${hash%% *}
    umask 077
    scratch=$(mktemp -d) || return 1
    trap 'rm -rf -- "$scratch"' EXIT
    timeout --kill-after=1s 15s "$baseline_recorder" --record "$interface" "$triage_state" "$scratch/baseline.json" &&
        jq -es --argjson scope "$capture_stamp" --arg interface "$interface" --arg hash "$hash" '
            length == 1 and (.[0] | .record_type == "capture_build_baseline"
                and .build.sha256 == $hash and .build.interface == $interface and .build.capture_run_id == $scope.capture_run_id
                and .build.scope == {capture_id:$scope.capture_id,session_id:$scope.alert_session_id}
                and .coverage.scope == .build.scope)
        ' "$scratch/baseline.json" >/dev/null &&
        sudo -n install -o root -g root -m 0600 -- "$scratch/baseline.json" "$receipt" &&
        printf 'Pre-cutover baseline: %s\n' "$receipt"
)

triage_watcher_ready() {
    [[ -n $triage_state ]] || return 0
    local check packets code=0 drops=${2:-0} gap_free=${3:-0}
    check=$(timeout 5s "$triage_check" --check "$triage_state") || code=$?
    packets=$(jq -ser --argjson scope "$1" --argjson require_journal "$triage_journal_required" \
        --argjson drops "$drops" --argjson code "$code" --arg archive "$archive_candidate" \
        --argjson after "${triage_after:-0}" --argjson gap_free "$gap_free" '
        def counter: type == "number" and floor == . and . >= 0 and . <= 9007199254740991;
        select(length == 1) | .[0] | objects
        | select((($code == 0 and .status == "current") or ($code == 1 and $drops > 0
            and .status == "triage_unhealthy" and .historical_drop_total == $drops))
            and .capture_id == $scope.capture_id and .session_id == $scope.alert_session_id
            and ($gap_free == 0 or (.packet_counter_gap == false and .alert_sample_gap == false))
            and ($archive == "" or (.poll_started_at | type == "number" and . > $after))
            and ($require_journal == 0 or (.journal_status == "current" and .journal_pending_events == 0)))
        | if .packets == null and $gap_free == 0 then "legacy" else .packets | select(counter) end
    ' <<< "$check") || return 1
    [[ $packets != legacy ]] || return 0
    # The watcher sample can lag, but must not be ahead of live telemetry in the same scope.
    curl --disable --fail --silent --noproxy '*' --max-time 3 "http://$health_addr/health" |
        jq -se --argjson scope "$1" --argjson packets "$packets" --argjson gap_free "$gap_free" '
        length == 1 and (.[0] | .service == "packrat" and .status == "ok"
            and .telemetry_fresh == true and .capture_active == true
            and .capture_id == $scope.capture_id and .capture_run_id == $scope.capture_run_id
            and .alert_session_id == $scope.alert_session_id
            and ($gap_free == 0 or (.pcap_buffer_drops == 0 and .capture_queue_full_packets == 0
                and .capture_truncated_frames == 0))
            and (.packets_total | type == "number" and floor == . and . <= 9007199254740991 and . >= $packets))
    ' >/dev/null
}

companion_candidates_ready() {
    local tool proposed destination resolved help
    for tool in "${companion_tools[@]}"; do
        proposed="${tool}_candidate" destination="installed_$tool"
        [[ -n ${!proposed} ]] || continue
        resolved=$(realpath -- "${!proposed}") &&
            [[ -f $resolved && -x $resolved &&
               -f ${!destination} && -x ${!destination} && ! -L ${!destination} ]] &&
            help=$(timeout 5s "$resolved" --help) &&
            [[ $help == "Usage: ${!destination##*/} "* ]] || return 1
        printf -v "$proposed" '%s' "$resolved"
    done
}

backup_space_ready() {
    local destination="$data_dir/backups" free_kib sizes reserve=$backup_reserve_mib tool proposed current
    local staging_mib=256 i
    local -a files=("$installed" "$data_dir/alerts.jsonl")
    for tool in "${companion_tools[@]}"; do
        proposed="${tool}_candidate" current="installed_$tool"
        if [[ -n ${!proposed} ]]; then files+=("${!current}" "${!proposed}"); fi
    done
    sudo -n test -d "$destination" || destination=$data_dir
    free_kib=$(sudo -n env LC_ALL=C df -Pk -- "$destination" | awk 'NR == 2 { print $4 }') || return 1
    sizes=$(sudo -n stat --format='%s' -- "${files[@]}") || return 1
    [[ $free_kib =~ ^[0-9]{1,15}$ && $backup_reserve_mib =~ ^[1-9][0-9]{0,5}$ ]] || return 1
    if "$enable_alert_evidence"; then
        reserve=$((reserve + 2 * evidence_max_mib))
    elif [[ -n $archive_path && ${1-} != --companions-only ]] &&
            { archive_policy_changes || ! cmp -s -- "${candidate-}" "$installed"; }; then
        # The staging capture writes a separate archive under the rollback directory.
        for ((i=0; i<${#archive_limits[@]}; i+=2)); do
            if [[ ${archive_limits[i]} == --archive-max-mib ]]; then
                staging_mib=${archive_limits[i+1]}
                [[ $staging_mib =~ ^[1-9][0-9]{0,8}$ ]] || return 1
                break
            fi
        done
        reserve=$((reserve + staging_mib))
    fi
    awk -v free="$free_kib" -v reserve="$reserve" -v expected="${#files[@]}" '
        /^[0-9]+$/ && length($0) <= 15 { size_kib += int(($0 + 1023) / 1024); sizes++ }
        END { exit !(NR == expected && sizes == expected && free >= reserve * 1024 + size_kib) }
    ' <<< "$sizes"
}

create_rollout_backup() {
    sudo -n install -d -o root -g root -m 0700 "$data_dir/backups" || return 1
    backup_dir=$(sudo -n mktemp -d "$data_dir/backups/rollout.XXXXXXXX") || return 1
    sudo -n install -o root -g root -m 0700 "$installed" "$backup_dir/packrat" || return 1
    sudo -n install -o root -g root -m 0600 "$data_dir/alerts.jsonl" "$backup_dir/alerts.jsonl" || return 1
    if ! sudo -n cmp -s -- "$installed" "$backup_dir/packrat" ||
       ! sudo -n cmp -s -- "$data_dir/alerts.jsonl" "$backup_dir/alerts.jsonl"; then
        error "Rollback backup did not match its source; inspect $backup_dir"
        return 1
    fi
}

stage_companion_updates() {
    local tool proposed destination previous
    for tool in "${companion_tools[@]}"; do
        proposed="${tool}_candidate" destination="installed_$tool"
        [[ -n ${!proposed} ]] || continue
        previous="$backup_dir/${!destination##*/}"
        sudo -n install -o root -g root -m 0700 "${!destination}" "$previous" &&
            sudo -n cmp -s -- "${!destination}" "$previous" &&
            sudo -n install -o root -g root -m 0700 "${!proposed}" "$previous.next" &&
            sudo -n cmp -s -- "${!proposed}" "$previous.next" || return 1
    done
}

prepare_backup_and_stage() {
    create_rollout_backup && stage_companion_updates || return 1
    stage_binary=$(sudo -n mktemp /usr/local/bin/.packrat-stage.XXXXXXXX) || return 1
    sudo -n install -o root -g root -m 0755 "$candidate" "$stage_binary" || return 1
    cmp -s "$candidate" "$stage_binary"
}

replace_installed() {
    local source=$1 destination=${2:-$installed} replacement
    replacement=$(sudo -n mktemp "${destination%/*}/.packrat-install.XXXXXXXX") || return 1
    if sudo -n install -o root -g root -m 0755 "$source" "$replacement" &&
       sudo -n cmp -s "$source" "$replacement" &&
       sudo -n mv -T "$replacement" "$destination"; then
        return 0
    fi
    sudo -n rm -f -- "$replacement"
    return 1
}

restore_companions() {
    local destination previous i
    for ((i=$#; i>0; i--)); do
        destination=${!i} previous="$backup_dir/${!i##*/}"
        if ! sudo -n cmp -s -- "$previous.next" "$destination" ||
           ! replace_installed "$previous" "$destination"; then
            error "Could not restore $destination; inspect $previous"
        fi
    done
}

verify_archive_promotion() {
    [[ -n $archive_candidate && -n $triage_state ]] || return 0
    local triage_after
    triage_after=$(date -u +%s) && await_primary_watcher "${1:-0}" "${2:-0}"
}

promote_companions() {
    local tool proposed destination previous
    local -a selected=() promoted=()
    # Check all installed companions before changing any of them.
    for tool in "${companion_tools[@]}"; do
        proposed="${tool}_candidate" destination="installed_$tool"
        [[ -n ${!proposed} ]] || continue
        sudo -n cmp -s -- "$backup_dir/${!destination##*/}" "${!destination}" || return 1
        selected+=("${!destination}")
    done
    for destination in "${selected[@]}"; do
        previous="$backup_dir/${destination##*/}"
        if ! sudo -n cmp -s -- "$previous" "$destination" ||
           ! replace_installed "$previous.next" "$destination"; then
            restore_companions "${promoted[@]}"
            return 1
        fi
        promoted+=("$destination")
    done
    if ! verify_archive_promotion "${1:-0}" "${2:-0}"; then
        error "Triage did not verify the promoted archive tool; restoring companion binaries"
        restore_companions "${promoted[@]}"
        return 1
    fi
    for destination in "${promoted[@]}"; do
        previous="$backup_dir/${destination##*/}"
        sudo -n rm -f -- "$previous.next" || error "Staged companion cleanup failed; inspect $previous.next"
        printf 'Companion rollback binary: %s\n' "$previous"
    done
}

update_companions_only() {
    local tool proposed destination
    for tool in "${companion_tools[@]}"; do
        proposed="${tool}_candidate" destination="installed_$tool"
        if [[ -n ${!proposed} ]] && ! cmp -s -- "${!proposed}" "${!destination}"; then
            create_rollout_backup && stage_companion_updates && promote_companions "$allow_historical_drops" || return 1
            printf '%s\n' 'Companions updated; capture unchanged'
            return 0
        fi
    done
    printf '%s\n' 'Candidate is already installed; capture unchanged'
}
