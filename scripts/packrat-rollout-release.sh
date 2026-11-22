#!/usr/bin/env bash

analyzer_candidate=${PACKRAT_ROLLOUT_ANALYZER:-}
installed_analyzer=/usr/local/bin/packrat-analyze

analyzer_candidate_ready() {
    local help
    [[ -n $analyzer_candidate ]] || return 0
    analyzer_candidate=$(realpath -- "$analyzer_candidate") &&
        [[ -f $analyzer_candidate && -x $analyzer_candidate &&
           -f $installed_analyzer && -x $installed_analyzer && ! -L $installed_analyzer ]] &&
        help=$(timeout 5s "$analyzer_candidate" --help) &&
        [[ $help == *'Usage: packrat-analyze'* ]]
}

backup_space_ready() {
    local destination="$data_dir/backups" free_kib sizes reserve=$backup_reserve_mib
    local -a files=("$installed" "$data_dir/alerts.jsonl")
    if [[ -n $analyzer_candidate ]]; then files+=("$installed_analyzer" "$analyzer_candidate"); fi
    sudo -n test -d "$destination" || destination=$data_dir
    free_kib=$(sudo -n env LC_ALL=C df -Pk -- "$destination" | awk 'NR == 2 { print $4 }') || return 1
    sizes=$(sudo -n stat --format='%s' -- "${files[@]}") || return 1
    [[ $free_kib =~ ^[0-9]{1,15}$ && $backup_reserve_mib =~ ^[1-9][0-9]{0,5}$ ]] || return 1
    if "$enable_alert_evidence"; then reserve=$((reserve + 2 * evidence_max_mib)); fi
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

stage_analyzer_update() {
    [[ -n $analyzer_candidate ]] || return 0
    sudo -n install -o root -g root -m 0700 "$installed_analyzer" "$backup_dir/packrat-analyze" &&
        sudo -n cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze" &&
        sudo -n install -o root -g root -m 0700 "$analyzer_candidate" "$backup_dir/packrat-analyze.next" &&
        sudo -n cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
}

prepare_backup_and_stage() {
    create_rollout_backup && stage_analyzer_update || return 1
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

promote_analyzer() {
    [[ -n $analyzer_candidate ]] || return 0
    # Refuse to overwrite an independent update after we made the rollback copy.
    sudo -n cmp -s -- "$backup_dir/packrat-analyze" "$installed_analyzer" &&
        replace_installed "$backup_dir/packrat-analyze.next" "$installed_analyzer" || return 1
    printf 'Analyzer rollback binary: %s/packrat-analyze\n' "$backup_dir"
}

update_analyzer_only() {
    if [[ -n $analyzer_candidate ]] && ! cmp -s -- "$analyzer_candidate" "$installed_analyzer"; then
        create_rollout_backup && stage_analyzer_update && promote_analyzer || return 1
        printf '%s\n' 'Analyzer updated; capture unchanged'
    else
        printf '%s\n' 'Candidate is already installed; capture unchanged'
    fi
}
