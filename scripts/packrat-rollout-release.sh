#!/usr/bin/env bash

analyzer_candidate=${PACKRAT_ROLLOUT_ANALYZER:-}
archive_candidate=${PACKRAT_ROLLOUT_ARCHIVE:-}
installed_analyzer=/usr/local/bin/packrat-analyze
installed_archive=/usr/local/bin/packrat-archive
companion_tools=(analyzer archive)
companion_update_selected() { [[ -n $analyzer_candidate || -n $archive_candidate ]]; }

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
    local -a files=("$installed" "$data_dir/alerts.jsonl")
    for tool in "${companion_tools[@]}"; do
        proposed="${tool}_candidate" current="installed_$tool"
        if [[ -n ${!proposed} ]]; then files+=("${!current}" "${!proposed}"); fi
    done
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

promote_companions() {
    local tool proposed destination previous i
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
            for ((i=${#promoted[@]}-1; i>=0; i--)); do
                destination=${promoted[i]} previous="$backup_dir/${promoted[i]##*/}"
                if ! sudo -n cmp -s -- "$previous.next" "$destination" ||
                   ! replace_installed "$previous" "$destination"; then
                    error "Could not restore $destination; inspect $previous"
                fi
            done
            return 1
        fi
        promoted+=("$destination")
    done
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
            create_rollout_backup && stage_companion_updates && promote_companions || return 1
            printf '%s\n' 'Companions updated; capture unchanged'
            return 0
        fi
    done
    printf '%s\n' 'Candidate is already installed; capture unchanged'
}
