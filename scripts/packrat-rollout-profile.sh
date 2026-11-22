#!/usr/bin/env bash

evidence_max_mib=64
evidence_max_frames=8192

read_launch_profile() {
    local flag value path='' mode=--archive max_mib='' max_frames=''
    local -a limits=() policy=()
    local LC_ALL=C
    [[ ${1-} == "$installed" && ${2-} == --telemetry-listen && ${3-} == "$health_addr" ]] || return 1
    shift 3
    while (( $# > 0 )); do
        (( $# >= 2 )) || return 1
        flag=$1 value=$2
        case $flag in
            --single-tag-interface)
                [[ -n $value && $value != -* && ${#value} -le 128 &&
                    $value != *[^[:print:]]* && ${#policy[@]} -lt 64 ]] || return 1
                policy+=("$flag" "$value")
                ;;
            --archive|--archive-alert-evidence)
                [[ -z $path && $value == /* && $value != / ]] || return 1
                path=$value mode=$flag
                ;;
            --archive-max-mib)
                [[ -z $max_mib && $value =~ ^[1-9][0-9]*$ ]] || return 1
                max_mib=$value
                limits+=("$flag" "$value")
                ;;
            --archive-max-frames)
                [[ -z $max_frames && $value =~ ^[1-9][0-9]*$ ]] || return 1
                max_frames=$value
                limits+=("$flag" "$value")
                ;;
            *) return 1 ;;
        esac
        shift 2
    done
    [[ -n $path || ${#limits[@]} == 0 ]] || return 1
    archive_path=$path
    archive_flag=$mode
    archive_limits=("${limits[@]}") vlan_policy_args=("${policy[@]}")
}

apply_requested_profile() {
    "$enable_alert_evidence" || return 0
    local parent resolved path="$data_dir/alert-evidence-archive"
    if [[ -n $archive_path ]]; then
        error "Evidence opt-in cannot replace an existing archive profile"
        return 1
    fi
    resolved=$(sudo -n realpath -e -- "$data_dir") || return 1
    parent=$(sudo -n stat --format='%f:%u' -- "$data_dir") || return 1
    if [[ $resolved != "$data_dir" || ! $parent =~ ^([0-9a-fA-F]{1,8}):0$ ]] ||
       (( (16#${BASH_REMATCH[1]} & 0170022) != 0040000 )); then
        error "Archive parent must be a root-owned directory without group or other write access"
        return 1
    fi
    if sudo -n test -e "$path" || sudo -n test -L "$path"; then
        error "Archive destination already exists: $path"
        return 1
    fi
    archive_path=$path archive_flag=--archive-alert-evidence
    archive_limits=(--archive-max-mib "$evidence_max_mib" --archive-max-frames "$evidence_max_frames")
}

candidate_supports_profile() {
    local help
    help=$("$candidate" --help) || return 1
    [[ $help == *--telemetry-listen* ]] || return 1
    [[ ${#vlan_policy_args[@]} == 0 || $help == *'--single-tag-interface NAME'* ]] || return 1
    [[ -z $archive_path ]] ||
        [[ $help == *"$archive_flag PATH"* && $help == *--archive-max-mib* && $help == *--archive-max-frames* ]]
}

archive_for_session() {
    if [[ -z $archive_path ]]; then
        return 0
    elif [[ $1 == "$bridge_session" ]]; then
        printf '%s\n' "$backup_dir/stage-data/packet-archive"
    else
        printf '%s\n' "$archive_path"
    fi
}

capture_storage_ready() {
    local pid=$1 session=$2 archive
    archive=$(archive_for_session "$session")
    capture_file_open "$pid" "$(alert_log_for_session "$session")" &&
        { [[ -z $archive ]] || capture_file_open "$pid" "${archive%/}/packets.bin"; }
}
