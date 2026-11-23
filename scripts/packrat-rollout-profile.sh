#!/usr/bin/env bash

evidence_max_mib=64
evidence_max_frames=8192
retain_rule=${PACKRAT_ROLLOUT_ADD_EVIDENCE_RULE:-}
remove_rule=${PACKRAT_ROLLOUT_REMOVE_EVIDENCE_RULE:-}

read_launch_profile() {
    local flag value path='' mode=--archive max_mib='' max_frames=''
    local -a limits=() policy=() rule_args=()
    local -A rules=()
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
            --archive-evidence-rule)
                [[ $value =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ && ${#rule_args[@]} -lt 32 ]] || return 1
                [[ ! -v 'rules[$value]' ]] || return 1
                rules[$value]=1
                rule_args+=("$flag" "$value")
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
    [[ ${#rule_args[@]} == 0 || $mode == --archive-alert-evidence ]] || return 1
    archive_path=$path
    archive_flag=$mode
    archive_limits=("${limits[@]}") vlan_policy_args=("${policy[@]}")
    archive_rule_args=("${rule_args[@]}")
}

archive_rule_enabled() {
    local i
    for ((i=1; i<${#archive_rule_args[@]}; i+=2)); do
        [[ ${archive_rule_args[i]} != "$1" ]] || return 0
    done
    return 1
}

archive_policy_changes() {
    "$enable_alert_evidence" ||
        { [[ -n $retain_rule ]] && ! archive_rule_enabled "$retain_rule"; } ||
        { [[ -n $remove_rule ]] && archive_rule_enabled "$remove_rule"; }
}

apply_requested_profile() {
    local requested=${retain_rule:-$remove_rule}
    if [[ -n $requested ]]; then
        if [[ -n $retain_rule && -n $remove_rule ]]; then
            error "Add and remove evidence rule requests are mutually exclusive"
            return 1
        fi
        if "$enable_alert_evidence" || [[ -z $archive_path || $archive_flag != --archive-alert-evidence ||
                                          ! $requested =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ ]]; then
            error "The requested rule requires an existing selective archive and a valid rule ID"
            return 1
        fi
        if [[ -n $remove_rule ]]; then
            local i
            local -a remaining=()
            for ((i=1; i<${#archive_rule_args[@]}; i+=2)); do
                if [[ ${archive_rule_args[i]} != "$remove_rule" ]]; then
                    remaining+=("${archive_rule_args[i-1]}" "${archive_rule_args[i]}")
                fi
            done
            archive_rule_args=("${remaining[@]}")
            return 0
        fi
        if archive_rule_enabled "$retain_rule"; then return 0; fi
        if (( ${#archive_rule_args[@]} >= 32 )); then
            error "The selective archive already has 16 additional rules"
            return 1
        fi
        archive_rule_args+=(--archive-evidence-rule "$retain_rule")
        return 0
    fi
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
    [[ ${#archive_rule_args[@]} == 0 || $help == *'--archive-evidence-rule RULE_ID'* ]] || return 1
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
