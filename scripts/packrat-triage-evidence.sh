#!/usr/bin/env bash
# Sourced by packrat-triage.sh.

log_stamp() {
    [[ -f $1 ]] && stat -L --format='%d:%i %s %y %z' -- "$1"
}
previous_log_stamps() {
    local path stamp
    for path in "${previous_logs[@]}"; do
        stamp=$(log_stamp "$path") || return 1
        printf '%s\n' "$stamp"
    done
}
evidence_frame_digest() {
    local frame hex i sum
    # Match the archive format: concatenate the sorted eight-byte big-endian ordinals.
    sum=$(jq -r '.frames[].frame_number | floor' | {
        while IFS= read -r frame; do
            printf -v hex '%016x' "$frame" || return 1
            for ((i=0; i<16; i+=2)); do
                printf '%b' "\\x${hex:i:2}"
            done
        done
    } | sha256sum) || return 1
    printf '%s\n' "${sum%% *}"
}
check_evidence() {
    local LC_ALL=C response expected receipt claimed actual
    local -a evidence_args
    if [[ -n $project ]]; then
        evidence_args=(--project-alert-status "$project" "$1" "$session" "$capture" "$evidence_id")
    else
        evidence_args=("$archive" --alert-status "$1" "$session" "$evidence_id" --capture-id "$capture")
    fi
    expected=$(jq -c --argjson id "$evidence_id" --argjson limit "$alert_limit" '
        {match:(first(.alerts[] | select(.alert_id == $id) |
            {digest:.evidence_frame_set_sha256, count:.evidence_frame_count}) // null),
         outside_report: ([.alerts[:$limit][] | select(.alert_id == $id)] | length) == 0,
         stopped_at_limit:.integrity.stopped_at_limit,
         stopped_at_scan_budget:.integrity.stopped_at_scan_budget}
    ' <<< "$history") || return 1
    if jq -e '.match == null and .stopped_at_scan_budget == true' <<< "$expected" >/dev/null; then
        jq -cn --argjson id "$evidence_id" '{status:"outside_history_scan",alert_id:$id,frames:null}'
        return
    fi
    response=$(timeout --kill-after=2s "${2}s" packrat-archive \
        "${evidence_args[@]}" "${previous_args[@]}" | head -c 65537) || return "$?"
    (( ${#response} <= 65536 )) || return 1
    receipt=$(jq -cse --arg session "$session" --arg capture "$capture" --argjson id "$evidence_id" \
        --argjson expected "$expected" '
        select(length == 1) | .[0] | objects
        | select(.session_id == $session and .capture_id == $capture and .alert_id == $id
            and (.evidence_frame_set_sha256 | type == "string" and test("\\A[0-9a-f]{64}\\z"))
            and (.frames | type == "array" and length >= 1 and length <= 131
                and all(.[]; type == "object"
                    and (.frame_number | type == "number" and . > 0 and . <= 9007199254740991 and floor == .)
                    and (.status == "complete" or .status == "truncated" or .status == "missing"
                        or .status == "length_unknown" or .status == "unreadable"))
                and (map(.frame_number) | . == unique)))
        | if ($expected.match != null and ($expected.match.digest != .evidence_frame_set_sha256
                  or $expected.match.count != (.frames | length)))
              or ($expected.match == null and ($expected.stopped_at_limit | not))
          then {status:"alert_evidence_changed", alert_id, frames:null}
          else {status:"checked", alert_id, frames:(.frames | map({frame_number,status})),
                in_recent_alerts:($expected.outside_report | not), claimed_digest:.evidence_frame_set_sha256}
          end
    ' <<< "$response") || return 1
    claimed=$(jq -r '.claimed_digest // empty' <<< "$receipt") || return 1
    if [[ -z $claimed ]]; then
        printf '%s\n' "$receipt"
        return
    fi
    actual=$(evidence_frame_digest <<< "$receipt") || return 1
    if [[ $actual != "$claimed" ]]; then
        jq -cn --argjson id "$evidence_id" '{status:"evidence_frame_set_mismatch",alert_id:$id,frames:null}'
    else
        jq -c 'del(.claimed_digest)' <<< "$receipt"
    fi
}
