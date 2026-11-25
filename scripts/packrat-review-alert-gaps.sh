#!/usr/bin/env bash
# Reconcile watcher gap ranges against scoped saved alert metadata.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-review-alert-gaps.sh COVERAGE.json ALERT_LOG [PREVIOUS_LOG ...]' \
        'Reads up to 8 MiB per lookup and reports up to 512 saved alerts. Supply previous logs oldest first.' \
        'Prioritizes outstanding previously observed IDs; older reports use the historical disappearance list.' \
        'If the broad lookup fills, retry outstanding known IDs in a second lookup under the same deadline.' \
        'Absence refers only to the supplied logs, never to uncaptured or unpersisted traffic.'
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
if (( $# < 2 || $# > 10 )) || [[ ! -f $1 ]]; then usage >&2; exit 2; fi
requested=$(head -c 65537 -- "$1" | jq -Rces '
    def id: type == "number" and . >= 1 and . <= 9007199254740991 and floor == .;
    def id_list: type == "array" and length <= 64 and all(.[]; id);
    def gap_group:
        type == "object" and (.alert_ids | id_list and . == unique)
        and (.truncated | type == "boolean") and (.truncated == false or (.alert_ids | length) == 64);
    def valid_gap_status:
        type == "object"
        and (.outstanding | gap_group) and (.reobserved | gap_group)
        and (.outstanding.alert_ids as $a | .reobserved.alert_ids as $b | ($a - $b) == $a);
    select(utf8bytelength <= 65536) | fromjson | objects
    | select(.record_type == "capture_coverage_report"
        and (.scope.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"))
        and (.scope.session_id | type == "string" and test("\\A[A-Za-z0-9_-]{1,128}\\z"))
        and (.unobserved_alert_id_ranges_truncated | type == "boolean")
        and (.alert_sample_gap_reported | type == "boolean")
        and ((has("missing_previously_observed_alert_ids_truncated") | not)
             or (.missing_previously_observed_alert_ids_truncated | type == "boolean"))
        and ((has("missing_previously_observed_alert_ids") | not)
             or (.missing_previously_observed_alert_ids | id_list))
        and ((has("previously_observed_gap_status") | not) or (.previously_observed_gap_status | valid_gap_status))
        and (.unobserved_alert_id_ranges | type == "array" and length <= 64
             and all(.[]; type == "object" and (.first_id | id) and (.last_id | id) and .first_id <= .last_id)))
    | ((.missing_previously_observed_alert_ids // []) | unique) as $historical
    | (if has("previously_observed_gap_status") then
          .previously_observed_gap_status | {outstanding:(.outstanding | {alert_ids,truncated}),
                                             reobserved:(.reobserved | {alert_ids,truncated})}
       else null end) as $gap_status
    | select($gap_status == null or .missing_previously_observed_alert_ids_truncated == true
        or (($gap_status.outstanding.truncated or $gap_status.reobserved.truncated) | not)
           and (($gap_status.outstanding.alert_ids + $gap_status.reobserved.alert_ids | sort) == $historical))
    | (if $gap_status != null then $gap_status.outstanding.alert_ids else $historical end) as $missing
    | (if $gap_status != null then $gap_status.outstanding.truncated
       else (.missing_previously_observed_alert_ids_truncated // false) end) as $priority_truncated
    | {scope:(.scope | {capture_id,session_id}),alert_sample_gap_reported,unobserved_alert_id_ranges_truncated,
       missing_previously_observed_alert_ids:$historical,
       missing_previously_observed_alert_ids_truncated:(.missing_previously_observed_alert_ids_truncated // false),
       previously_observed_gap_status:$gap_status,priority_alert_ids:$missing,priority_alert_ids_truncated:$priority_truncated,
       ranges:((.unobserved_alert_id_ranges | map({first_id,last_id})) + ($missing | map({first_id:.,last_id:.})) | sort_by([.first_id,.last_id])
           | reduce .[] as $range ([];
               if length > 0 and .[-1].last_id + 1 >= $range.first_id then
                   .[-1].last_id = ([.[-1].last_id,$range.last_id] | max)
               else . + [$range] end))}
    | .request_ranges_truncated = (.unobserved_alert_id_ranges_truncated or .priority_alert_ids_truncated
        or (.ranges | length > 64))
    | .ranges |= (sort_by(. as $range |
        [(if any($missing[]; . >= $range.first_id and . <= $range.last_id) then 0 else 1 end),$range.first_id])
        | .[:64] | sort_by(.first_id))
') || { printf '%s\n' 'Invalid or unsupported coverage report.' >&2; exit 2; }
shift
if jq -e '.ranges == []' <<< "$requested" >/dev/null; then
    jq -c '. + {record_type:"alert_gap_reconciliation",
        status:(if .alert_sample_gap_reported or .request_ranges_truncated then "unlocated_gap" else "no_reported_ranges" end),
        saved_log_scan_complete:null,recovered_alerts:[],
        priority_lookup_status:"not_needed",recovered_alerts_omitted:0,
        previously_observed_reconciliation:{recovered_alert_ids:[],not_in_supplied_logs:[],unverified_alert_ids:[]}}' <<< "$requested"
    exit
fi

read -r capture session < <(jq -r '.scope | [.capture_id,.session_id] | @tsv' <<< "$requested")
logs=("$@") previous=()
for log in "${logs[@]:1}"; do previous+=(--previous-log "$log"); done
log_stamps() {
    local path
    for path in "${logs[@]}"; do
        [[ -f $path ]] || return 1
        stat -L --format='%d:%i:%s:%y:%z' -- "$path" || return 1
    done
}
read_history() {
    local remaining=$1 ranges=$2 raw range range_list
    local -a range_args=()
    (( remaining > 0 )) || return 1
    range_list=$(jq -er '.[] | "\(.first_id)..\(.last_id)"' <<< "$ranges") || return 1
    while IFS= read -r range; do range_args+=(--alert-range "$range"); done <<< "$range_list"
    raw=$(timeout --kill-after=2s "${remaining}s" packrat-archive --alerts "${logs[0]}" \
        --session "$session" --capture-id "$capture" --limit 512 --scan-bytes 8388608 \
        --report-integrity "${range_args[@]}" "${previous[@]}" | head -c 2097153) || return 1
    (( ${#raw} <= 2097152 )) || return 1
    jq -ces --arg session "$session" --arg capture "$capture" --argjson ranges "$ranges" '
    def counter: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def clean_log: .invalid_records == 0 and .oversized_records == 0
        and .stopped_at_limit == false and .stopped_at_scan_budget != true;
    def valid_alert:
        type == "object" and .capture_id == $capture and .session_id == $session
        and (.alert_id | counter and . > 0);
    def safe_rule: if type == "string" and test("\\A[a-z0-9_.-]{1,128}\\z") then . else null end;
    def severity: if . == "WARN" then "MEDIUM" elif . == "CRIT" then "CRITICAL"
        elif IN("INFO","LOW","MEDIUM","HIGH","CRITICAL") then . else null end;
    def in_ranges($ranges; $id): any($ranges[]; $id >= .first_id and $id <= .last_id);
    select(length == 1) | .[0] as $history
    | select($history.alerts | type == "array" and length <= 512 and all(.[]; valid_alert and in_ranges($ranges; .alert_id))
        and (map(.alert_id) | length == (unique | length)))
    | $history.integrity as $integrity
    | select($integrity | type == "object" and (.invalid_records | counter) and (.oversized_records | counter)
        and (.stopped_at_limit | type == "boolean") and (.stopped_at_scan_budget | . == null or type == "boolean"))
    | select($integrity.stopped_at_limit == (($history.alerts | length) == 512))
    | ($integrity | clean_log) as $complete
    | [$history.alerts[]
        | (.evidence_frame_count | if counter and . <= 131 then . else null end) as $refs
        | {alert_id,rule_id:(.rule_id | safe_rule),
           revision:(.revision | if counter and . >= 1 and . <= 65535 then . else null end),
           severity:(.severity | severity),
           confidence:(.confidence | if IN("heuristic","correlated","direct_observation") then . else null end),
           evidence_frame_count:$refs,
           evidence_frame_set_sha256:((if $refs != null then .evidence_frame_set_sha256 | strings
               | select(test("\\A[0-9a-f]{64}\\z")) else empty end) // null),
           next_evidence_step:(if $refs == 0 then "corroborate_with_host_or_service_logs"
               elif $refs != null then "verify_frame_availability" else "inspect_saved_alert" end),
           disposition:(.disposition | if IN("New","Reviewing","Confirmed","Benign","Contained","Closed") then . else null end)}]
        | sort_by(.alert_id) as $recovered
    | {complete:$complete,recovered:$recovered,
       integrity:($integrity | {invalid_records,oversized_records,stopped_at_limit,stopped_at_scan_budget})}
' <<< "$raw"
}

before=$(log_stamps) || { printf '%s\n' 'Expected regular saved alert logs.' >&2; exit 2; }
deadline=$((SECONDS + 15))
ranges=$(jq -c '.ranges' <<< "$requested")
history=$(read_history "$((deadline - SECONDS))" "$ranges") || {
    printf '%s\n' 'Could not read the bounded saved alert log.' >&2
    exit 1
}
priority=null priority_status=not_needed
if jq -e '.integrity.stopped_at_limit' <<< "$history" >/dev/null; then
    priority_ranges=$(printf '%s\n' "$requested" "$history" | jq -cs '
        (.[0].priority_alert_ids - [.[1].recovered[].alert_id])
        | map({first_id:.,last_id:.})')
    if [[ $priority_ranges != '[]' ]]; then
        priority_status=unavailable
        if priority=$(read_history "$((deadline - SECONDS))" "$priority_ranges" 2>/dev/null); then
            priority_status=$(jq -r 'if .complete then "complete" else "partial" end' <<< "$priority")
        else priority=null
        fi
    fi
fi
if ! after=$(log_stamps) || [[ $before != "$after" ]]; then
    printf '%s\n' 'Saved log changed during lookup; retry from a stable snapshot.' >&2
    exit 1
fi
printf '%s\n' "$requested" "$history" "$priority" | jq -ces --arg priority_status "$priority_status" '
    def in_ranges($ranges; $id): any($ranges[]; $id >= .first_id and $id <= .last_id);
    select(length == 3) | .[0] as $input | .[1] as $history | .[2] as $priority
    | $input.priority_alert_ids as $known
    | $history.complete as $complete
    | ($history.recovered + ($priority.recovered // []) | sort_by(.alert_id)) as $recovered
    | ($recovered | map(.alert_id)) as $recovered_ids
    | ($known - $recovered_ids) as $missing
    | [$missing[] | select(. as $id | ($complete or $priority.complete == true) and in_ranges($input.ranges; $id))] as $absent
    | ($recovered | sort_by(.alert_id as $id | [(if ($known | index($id)) == null then 1 else 0 end),-$id])
        | .[:512] | sort_by(.alert_id)) as $returned
    | $input + {
        record_type:"alert_gap_reconciliation",status:"reconciled",saved_log_scan_complete:$complete,
        alert_log_integrity:$history.integrity,
        priority_lookup_status:$priority_status,recovered_alerts:$returned,
        recovered_alerts_omitted:(($recovered | length) - ($returned | length)),
        previously_observed_reconciliation:{
            recovered_alert_ids:($known - $missing),
            not_in_supplied_logs:$absent,unverified_alert_ids:($missing - $absent)},
        ranges:[$input.ranges[] | . as $range
            | ([$recovered[].alert_id | select(. >= $range.first_id and . <= $range.last_id)] | length) as $found
            | (.last_id - .first_id + 1 - $found) as $remaining
            | . + {found:$found,not_found_in_scan:$remaining,
                   remaining_status:(if $remaining == 0 then "all_found"
                       elif $complete then "not_in_supplied_logs" else "unverified" end)}]}
'
