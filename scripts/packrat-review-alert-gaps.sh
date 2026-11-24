#!/usr/bin/env bash
# Reconcile watcher gap ranges against scoped saved alert metadata.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-review-alert-gaps.sh COVERAGE.json ALERT_LOG [PREVIOUS_LOG ...]' \
        'Reads up to 8 MiB and returns up to 512 saved alerts matching the requested ID ranges. Supply previous logs oldest first.' \
        'Absence refers only to the supplied logs, never to uncaptured or unpersisted traffic.'
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
if (( $# < 2 || $# > 10 )) || [[ ! -f $1 ]]; then usage >&2; exit 2; fi
requested=$(head -c 65537 -- "$1" | jq -Rces '
    def id: type == "number" and . >= 1 and . <= 9007199254740991 and floor == .;
    select(utf8bytelength <= 65536) | fromjson | objects
    | select(.record_type == "capture_coverage_report"
        and (.scope.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"))
        and (.scope.session_id | type == "string" and test("\\A[A-Za-z0-9_-]{1,128}\\z"))
        and (.unobserved_alert_id_ranges_truncated | type == "boolean")
        and (.alert_sample_gap_reported | type == "boolean")
        and (.unobserved_alert_id_ranges | type == "array" and length <= 64
             and all(.[]; type == "object" and (.first_id | id) and (.last_id | id) and .first_id <= .last_id)))
    | {scope:(.scope | {capture_id,session_id}),alert_sample_gap_reported,unobserved_alert_id_ranges_truncated,
       ranges:(.unobserved_alert_id_ranges | map({first_id,last_id}) | sort_by([.first_id,.last_id])
           | reduce .[] as $range ([];
               if length > 0 and .[-1].last_id + 1 >= $range.first_id then
                   .[-1].last_id = ([.[-1].last_id,$range.last_id] | max)
               else . + [$range] end))}
') || { printf '%s\n' 'Invalid or unsupported coverage report.' >&2; exit 2; }
shift
if jq -e '.ranges == []' <<< "$requested" >/dev/null; then
    jq -c '. + {record_type:"alert_gap_reconciliation",
        status:(if .alert_sample_gap_reported then "unlocated_gap" else "no_reported_ranges" end),
        saved_log_scan_complete:null,recovered_alerts:[]}' <<< "$requested"
    exit
fi

read -r capture session < <(jq -r '.scope | [.capture_id,.session_id] | @tsv' <<< "$requested")
logs=("$@") previous=()
for log in "${logs[@]:1}"; do previous+=(--previous-log "$log"); done
range_args=()
range_list=$(jq -er '.ranges[] | "\(.first_id)..\(.last_id)"' <<< "$requested")
while IFS= read -r range; do range_args+=(--alert-range "$range"); done <<< "$range_list"
log_stamps() {
    local path
    for path in "${logs[@]}"; do
        [[ -f $path ]] || return 1
        stat -L --format='%d:%i:%s:%y:%z' -- "$path" || return 1
    done
}
before=$(log_stamps) || { printf '%s\n' 'Expected regular saved alert logs.' >&2; exit 2; }
if ! history=$(timeout --kill-after=2s 15s packrat-archive --alerts "${logs[0]}" \
    --session "$session" --capture-id "$capture" --limit 512 --scan-bytes 8388608 \
    --report-integrity "${range_args[@]}" "${previous[@]}" | head -c 2097153) || (( ${#history} > 2097152 )); then
    printf '%s\n' 'Could not read the bounded saved alert log.' >&2
    exit 1
fi
if ! after=$(log_stamps) || [[ $before != "$after" ]]; then
    printf '%s\n' 'Saved log changed during lookup; retry from a stable snapshot.' >&2
    exit 1
fi

printf '%s\n' "$requested" "$history" | jq -ces --arg session "$session" --arg capture "$capture" '
    def counter: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def clean_log: .invalid_records == 0 and .oversized_records == 0
        and .stopped_at_limit == false and .stopped_at_scan_budget != true;
    def valid_alert:
        type == "object" and .capture_id == $capture and .session_id == $session
        and (.alert_id | counter and . > 0);
    def safe_rule: if type == "string" and test("\\A[a-z0-9_.-]{1,128}\\z") then . else null end;
    def severity: if . == "WARN" then "MEDIUM" elif . == "CRIT" then "CRITICAL"
        elif IN("INFO","LOW","MEDIUM","HIGH","CRITICAL") then . else null end;
    def in_ranges($ranges): .alert_id as $id | any($ranges[]; $id >= .first_id and $id <= .last_id);
    select(length == 2) | .[0] as $input | .[1] as $history
    | select($history.alerts | type == "array" and length <= 512 and all(.[]; valid_alert and in_ranges($input.ranges))
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
    | $input + {
        record_type:"alert_gap_reconciliation",status:"reconciled",saved_log_scan_complete:$complete,
        alert_log_integrity:($integrity | {invalid_records,oversized_records,stopped_at_limit,stopped_at_scan_budget}),
        recovered_alerts:$recovered,
        ranges:[$input.ranges[] | . as $range
            | ([$recovered[].alert_id | select(. >= $range.first_id and . <= $range.last_id)] | length) as $found
            | (.last_id - .first_id + 1 - $found) as $remaining
            | . + {found:$found,not_found_in_scan:$remaining,
                   remaining_status:(if $remaining == 0 then "all_found"
                       elif $complete then "not_in_supplied_logs" else "unverified" end)}]}
'
