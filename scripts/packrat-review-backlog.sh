#!/usr/bin/env bash
# Check saved priority findings against a packet archive without exporting frames.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-review-backlog.sh [--review-offset N] ARCHIVE ALERT_LOG [PREVIOUS_LOG ...]' \
        'Review five saved priority alerts per page. Use immutable logs across pages.' \
        'PACKRAT_BACKLOG_TIMEOUT sets the shared deadline (default: 15 seconds).'
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
offset=0 offset_args=()
if [[ ${1-} == --review-offset ]]; then
    offset=${2-}
    if [[ ! $offset =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( offset >= 512 )); then usage >&2; exit 2; fi
    offset_args=(--review-offset "$offset")
    shift 2
fi
if (( $# < 2 || $# > 10 )) || [[ $1 != /* || ! -d $1 ]]; then usage >&2; exit 2; fi
budget=${PACKRAT_BACKLOG_TIMEOUT:-15}
if [[ ! $budget =~ ^[1-9][0-9]{0,2}$ ]] || (( budget > 120 )); then
    printf '%s\n' 'PACKRAT_BACKLOG_TIMEOUT must be between 1 and 120 seconds.' >&2
    exit 2
fi
archive=$1
shift
bin=$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")
triage="$bin/packrat-triage"
if [[ -f $bin/packrat-triage.sh ]]; then triage="$bin/packrat-triage.sh"; fi
unset PACKRAT_TRIAGE_PROJECT PACKRAT_TRIAGE_EVIDENCE_ALERT_ID PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE
export PACKRAT_TRIAGE_AUTO_EVIDENCE=0 PACKRAT_TRIAGE_ARCHIVE="$archive"
deadline=$((SECONDS + budget))

triage_with_budget() {
    local remaining=$1
    shift
    PACKRAT_TRIAGE_READ_TIMEOUT="$remaining" timeout --kill-after=1s "${remaining}s" \
        bash "$triage" "$@" | head -c 1048577
}

rc=0
raw=$(triage_with_budget "$budget" --list-saved "${offset_args[@]}" "$@") || rc=$?
if (( rc > 1 || ${#raw} > 1048576 )) || ! index=$(jq -ces --argjson offset "$offset" '
    def count: type == "number" and . >= 0 and . <= 512 and floor == .;
    def valid_entry:
        type == "object" and (.session_id | strings | test("\\A[A-Za-z0-9_-]{1,128}\\z"))
        and (.capture_id | strings | test("\\A[0-9a-f]{32}\\z"))
        and (.alert_id | numbers | . >= 1 and . <= 999999999999999 and floor == .)
        and (.evidence_frame_set_sha256 | strings | test("\\A[0-9a-f]{64}\\z"))
        and (.evidence_frame_count | numbers | . >= 0 and . <= 131 and floor == .)
        and (.rule_id == null or (.rule_id | strings | test("\\A[a-z0-9_.-]{1,128}\\z")))
        and (.revision == null or (.revision | numbers | . >= 1 and . <= 65535 and floor == .))
        and (.confidence == null or .confidence == "heuristic" or .confidence == "correlated" or .confidence == "direct_observation")
        and (.disposition == "New" or .disposition == "Reviewing" or .disposition == "Confirmed")
        and (.last_seen | numbers | isfinite)
        and (.severity == "HIGH" or .severity == "CRITICAL");
    if length == 1 then .[0] else error("Expected one saved capture index") end
    | select(.record_type == "saved_capture_index" and (.status == "saved" or .status == "saved_log_degraded")
        and .review_offset == $offset and (.sampled_alerts | count)
        and (.sample_scan_complete | type == "boolean")
        and (.review_eligible_in_sample | count) and .review_eligible_in_sample <= .sampled_alerts)
    | .review_eligible_in_sample as $eligible
    | ([0, ([5, ($eligible - $offset)] | min)] | max) as $page_length
    | select((.review_shortlist | type == "array" and length == $page_length
              and all(.[]; valid_entry))
        and .review_shortlist_truncated == ($eligible > $offset + 5)
        and .next_review_offset == (if $eligible > $offset + 5 then $offset + 5 else null end))
    | {index_status:.status,sampled_alerts,sampled_unscoped_open_high_or_critical,sample_scan_complete,
       review_offset,review_eligible_in_sample,review_shortlist_truncated,next_review_offset,
       review_shortlist:(.review_shortlist | map({session_id,capture_id,alert_id,rule_id,revision,confidence,
                                               severity,disposition,last_seen,evidence_frame_count,evidence_frame_set_sha256}))}
' <<< "$raw"); then
    printf '%s\n' 'Could not read the bounded saved-priority index.' >&2
    exit 1
fi

results='[]'
while IFS= read -r candidate; do
    IFS=$'\t' read -r session capture alert < <(jq -r '[.session_id,.capture_id,.alert_id] | @tsv' <<< "$candidate")
    remaining=$((deadline - SECONDS))
    verdict='null' status=check_deferred
    if (( remaining > 0 )); then
        rc=0
        raw=$(triage_with_budget "$remaining" --saved-alert "$session" "$capture" "$alert" "$@") || rc=$?
        status=check_failed
        if (( rc == 124 || rc == 137 )); then status=check_timed_out; fi
        if (( rc <= 2 && ${#raw} <= 1048576 )); then
            verdict=$(jq -ces --argjson selected "$candidate" '
                select(length == 1) | .[0] | select(.record_type == "capture_triage" and .mode == "saved")
                | if .status == "saved_alert_not_observed" then
                    {packet_evidence_status:"changed_during_review",next_evidence_step:"refresh_saved_index"}
                  elif .status == "saved" and (.alerts | type == "array" and length == 1) then .alerts[0]
                    | if ({session_id,capture_id,alert_id,rule_id,revision,confidence,severity,disposition,
                            last_seen,evidence_frame_count,evidence_frame_set_sha256} != $selected) then
                        {packet_evidence_status:"changed_during_review",next_evidence_step:"refresh_saved_index"}
                      elif (.packet_evidence_status | strings | test("\\A[a-z_]{1,48}\\z")) and
                           (.next_evidence_step | strings | test("\\A[a-z_]{1,64}\\z")) then
                        {packet_evidence_status,next_evidence_step}
                      else null end
                  else null end' <<< "$raw") || verdict='null'
        fi
    fi
    results=$(jq -c --argjson candidate "$candidate" --argjson verdict "$verdict" --arg status "$status" '
        . + [($candidate | del(.evidence_frame_set_sha256))
             + ($verdict // {packet_evidence_status:$status,next_evidence_step:"retry_evidence_check"})]
    ' <<< "$results")
done < <(jq -c '.review_shortlist[]' <<< "$index")

jq -ce --argjson results "$results" 'del(.review_shortlist) + {
    record_type:"saved_alert_evidence_review", findings:$results}' <<< "$index"
