#!/usr/bin/env bash
# Check saved findings against a packet archive without exporting frames.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-review-backlog.sh [--review-scope SESSION_ID CAPTURE_ID] [--review-rule RULE_ID] [--review-offset N] ARCHIVE ALERT_LOG [PREVIOUS_LOG ...]' \
        'Review five scoped High/Critical alerts per page, or a named rule at any severity. Use immutable logs across pages.' \
        'PACKRAT_BACKLOG_TIMEOUT sets the shared deadline (default: 15 seconds).'
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
offset=0 rule='' session_scope='' capture_scope='' index_args=()
if [[ ${1-} == --review-scope ]]; then
    session_scope=${2-} capture_scope=${3-}
    [[ $session_scope =~ ^[A-Za-z0-9_-]{1,128}$ && $capture_scope =~ ^[0-9a-f]{32}$ ]] || { usage >&2; exit 2; }
    index_args+=(--review-scope "$session_scope" "$capture_scope")
    shift 3
fi
if [[ ${1-} == --review-rule ]]; then
    rule=${2-}
    [[ $rule =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ ]] || { usage >&2; exit 2; }
    index_args+=(--review-rule "$rule")
    shift 2
fi
if [[ ${1-} == --review-offset ]]; then
    offset=${2-}
    if [[ ! $offset =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( offset >= 512 )); then usage >&2; exit 2; fi
    index_args+=(--review-offset "$offset")
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
raw=$(triage_with_budget "$budget" --list-saved "${index_args[@]}" "$@") || rc=$?
if (( rc > 1 || ${#raw} > 1048576 )) || ! index=$(jq -ces --arg rule "$rule" --argjson offset "$offset" \
    --arg session "$session_scope" --arg capture "$capture_scope" '
    def count: type == "number" and . >= 0 and . <= 512 and floor == .;
    def valid_reference:
        type == "object" and (.session_id | strings | test("\\A[A-Za-z0-9_-]{1,128}\\z"))
        and (.alert_id | numbers | . >= 1 and . <= 999999999999999 and floor == .)
        and (.disposition == "New" or .disposition == "Reviewing" or .disposition == "Confirmed");
    def priority: .severity == "HIGH" or .severity == "CRITICAL";
    def selected: if $rule == "" then priority else .rule_id == $rule and (.severity | IN("CRITICAL","HIGH","MEDIUM","LOW")) end;
    def valid_entry: valid_reference and selected
        and ($capture == "" or (.session_id == $session and .capture_id == $capture))
        and (.capture_id | strings | test("\\A[0-9a-f]{32}\\z"))
        and (.evidence_frame_set_sha256 | strings | test("\\A[0-9a-f]{64}\\z"))
        and (.evidence_frame_count | numbers | . >= 0 and . <= 131 and floor == .)
        and (.rule_id == null or (.rule_id | strings | test("\\A[a-z0-9_.-]{1,128}\\z")))
        and (.revision == null or (.revision | numbers | . >= 1 and . <= 65535 and floor == .))
        and (.confidence == null or .confidence == "heuristic" or .confidence == "correlated" or .confidence == "direct_observation")
        and (.last_seen | numbers | isfinite);
    def unscoped_reference: valid_reference and priority
        and (.legacy_rule_hint == null or (.legacy_rule_hint | strings | test("\\A[a-z0-9_.-]{1,128}\\z")))
        and (.last_seen == null or (.last_seen | numbers | isfinite and . > 0));
    if length == 1 then .[0] else error("Expected one saved capture index") end
    | select(.record_type == "saved_capture_index" and (.status == "saved" or .status == "saved_log_degraded")
        and .review_scope == (if $capture == "" then null else {session_id:$session,capture_id:$capture} end)
        and ($capture == "" or (.sampled_unscoped_open_high_or_critical == 0 and .unscoped_review_queue == []))
        and .review_rule == (if $rule == "" then null else $rule end)
        and .review_offset == $offset and (.sampled_alerts | count)
        and (.sample_scan_complete | type == "boolean")
        and (.review_eligible_in_sample | count) and .review_eligible_in_sample <= .sampled_alerts)
    | .review_eligible_in_sample as $eligible
    | ([0, ([5, ($eligible - $offset)] | min)] | max) as $page_length
    | select((.review_shortlist | type == "array" and length == $page_length
              and all(.[]; valid_entry))
        and .review_shortlist_truncated == ($eligible > $offset + 5)
        and .next_review_offset == (if $eligible > $offset + 5 then $offset + 5 else null end)
        and (.unscoped_review_queue | type == "array" and length <= 5 and all(.[]; unscoped_reference)))
    | {index_status:.status,sampled_alerts,sampled_unscoped_open_high_or_critical,sample_scan_complete,
       review_scope,review_rule,review_offset,review_eligible_in_sample,review_shortlist_truncated,next_review_offset,
       unscoped_review_queue:(.unscoped_review_queue | map({session_id,alert_id,severity,disposition,last_seen,
             legacy_rule_hint,next_evidence_step:"locate_original_capture_or_host_logs"})),
       review_shortlist:(.review_shortlist | map({session_id,capture_id,alert_id,rule_id,revision,confidence,
                                               severity,disposition,last_seen,evidence_frame_count,evidence_frame_set_sha256}))}
' <<< "$raw"); then
    printf '%s\n' 'Could not read the bounded saved-alert index.' >&2
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
                def valid_counts:
                    if .packet_evidence_status | IN("complete","partial","unavailable") then
                        (.evidence_availability | type == "object" and length > 0
                            and all(to_entries[]; (.key | IN("complete","truncated","missing","length_unknown","unreadable"))
                                and (.value | numbers | . >= 1 and . <= 131 and floor == .))
                            and ([.[]] | add) == $selected.evidence_frame_count)
                    else .evidence_availability == null end;
                select(length == 1) | .[0] | select(.record_type == "capture_triage" and .mode == "saved")
                | if .status == "saved_alert_not_observed" then
                    {packet_evidence_status:"changed_during_review",next_evidence_step:"refresh_saved_index"}
                  elif .status == "saved" and (.alerts | type == "array" and length == 1) then .alerts[0]
                    | if ({session_id,capture_id,alert_id,rule_id,revision,confidence,severity,disposition,
                            last_seen,evidence_frame_count,evidence_frame_set_sha256} != $selected) then
                        {packet_evidence_status:"changed_during_review",next_evidence_step:"refresh_saved_index"}
                      elif valid_counts and (.packet_evidence_status | strings | test("\\A[a-z_]{1,48}\\z")) and
                           (.next_evidence_step | strings | test("\\A[a-z_]{1,64}\\z")) then
                        {packet_evidence_status,next_evidence_step,evidence_availability}
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
