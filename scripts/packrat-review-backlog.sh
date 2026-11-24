#!/usr/bin/env bash
# Check saved findings against a packet archive without exporting frames.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-review-backlog.sh [--review-scope SESSION_ID CAPTURE_ID] [--review-rule RULE_ID] [--review-offset N] [--socket-context FILE] [--flow-context] ARCHIVE ALERT_LOG [PREVIOUS_LOG ...]' \
        'Review five scoped High/Critical alerts per page, or a named rule at any severity. Use immutable logs across pages.' \
        'With --socket-context, report verified socket evidence availability without process or endpoint details.' \
        'With --flow-context, report cited transport-header coverage, initial SYN fan-out, and candidate TCP and UDP DNS links without disclosing endpoints.' \
        'Timing counts describe adjacent cited frames, not full-flow cadence.' \
        'UDP DNS timing counts distinguish capture-clock, legacy, unavailable, and unreported reply times.' \
        'Reader rule revisions are compared with saved revisions without reclassifying findings.' \
        'PACKRAT_BACKLOG_TIMEOUT sets the shared deadline (default: 15 seconds).'
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
offset=0 rule='' session_scope='' capture_scope='' socket_file='' index_args=() flow_context=false
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
if [[ ${1-} == --socket-context ]]; then
    socket_file=${2-}
    [[ $socket_file == /* && $socket_file != *[[:cntrl:]]* && -f $socket_file && ! -L $socket_file ]] ||
        { usage >&2; exit 2; }
    shift 2
fi
if [[ ${1-} == --flow-context ]]; then flow_context=true; shift; fi
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

check_flow_context() {
    local remaining=$1 selected=$2 reply=$3 session=$4 capture=$5 alert=$6 active=$7 raw rc=0
    shift 7
    local -a previous=()
    local log
    for log in "$@"; do previous+=(--previous-log "$log"); done
    raw=$(timeout --kill-after=1s "${remaining}s" packrat-archive "$archive" --alert-flow-summary \
        "$active" "$session" "$alert" --capture-id "$capture" "${previous[@]}" | head -c 1048577) || rc=$?
    if (( rc == 124 || rc == 137 )); then
        printf '%s\n' '{"flow_context_status":"check_timed_out"}'
        return
    fi
    (( rc == 0 && ${#raw} <= 1048576 )) || return 1
    jq -ces --argjson selected "$selected" --argjson verified "$reply" '
        def frame: type == "number" and . >= 1 and . <= 9007199254740991 and floor == .;
        def count: type == "number" and . >= 0 and . <= $selected.evidence_frame_count and floor == .;
        def frames: type == "array" and length <= $selected.evidence_frame_count;
        def valid_syn_ack_match:
            .syn_ack_frame as $response
            | ($response | frame) and (.latest_candidate_syn_frame | frame and . < $response)
              and (.prior_syn_candidates | count and . > 0)
              and (.later_ack_candidates | count)
              and .prior_syn_candidates + .later_ack_candidates < $selected.evidence_frame_count
              and (if .later_ack_candidates == 0 then .earliest_candidate_ack_frame == null
                   else (.earliest_candidate_ack_frame | frame and . > $response) end);
        def valid_dns_reply:
            .reply_frame as $reply
            | ($reply | frame) and (.query_candidate_frames | frames and all(.[]; frame and . < $reply) and . == unique)
              and (if has("timestamp_basis") then
                    (.timestamp_basis | IN("capture_clock","legacy_packet_time","unavailable"))
                    and (.timestamp_basis != "unavailable" or .query_candidate_frames == [])
                   else true end);
        def dns_timing_context:
            .udp_dns_reply_candidates
            | if length == 0 then {udp_dns_timing_status:"no_dns_replies"}
              else reduce .[] as $reply ({capture_clock:0,legacy_packet_time:0,unavailable:0,not_reported:0};
                    .[$reply.timestamp_basis // "not_reported"] += 1) as $counts
              | {udp_dns_timing_status:(if $counts.not_reported == length then "not_reported"
                                        elif $counts.not_reported > 0 then "partial" else "reported" end),
                 udp_dns_reply_timestamps:$counts} end;
        def valid_timing:
            .evidence_frames as $frames
            | .cited_timing | type == "object"
              and all([.timestamped_frames,.missing_timestamp_frames,.forward_gaps,.tied_timestamps,.backwards_timestamps][]; count)
              and .timestamped_frames + .missing_timestamp_frames == $frames
              and .forward_gaps + .tied_timestamps + .backwards_timestamps <= ([0, .timestamped_frames - 1] | max);
        def timing_context:
            .directional_flows
            | if length == 0 then {timing_status:"no_flow_headers"}
              elif all(.[]; has("cited_timing") | not) then {timing_status:"not_reported"}
              elif all(.[]; valid_timing) then
                {timing_status:"reported",cited_timing:(
                    reduce .[].cited_timing as $flow (
                        {timestamped_frames:0,missing_timestamp_frames:0,forward_gaps:0,
                         tied_timestamps:0,backwards_timestamps:0,directions_with_forward_gaps:0};
                        .timestamped_frames += $flow.timestamped_frames
                        | .missing_timestamp_frames += $flow.missing_timestamp_frames
                        | .forward_gaps += $flow.forward_gaps
                        | .tied_timestamps += $flow.tied_timestamps
                        | .backwards_timestamps += $flow.backwards_timestamps
                        | .directions_with_forward_gaps += (if $flow.forward_gaps > 0 then 1 else 0 end)
                    )
                )}
              else {timing_status:"invalid"} end;
        def flag_fields: {initial_syn_frames,syn_ack_frames,reset_frames};
        def valid_flag_counts:
            .evidence_frames as $frames | .protocol as $protocol | flag_fields
            | all(.[]; count) and (([.[]] | add) <= $frames)
              and ($protocol == "tcp" or ($protocol == "udp" and all(.[]; . == 0)));
        def tcp_flag_context:
            .directional_flows
            | if length == 0 then {tcp_flag_status:"no_flow_headers"}
              elif all(.[]; has("initial_syn_frames") or has("syn_ack_frames") or has("reset_frames") | not)
                then {tcp_flag_status:"not_reported"}
              elif any(.[]; valid_flag_counts | not) then {tcp_flag_status:"invalid"}
              elif all(.[]; .protocol == "udp") then {tcp_flag_status:"no_tcp_headers"}
              else {tcp_flag_status:"reported",cited_tcp_flags:{
                  initial_syn_frames:([.[].initial_syn_frames] | add),
                  syn_ack_frames:([.[].syn_ack_frames] | add),
                  reset_frames:([.[].reset_frames] | add)
              }} end;
        def syn_fanout:
            (tcp_flag_context | .cited_tcp_flags.initial_syn_frames // 0) as $syns
            | ([.directional_flows[] | select((.initial_syn_frames | count) and .initial_syn_frames > 0)] | length) as $directions
            | ((.cited_syn_fanout | objects | {source_hosts,destination_hosts,destination_ports,capture_paths}
                | select($syns > 0 and all(.[]; count and . > 0 and . <= $directions))
                | {cited_syn_fanout:.}) // {});
        def valid_trigger:
            (.trigger_tuple_status | IN("not_recorded","trigger_header_unavailable","matches_wire","differs_from_wire"))
            and (.trigger_frame | . == null or
                ((.frame_number | frame) and (.status | IN("complete","truncated","length_unknown","missing","unreadable"))
                    and (.transport_header_observed | type == "boolean")
                    and (if .status | IN("missing","unreadable") then .transport_header_observed == false else true end)))
            and (if .trigger_tuple_status | IN("matches_wire","differs_from_wire") then
                    .trigger_frame.transport_header_observed == true
                 elif .trigger_tuple_status == "trigger_header_unavailable" then
                    .trigger_frame.transport_header_observed != true
                 else true end);
        select(length == 1) | .[0] | objects
        | select(.record_type == "alert_flow_summary" and
            {session_id,capture_id,alert_id} == ($selected | {session_id,capture_id,alert_id}))
        | if .evidence_frame_set_sha256 != $selected.evidence_frame_set_sha256
             or .referenced_frames != $selected.evidence_frame_count
             or .missing_frames != ($verified.evidence_availability.missing // 0)
             or .unreadable_frames != ($verified.evidence_availability.unreadable // 0)
             or .truncated_frames != ($verified.evidence_availability.truncated // 0)
             or .length_unknown_frames != ($verified.evidence_availability.length_unknown // 0)
          then {flow_context_status:"changed_during_review"}
          else select((.directional_flows | frames and all(.[]; .evidence_frames | count and . > 0))
                and (.retained_frames_without_flow | count) and valid_trigger
                and (.tcp_syn_ack_matches | frames and all(.[]; valid_syn_ack_match)
                     and length == (unique_by(.syn_ack_frame)|length))
                and (.udp_dns_reply_candidates | frames and all(.[]; valid_dns_reply)
                     and length == (unique_by(.reply_frame)|length)))
            | ([.directional_flows[].evidence_frames] | add // 0) as $flow_frames
            | select($flow_frames + .retained_frames_without_flow + .missing_frames + .unreadable_frames == .referenced_frames)
            | {flow_context_status:"checked",flow_context:{
                retained_flow_frames:$flow_frames,retained_frames_without_flow,
                trigger_frame_status:.trigger_frame.status,
                trigger_transport_header_observed:.trigger_frame.transport_header_observed,
                trigger_tuple_status,
                directional_flows:(.directional_flows|length),tcp_syn_ack_matches:(.tcp_syn_ack_matches|length),
                tcp_syn_ack_with_later_ack_candidates:([.tcp_syn_ack_matches[] | select(.later_ack_candidates > 0)]|length),
                tcp_syn_ack_without_later_ack_candidates:([.tcp_syn_ack_matches[] | select(.later_ack_candidates == 0)]|length),
                tcp_syn_ack_ambiguous_candidates:([.tcp_syn_ack_matches[]
                    | select(.prior_syn_candidates > 1 or .later_ack_candidates > 1)]|length),
                udp_dns_replies:(.udp_dns_reply_candidates|length),
                udp_dns_replies_with_query_candidates:([.udp_dns_reply_candidates[] | select(.query_candidate_frames|length > 0)]|length),
                udp_dns_ambiguous_replies:([.udp_dns_reply_candidates[] | select(.query_candidate_frames|length > 1)]|length)}
                + timing_context + tcp_flag_context + syn_fanout + dns_timing_context}
          end
    ' <<< "$raw"
}

rc=0
raw=$(triage_with_budget "$budget" --list-saved "${index_args[@]}" "$@") || rc=$?
if (( rc > 1 || ${#raw} > 1048576 )) || ! index=$(jq -ces --arg rule "$rule" --argjson offset "$offset" \
    --arg session "$session_scope" --arg capture "$capture_scope" '
    def count: type == "number" and . >= 0 and . <= 512 and floor == .;
    def frame_count: count and . <= 131;
    def valid_reference:
        type == "object" and (.session_id | strings | test("\\A[A-Za-z0-9_-]{1,128}\\z"))
        and (.alert_id | numbers | . >= 1 and . <= 999999999999999 and floor == .)
        and (.disposition == "New" or .disposition == "Reviewing" or .disposition == "Confirmed");
    def priority: .severity == "HIGH" or .severity == "CRITICAL";
    def selected: if $rule == "" then priority else .rule_id == $rule and (.severity | IN("CRITICAL","HIGH","MEDIUM","LOW","INFO")) end;
    def valid_entry: valid_reference and selected
        and ($capture == "" or (.session_id == $session and .capture_id == $capture))
        and (.capture_id | strings | test("\\A[0-9a-f]{32}\\z"))
        and (.evidence_frame_set_sha256 | strings | test("\\A[0-9a-f]{64}\\z"))
        and (.evidence_frame_count | frame_count)
        and (.rule_id == null or (.rule_id | strings | test("\\A[a-z0-9_.-]{1,128}\\z")))
        and (.revision == null or (.revision | numbers | . >= 1 and . <= 65535 and floor == .))
        and (.confidence == null or .confidence == "heuristic" or .confidence == "correlated" or .confidence == "direct_observation")
        and (.last_seen | numbers | isfinite);
    def unscoped_reference: valid_reference and priority
        and (.evidence_frame_count | . == null or frame_count)
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
             legacy_rule_hint,evidence_frame_count,
             packet_evidence_status:(if .evidence_frame_count == 0 then "no_references" else "scope_unverified" end),
             next_evidence_step:(if .evidence_frame_count == 0 then "corroborate_with_host_or_service_logs" else "locate_original_capture_or_host_logs" end)})),
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
        raw=$(PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE="$socket_file" \
            triage_with_budget "$remaining" --saved-alert "$session" "$capture" "$alert" "$@") || rc=$?
        status=check_failed
        if (( rc == 124 || rc == 137 )); then status=check_timed_out; fi
        if (( rc <= 2 && ${#raw} <= 1048576 )); then
            verdict=$(jq -ces --argjson selected "$candidate" '
                def reader_revision:
                    if .rule_id != null and .revision != null and
                        (.reader_rule_revision | type == "number" and . >= 1 and . <= 65535 and floor == .)
                    then {reader_rule_revision, rule_revision_differs_from_reader:(.reader_rule_revision != .revision)}
                    else {} end;
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
                        {packet_evidence_status,next_evidence_step,evidence_availability} + reader_revision
                        + (if .socket_evidence | IN("latest","earlier","latest_and_earlier") then {socket_evidence} else {} end)
                      else null end
                  else null end' <<< "$raw") || verdict='null'
        fi
    fi
    flow='{}'
    if "$flow_context"; then
        flow='{"flow_context_status":"not_checked"}'
        if jq -e '.packet_evidence_status | IN("complete","partial")' <<<"$verdict" >/dev/null; then
            remaining=$((deadline - SECONDS))
            flow='{"flow_context_status":"check_deferred"}'
            if (( remaining > 0 )); then
                flow=$(check_flow_context "$remaining" "$candidate" "$verdict" "$session" "$capture" "$alert" "$@") ||
                    flow='{"flow_context_status":"check_failed"}'
            fi
        fi
    fi
    results=$(jq -c --argjson candidate "$candidate" --argjson verdict "$verdict" --argjson flow "$flow" --arg status "$status" '
        . + [($candidate | del(.evidence_frame_set_sha256))
             + ($verdict // {packet_evidence_status:$status,next_evidence_step:"retry_evidence_check"}) + $flow]
    ' <<< "$results")
done < <(jq -c '.review_shortlist[]' <<< "$index")

jq -ce --argjson results "$results" 'del(.review_shortlist) + {
    record_type:"saved_alert_evidence_review", findings:$results}' <<< "$index"
