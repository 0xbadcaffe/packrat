#!/usr/bin/env bash
set -euo pipefail

dir=$(mktemp -d)
trap 'rm -rf -- "$dir"' EXIT
cp -- "$(dirname "$0")/../scripts/packrat-review-backlog.sh" "$dir/packrat-review-backlog"
export TEST_DIR=$dir
touch -- "$dir/alerts.jsonl" "$dir/previous.jsonl"
cat > "$dir/packrat-triage" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $PACKRAT_TRIAGE_READ_TIMEOUT =~ ^[1-9][0-9]*$ && $PACKRAT_TRIAGE_ARCHIVE == "$TEST_DIR" ]]
[[ $PACKRAT_TRIAGE_AUTO_EVIDENCE == 0 && ! -v PACKRAT_TRIAGE_EVIDENCE_ALERT_ID ]]
session=session-a capture=00000000000000000000000000000001
base='{"rule_id":"scan.horizontal","revision":7,"confidence":"heuristic","severity":"HIGH",
       "disposition":"New","last_seen":42,"evidence_frame_count":2,"trigger_frame_number":4,
       "recorded_trigger_flow_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
       "evidence_frame_set_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}'
if [[ ${TEST_MODE:-normal} == by_rule || ${TEST_MODE:-normal} == wrong_rule ]]; then
    base=$(jq -c '. + {rule_id:"ipv6.ra_router_link_change",severity:"MEDIUM"}' <<< "$base")
elif [[ ${TEST_MODE:-normal} == info ]]; then
    base=$(jq -c '. + {rule_id:"vlan.vid_one_observed",severity:"INFO"}' <<< "$base")
elif [[ ${TEST_MODE:-normal} == legacy_trigger ]]; then
    base=$(jq -c 'del(.trigger_frame_number)' <<< "$base")
elif [[ ${TEST_MODE:-normal} == legacy_tuple ]]; then
    base=$(jq -c 'del(.recorded_trigger_flow_sha256)' <<< "$base")
fi
if [[ ${FLOW_MODE:-normal} == tcp_ack_* ]]; then base=$(jq -c '.evidence_frame_count=3' <<< "$base"); fi
if [[ $1 == --list-saved ]]; then
    [[ ! -v PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE ]]
    shift
    offset=0 rule='' review_session='' review_capture=''
    if [[ $1 == --review-scope ]]; then review_session=$2 review_capture=$3; shift 3; fi
    if [[ $1 == --review-rule ]]; then rule=$2; shift 2; fi
    if [[ $1 == --review-offset ]]; then offset=$2; shift 2; fi
    [[ $# == 2 && $1 == "$TEST_DIR/alerts.jsonl" && $2 == "$TEST_DIR/previous.jsonl" ]]
    if [[ ${TEST_MODE:-normal} == index_race ]]; then printf 'new record\n' >>"$1"; fi
    jq -nc --arg session "$session" --arg capture "$capture" --argjson base "$base" --arg mode "${TEST_MODE:-normal}" --argjson offset "$offset" --arg rule "$rule" \
        --arg selected_session "$review_session" --arg selected_capture "$review_capture" '
        (if $mode == "empty" then 0 elif $rule != "" then 1 else 7 end) as $eligible |
        {record_type:"saved_capture_index",status:"saved",sampled_alerts:12,
         review_rule:(if $rule == "" then null else $rule end),
         review_scope:(if $selected_capture == "" then null else {session_id:$selected_session,capture_id:$selected_capture} end),
         sampled_unscoped_open_high_or_critical:3,sample_scan_complete:($mode != "bounded"),
         unscoped_review_queue:[{session_id:$session,alert_id:9,severity:"CRITICAL",disposition:"Reviewing",
           capture_id:"private scope",title:"private title",
           evidence_frame_count:(if $mode=="no_refs" then 0 elif $mode=="bad_refs" then 132 else 1 end),
           legacy_rule_hint:"dns.competing_responders",next_evidence_step:"private suggestion"}],
         review_eligible_in_sample:$eligible,review_offset:$offset,
         review_shortlist_truncated:($eligible > $offset + 5),
         next_review_offset:(if $eligible > $offset + 5 then $offset + 5 else null end),
         review_shortlist:[range($offset + 1;[($eligible + 1),($offset + (if $mode == "extra" then 7 else 6 end))] | min)
           | $base + {session_id:$session,capture_id:$capture,alert_id:.}]}
         | if $selected_capture == "" then . else .sampled_unscoped_open_high_or_critical = 0 | .unscoped_review_queue = [] end
         | if ($mode | startswith("latency_")) then
            .review_latency={sampled_alerts:12,measured_alerts:3,unmeasured_alerts:9,min_ms:0,median_ms:100,max_ms:200,
                unmeasured_reasons:{missing_capture_scope:1,missing_first_save:2,missing_first_review:6,review_before_save:0},
                detail:"private time"}
            | if $mode == "latency_bad_counts" then .review_latency.sampled_alerts=3
              elif $mode == "latency_bad_order" then .review_latency.median_ms=201
              elif $mode == "latency_bad_reasons" then .review_latency.unmeasured_reasons.missing_first_review=5
              elif $mode == "latency_legacy" then del(.review_latency.unmeasured_reasons)
              else . end
           else . end'
    exit
fi
[[ $1 == --saved-alert && $2 == "$session" && $3 == "$capture" &&
    $5 == "$TEST_DIR/alerts.jsonl" && $6 == "$TEST_DIR/previous.jsonl" && $PACKRAT_TRIAGE_EXACT_SCAN_BYTES == 8388608 ]]
printf '%s\n' "$4" >> "$TEST_DIR/checks"
if [[ ${TEST_MODE:-normal} == evidence_race && $4 == 3 ]]; then printf 'late record\n' >>"$6"; fi
if [[ ${TEST_MODE:-normal} == timed ]]; then sleep 20; fi
counts=null
case $4 in
    1) status=complete step=inspect_retained_frames counts='{"complete":2}' ;;
    2) status=unavailable step=check_archive_integrity counts='{"missing":1,"unreadable":1}' ;;
    3) status=complete step=inspect_retained_frames counts='{"complete":2}'; base=$(jq '.evidence_frame_set_sha256=("a"*64)' <<< "$base") ;;
    4) if [[ ${TEST_MODE:-normal} == scan_exhausted ]]; then
           jq -cn --arg session "$session" --arg capture "$capture" --argjson id "$4" '
               {record_type:"capture_triage",mode:"saved",status:"saved_log_degraded",alerts:[],
                scope:{session_id:$session,capture_id:$capture,alert_id:$id},
                alert_log_integrity:{stopped_at_scan_budget:true}}'
       else printf '%s\n' '{"record_type":"capture_triage","mode":"saved","status":"saved_alert_not_observed"}'; fi
       exit 1 ;;
    5) status=check_failed step=retry_evidence_check ;;
    6|7) status=partial step=inspect_retained_and_recover_missing_frames counts='{"truncated":1,"missing":1}' ;;
esac
if [[ ${TEST_MODE:-normal} == invalid_counts && $4 == 1 ]]; then counts='{"complete":1}'; fi
if [[ ${FLOW_MODE:-normal} == status_swap && $4 == 1 ]]; then
    status=partial counts='{"complete":1,"truncated":1}'
fi
if [[ ${FLOW_MODE:-normal} == tcp_ack_* && $4 == 1 ]]; then counts='{"complete":3}'; fi
if [[ ${TEST_MODE:-normal} == trigger_drift && $4 == 1 ]]; then base=$(jq -c '.trigger_frame_number=5' <<< "$base"); fi
if [[ ${TEST_MODE:-normal} == tuple_drift && $4 == 1 ]]; then base=$(jq -c '.recorded_trigger_flow_sha256=("b"*64)' <<< "$base"); fi
case $4 in
    1|3) base=$(jq -c '.reader_rule_revision=8' <<< "$base") ;;
    2) base=$(jq -c '.reader_rule_revision=7' <<< "$base") ;;
    5) base=$(jq -c '.reader_rule_revision="private revision"' <<< "$base") ;;
esac
if [[ ${TEST_MODE:-normal} == socket ]]; then
    [[ $PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE == "$TEST_DIR/socket context.jsonl" ]]
    marker=latest
    if [[ $4 == 2 ]]; then marker=earlier; fi
    if [[ $4 == 5 ]]; then marker='private invalid marker'; fi
    base=$(jq -c --arg marker "$marker" '. + {socket_evidence:$marker,socket_context:{process:"private process",pid:123}}' <<< "$base")
else
    [[ -z ${PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE:-} ]]
fi
jq -nc --arg session "$2" --arg capture "$3" --argjson id "$4" --arg status "$status" --arg step "$step" \
    --argjson base "$base" --argjson counts "$counts" --arg mode "${TEST_MODE:-normal}" '
    {record_type:"capture_triage",mode:"saved",status:"saved",alerts:[$base + {session_id:$session,capture_id:$capture,alert_id:$id,
      packet_evidence_status:$status,next_evidence_step:$step,evidence_availability:$counts,detail:"private detail"}],
      evidence_checks:[{frames:[{status:"complete",bytes:[5,7]}],path:"private path"}]}
    | if $status | IN("complete","partial") then .evidence_status={status:"checked",alert_id:$id,
        frames:[{frame_number:3,status:(if $counts.truncated then "truncated" else "complete" end),bytes:[5,7]},
                {frame_number:4,status:(if $counts.missing then "missing" else "complete" end)}]}
      else . end
    | if $counts.complete==3 then .evidence_status.frames += [{frame_number:5,status:"complete"}] else . end
    | if $mode=="missing_receipt" then del(.evidence_status)
      elif $mode=="duplicate_receipt" then .evidence_status.frames[1].frame_number=3
      elif $mode=="unmatched_receipt" then .evidence_status.alert_id=2
      elif $mode=="receipt_count_drift" then .evidence_status.frames[0].status="missing"
      else . end'
if [[ $status == check_failed ]]; then exit 2; fi
STUB
cat > "$dir/packrat-archive" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 9 && $1 == "$TEST_DIR" && $2 == --alert-flow-summary &&
    $3 == "$TEST_DIR/alerts.jsonl" && $4 == session-a &&
    $6 == --capture-id && $7 == 00000000000000000000000000000001 &&
    $8 == --previous-log && $9 == "$TEST_DIR/previous.jsonl" ]]
printf '%s\n' "$5" >> "$TEST_DIR/flow-checks"
jq -nc --arg session "$4" --argjson alert "$5" --arg capture "$7" --arg mode "${FLOW_MODE:-normal}" '
    def exchange($protocol):
        {protocol:$protocol,section_id:0,interface_id:1,evidence_frames:1,vlan_stack:[{tpid:33024,vid:20}]} as $base
        | [$base + {source:"192.0.2.1:22222",destination:"192.0.2.2:443",frames:[{frame_number:3,status:"complete"}]},
           $base + {source:"192.0.2.2:443",destination:"192.0.2.1:22222",frames:[{frame_number:4,status:"complete"}]}];
    {record_type:"alert_flow_summary",session_id:$session,capture_id:$capture,alert_id:$alert,
     evidence_frame_set_sha256:("0"*64),referenced_frames:2,missing_frames:0,unreadable_frames:0,
     truncated_frames:0,length_unknown_frames:0,
     retained_frames_without_flow:0,trigger_tuple_status:"matches_wire",
     recorded_trigger_flow_sha256:("a"*64),
     trigger_frame:{frame_number:4,status:"complete",transport_header_observed:true},
     unassigned_frames:[],
     directional_flows:[{protocol:"udp",evidence_frames:2,endpoint:"private endpoint",cited_timing:{
        timestamped_frames:2,missing_timestamp_frames:0,forward_gaps:1,tied_timestamps:0,
        backwards_timestamps:0,min_forward_gap_secs:2.75,private_debug:"private time"},
        frames:[{frame_number:3,status:"complete"},{frame_number:4,status:"complete"}]}],
     tcp_syn_ack_matches:[],
     udp_dns_reply_candidates:[{reply_frame:4,query_candidate_frames:[],name:"private name"}]}
    | if $mode == "digest" then .evidence_frame_set_sha256=("1"*64)
      elif $mode == "availability" then .missing_frames=1
      elif $mode == "scope" then .session_id="wrong-session"
      elif $mode == "partition_drift" then .directional_flows[0].frames[0].frame_number=2
      elif $mode == "status_swap" then .truncated_frames=1
          | .directional_flows[0].frames[1].status="truncated" | .trigger_frame.status="truncated"
      elif $mode == "dns_outside_frame" then .udp_dns_reply_candidates[0].query_candidate_frames=[2]
      elif ($mode | startswith("dns_path_")) then
          .directional_flows=exchange("udp") | .udp_dns_reply_candidates[0].query_candidate_frames=[3]
          | if $mode=="dns_path_wrong_vlan" then .directional_flows[0].vlan_stack[0].tpid=34984
            elif $mode=="dns_path_unknown" then del(.directional_flows[0].interface_id)
            else . end
      elif $mode == "trigger_header_across_partition" then
          .unassigned_frames=[.directional_flows[0].frames[1]]
          | .directional_flows[0].frames |= .[:1]
          | .directional_flows[0].evidence_frames=1 | .retained_frames_without_flow=1
          | .udp_dns_reply_candidates=[]
      elif $mode == "malformed" then .udp_dns_reply_candidates[0].query_candidate_frames=[4]
      elif $mode == "dns_unavailable" then
          .udp_dns_reply_candidates[0] += {timestamp_basis:"unavailable",query_candidate_frames:[]}
      elif $mode == "dns_partial_timing" then
          .udp_dns_reply_candidates[0].query_candidate_frames=[]
          | .udp_dns_reply_candidates += [{reply_frame:3,query_candidate_frames:[],timestamp_basis:"legacy_packet_time"}]
      elif $mode == "dns_impossible_timing" then
          .udp_dns_reply_candidates[0] += {timestamp_basis:"unavailable",query_candidate_frames:[3]}
      elif $mode == "dns_unknown_basis" then .udp_dns_reply_candidates[0].timestamp_basis="private time"
      elif $mode == "dns_duplicate_reply" then .udp_dns_reply_candidates += .udp_dns_reply_candidates
      elif $mode == "frame_count" then .retained_frames_without_flow=1
      elif $mode == "trigger_status" then .trigger_frame.transport_header_observed=false
      elif $mode == "trigger_private" then .trigger_frame.status="private payload"
      elif $mode == "trigger_drift" then .trigger_frame.frame_number=5
      elif $mode == "tuple_drift" then .recorded_trigger_flow_sha256=("b"*64)
      elif $mode == "legacy_tuple" then del(.recorded_trigger_flow_sha256)
      elif $mode == "legacy_timing" then del(.directional_flows[0].cited_timing)
      elif ($mode | startswith("payload_")) then
          .directional_flows[0] += {cited_declared_payload_bytes:150,cited_captured_payload_bytes:100}
          | if $mode=="payload_bad_order" then .directional_flows[0].cited_captured_payload_bytes=151
            elif $mode=="payload_missing_counter" then del(.directional_flows[0].cited_declared_payload_bytes)
            elif $mode=="payload_overbound" then .directional_flows[0].cited_declared_payload_bytes=2097153
            elif $mode=="payload_fractional" then .directional_flows[0].cited_captured_payload_bytes=1.5
            elif $mode=="payload_mixed_directions" then
                .directional_flows[1]=(.directional_flows[0] | .frames |= .[:1] | .evidence_frames=1)
                | .directional_flows[0].frames |= .[1:]
                | .directional_flows[0] += {evidence_frames:1,cited_declared_payload_bytes:300,cited_captured_payload_bytes:300}
              else . end
      elif $mode == "invalid_timing" then .directional_flows[0].cited_timing.backwards_timestamps=1
      elif $mode == "malformed_timing" then .directional_flows[0].cited_timing="private time"
      elif ($mode | startswith("connection_")) then
          .directional_flows=[
              {protocol:"tcp",evidence_frames:1,contains_trigger_frame:true,reverse_evidence_frames:1,
                   source:"192.0.2.1:22222",destination:"192.0.2.2:443",section_id:0,interface_id:1,
                   vlan_stack:[{tpid:34984,vid:20},{tpid:33024,vid:30}],
                   frames:[{frame_number:4,status:"complete"}]},
              {protocol:"tcp",evidence_frames:1,contains_trigger_frame:false,reverse_evidence_frames:1,
                   destination:"192.0.2.1:22222",source:"192.0.2.2:443",section_id:0,interface_id:1,
                   vlan_stack:[{tpid:34984,vid:20},{tpid:33024,vid:30}],
                   frames:[{frame_number:3,status:"complete"}]}]
          | .udp_dns_reply_candidates=[]
          | if $mode == "connection_other" then
              .directional_flows[1].interface_id=2 | .directional_flows[].reverse_evidence_frames=0
            elif $mode == "connection_vlan_other" then
              .directional_flows[1].vlan_stack[0].tpid=33024 | .directional_flows[].reverse_evidence_frames=0
            elif $mode == "connection_wrong_vlan_reply" then .directional_flows[1].vlan_stack[0].tpid=33024
            elif $mode == "connection_wrong_order" then .directional_flows[1].vlan_stack |= reverse
            elif $mode == "connection_wrong_trigger" then .directional_flows |= map(.contains_trigger_frame |= not)
            elif $mode == "connection_missing_path" then del(.directional_flows[1].interface_id)
            elif $mode == "connection_duplicate" then .directional_flows[1].contains_trigger_frame=true
            elif $mode == "connection_bad_count" then .directional_flows[0].reverse_evidence_frames=2
            elif $mode == "connection_mismatch" then .trigger_tuple_status="differs_from_wire"
            else . end
      elif ($mode | startswith("tcp_")) then
          .udp_dns_reply_candidates=[]
          | .directional_flows=exchange("tcp")
          | .directional_flows[0] += {initial_syn_frames:1,syn_ack_frames:0,reset_frames:0}
          | .directional_flows[1] += {initial_syn_frames:0,syn_ack_frames:1,reset_frames:0}
          | .cited_syn_fanout={source_hosts:1,destination_hosts:1,destination_ports:1,capture_paths:1,
              endpoint:"private source"}
          | .tcp_syn_ack_matches=[{syn_ack_frame:4,latest_candidate_syn_frame:3,
              prior_syn_candidates:1,later_ack_candidates:0,earliest_candidate_ack_frame:null}]
          | if $mode == "tcp_impossible_ack" then .tcp_syn_ack_matches[0].earliest_candidate_ack_frame=3
            elif $mode == "tcp_duplicate" then .tcp_syn_ack_matches += .tcp_syn_ack_matches
            elif $mode == "tcp_outside_frame" then .tcp_syn_ack_matches[0].latest_candidate_syn_frame=2
            elif $mode == "tcp_wrong_order" then .tcp_syn_ack_matches[0].latest_candidate_syn_frame=4
            elif $mode == "tcp_wrong_interface" then .directional_flows[0].interface_id=2
            elif ($mode | startswith("tcp_ack_")) then
                .referenced_frames=3
                | .tcp_syn_ack_matches[0] += {later_ack_candidates:1,earliest_candidate_ack_frame:5}
                | .directional_flows[0].frames += [{frame_number:5,status:"complete"}]
                | .directional_flows[0].evidence_frames=2
                | if $mode=="tcp_ack_wrong_path" then
                    .directional_flows[2]=(.directional_flows[0] | .frames |= .[1:] | .evidence_frames=1
                        | .initial_syn_frames=0 | .section_id=1)
                    | .directional_flows[0].frames |= .[:1] | .directional_flows[0].evidence_frames=1
                  else . end
            elif $mode == "tcp_bad_flags" then .directional_flows[0].reset_frames=1
            elif $mode == "tcp_bad_fanout" then .cited_syn_fanout.destination_hosts=2
            else . end
      elif $mode == "udp_flags" then
          .directional_flows[0] += {protocol:"udp",initial_syn_frames:0,syn_ack_frames:0,reset_frames:0}
      elif $mode == "no_flow" then
          .unassigned_frames=.directional_flows[0].frames
          | .directional_flows=[] | .tcp_syn_ack_matches=[] | .udp_dns_reply_candidates=[]
          | .retained_frames_without_flow=2 | .trigger_tuple_status="trigger_header_unavailable"
          | .trigger_frame.transport_header_observed=false
      elif $mode == "old_reader" then del(.udp_dns_reply_candidates)
      else . end'
STUB
chmod +x "$dir/packrat-archive"
export PATH="$dir:$PATH"
run_review() {
    PACKRAT_TRIAGE_EVIDENCE_ALERT_ID=13 "$dir/packrat-review-backlog" "$@" "$dir" "$dir/alerts.jsonl" "$dir/previous.jsonl"
}
run_review | jq -e '
    .record_type == "saved_alert_evidence_review" and .index_status == "saved"
    and .sample_review_latency == null
    and .sampled_unscoped_open_high_or_critical == 3 and .review_shortlist_truncated and .sample_scan_complete
    and .review_offset == 0 and .next_review_offset == 5 and .review_eligible_in_sample == 7
    and .unscoped_review_queue == [{
        session_id:"session-a",alert_id:9,severity:"CRITICAL",disposition:"Reviewing",last_seen:null,
        legacy_rule_hint:"dns.competing_responders",evidence_frame_count:1,packet_evidence_status:"scope_unverified",
        next_evidence_step:"locate_original_capture_or_host_logs"}]
    and [.findings[].packet_evidence_status] ==
        ["complete","unavailable","changed_during_review","changed_during_review","check_failed"]
    and .findings[0].evidence_availability == {complete:2}
    and .findings[1].evidence_availability == {missing:1,unreadable:1}
    and [.findings[] | [.revision,.reader_rule_revision,.rule_revision_differs_from_reader,.severity]] ==
        [[7,8,true,"HIGH"],[7,7,false,"HIGH"],[7,null,null,"HIGH"],[7,null,null,"HIGH"],[7,null,null,"HIGH"]]
    and .findings[1].next_evidence_step == "check_archive_integrity"
    and .findings[2].next_evidence_step == "refresh_saved_index"
    and (tostring | contains("private") | not) and all(.findings[]; has("evidence_frame_set_sha256") | not)' >/dev/null
[[ $(wc -l < "$dir/checks") == 5 ]]
[[ ! -e $dir/flow-checks ]]
TEST_MODE=scan_exhausted run_review | jq -e '
    .findings[3] | .packet_evidence_status == "scan_budget_exhausted"
    and .next_evidence_step == "retry_exact_lookup_with_larger_scan_budget"' >/dev/null
run_review --flow-context | jq -e '
    [.findings[].flow_context_status] == ["checked","not_checked","not_checked","not_checked","not_checked"]
    and .findings[0].flow_context == {directional_flows:1,tcp_syn_ack_matches:0,udp_dns_replies:1,
        tcp_syn_ack_with_later_ack_candidates:0,tcp_syn_ack_without_later_ack_candidates:0,tcp_syn_ack_ambiguous_candidates:0,
        retained_flow_frames:2,retained_frames_without_flow:0,
        trigger_frame_status:"complete",trigger_transport_header_observed:true,trigger_tuple_status:"matches_wire",
        trigger_connection_status:"not_reported",
        timing_status:"reported",cited_timing:{timestamped_frames:2,missing_timestamp_frames:0,forward_gaps:1,
            tied_timestamps:0,backwards_timestamps:0,directions_with_forward_gaps:1},
        udp_dns_replies_with_query_candidates:0,udp_dns_ambiguous_replies:0,tcp_flag_status:"not_reported",
        udp_dns_timing_status:"not_reported",cited_payload_status:"not_reported",
        udp_dns_reply_timestamps:{capture_clock:0,legacy_packet_time:0,unavailable:0,not_reported:1}}
    and (tostring | contains("private") | not)' >/dev/null
[[ $(cat "$dir/flow-checks") == 1 ]]
for mode in missing_receipt duplicate_receipt unmatched_receipt receipt_count_drift; do
    TEST_MODE=$mode run_review --flow-context | jq -e '
        .findings[0] | .packet_evidence_status=="complete" and .flow_context_status=="frame_receipt_unverified"
        and (has("frame_receipt") or has("flow_context") | not)' >/dev/null
done
[[ $(cat "$dir/flow-checks") == 1 ]]
for mode in partition_drift status_swap trigger_header_across_partition dns_outside_frame tcp_outside_frame \
    dns_path_wrong_vlan dns_path_unknown tcp_wrong_interface tcp_ack_wrong_path; do
    wanted=citation_unverified
    if [[ $mode == partition_drift || $mode == status_swap ]]; then wanted=changed_during_review; fi
    FLOW_MODE=$mode run_review --flow-context | jq -e --arg wanted "$wanted" '
        .findings[0] | .flow_context_status==$wanted and (has("flow_context") or has("frame_receipt") | not)' >/dev/null
done
FLOW_MODE=dns_path_pair run_review --flow-context | jq -e '
    .findings[0].flow_context | .udp_dns_replies_with_query_candidates==1 and (tostring | contains("192.0.2.") | not)' >/dev/null
FLOW_MODE=tcp_ack_pair run_review --flow-context | jq -e '
    .findings[0].flow_context | .tcp_syn_ack_with_later_ack_candidates==1 and (tostring | contains("192.0.2.") | not)' >/dev/null
TEST_MODE=trigger_drift run_review --flow-context | jq -e '
    .findings[0] | .packet_evidence_status=="changed_during_review" and .flow_context_status=="not_checked"
    and (has("trigger_frame_number") | not)' >/dev/null
FLOW_MODE=trigger_drift run_review --flow-context | jq -e '
    .findings[0] | .packet_evidence_status=="complete" and .flow_context_status=="changed_during_review"
    and (has("flow_context") | not)' >/dev/null
TEST_MODE=legacy_trigger FLOW_MODE=connection_pair run_review --flow-context | jq -e '
    .findings[0].flow_context | .trigger_connection_status=="snapshot_unverified"
    and (has("cited_trigger_connection") | not)' >/dev/null
TEST_MODE=tuple_drift run_review --flow-context | jq -e '
    .findings[0] | .packet_evidence_status=="changed_during_review" and .flow_context_status=="not_checked"
    and (has("recorded_trigger_flow_sha256") | not)' >/dev/null
FLOW_MODE=tuple_drift run_review --flow-context | jq -e '
    .findings[0] | .packet_evidence_status=="complete" and .flow_context_status=="changed_during_review"
    and (has("flow_context") | not)' >/dev/null
TEST_MODE=legacy_tuple FLOW_MODE=connection_pair run_review --flow-context | jq -e '
    .findings[0].flow_context | .trigger_tuple_status=="snapshot_unverified" and .trigger_connection_status=="reported"' >/dev/null
FLOW_MODE=legacy_tuple run_review --flow-context | jq -e '
    .findings[0] | .flow_context_status=="checked" and .flow_context.trigger_tuple_status=="snapshot_unverified"' >/dev/null
for mode in connection_pair connection_other connection_vlan_other connection_mismatch; do
    FLOW_MODE=$mode run_review --flow-context | jq -e --arg mode "$mode" '
        .findings[0].flow_context | .trigger_connection_status=="reported"
        and .cited_trigger_connection=={same_direction_frames:1,
            reverse_direction_frames:(if $mode|IN("connection_other","connection_vlan_other") then 0 else 1 end),
            other_flow_frames:(if $mode|IN("connection_other","connection_vlan_other") then 1 else 0 end)}
        and (.trigger_tuple_status=="differs_from_wire") == ($mode=="connection_mismatch")
        and (tostring | (contains("private") or contains("192.0.2.")) | not)' >/dev/null
done
for mode in connection_duplicate connection_bad_count connection_wrong_trigger connection_wrong_vlan_reply connection_wrong_order; do
    FLOW_MODE=$mode run_review --flow-context | jq -e '
        .findings[0].flow_context | .trigger_connection_status=="invalid"
        and (has("cited_trigger_connection") | not)' >/dev/null
done
FLOW_MODE=connection_missing_path run_review --flow-context | jq -e '
    .findings[0].flow_context | .trigger_connection_status=="path_unverified"
    and (has("cited_trigger_connection") | not)' >/dev/null
FLOW_MODE=dns_unavailable run_review --flow-context | jq -e '
    .findings[0].flow_context | .udp_dns_replies_with_query_candidates==0
    and .udp_dns_timing_status=="reported" and .udp_dns_reply_timestamps.unavailable==1' >/dev/null
FLOW_MODE=dns_partial_timing run_review --flow-context | jq -e '
    .findings[0].flow_context | .udp_dns_timing_status=="partial"
    and .udp_dns_reply_timestamps=={capture_clock:0,legacy_packet_time:1,unavailable:0,not_reported:1}' >/dev/null
FLOW_MODE=tcp_pair run_review --flow-context | jq -e '
    .findings[0].flow_context | .tcp_syn_ack_matches==1
    and .tcp_syn_ack_without_later_ack_candidates==1 and .tcp_syn_ack_with_later_ack_candidates==0
    and .tcp_syn_ack_ambiguous_candidates==0 and .tcp_flag_status=="reported"
    and .cited_tcp_flags=={initial_syn_frames:1,syn_ack_frames:1,reset_frames:0}
    and .cited_syn_fanout=={source_hosts:1,destination_hosts:1,destination_ports:1,capture_paths:1}' >/dev/null
FLOW_MODE=tcp_bad_fanout run_review --flow-context | jq -e '
    .findings[0].flow_context | .tcp_flag_status=="reported" and (has("cited_syn_fanout")|not)' >/dev/null
FLOW_MODE=tcp_bad_flags run_review --flow-context | jq -e '
    .findings[0].flow_context | .tcp_flag_status=="invalid" and (has("cited_tcp_flags")|not)' >/dev/null
FLOW_MODE=udp_flags run_review --flow-context | jq -e '
    .findings[0].flow_context | .tcp_flag_status=="no_tcp_headers" and (has("cited_tcp_flags")|not)' >/dev/null
FLOW_MODE=payload_mixed_directions run_review --flow-context | jq -e '
    .findings[0].flow_context | .cited_payload_status=="reported"
    and .cited_payload_bytes=={declared:450,captured:400,declared_not_captured:50}
    and .trigger_direction_cited_payload_bytes=={declared:300,captured:300,declared_not_captured:0}
    and (tostring | contains("private") | not)' >/dev/null
for mode in payload_bad_order payload_missing_counter payload_overbound payload_fractional; do
    FLOW_MODE=$mode run_review --flow-context | jq -e '
        .findings[0] | .flow_context_status=="checked" and .flow_context.cited_payload_status=="invalid"
        and (.flow_context | (has("cited_payload_bytes") or has("trigger_direction_cited_payload_bytes"))|not)' >/dev/null
done
FLOW_MODE=no_flow run_review --flow-context | jq -e '
    .findings[0] | .packet_evidence_status=="complete" and .flow_context_status=="checked"
    and .flow_context.retained_flow_frames==0 and .flow_context.retained_frames_without_flow==2
    and .flow_context.trigger_tuple_status=="trigger_header_unavailable"
    and .flow_context.trigger_transport_header_observed==false
    and .flow_context.trigger_connection_status=="no_trigger_header"
    and .flow_context.timing_status=="no_flow_headers" and .flow_context.tcp_flag_status=="no_flow_headers"
    and .flow_context.udp_dns_timing_status=="no_dns_replies" and .flow_context.cited_payload_status=="no_flow_headers"
    and (.flow_context|has("cited_timing")|not)' >/dev/null
for mode in legacy_timing invalid_timing malformed_timing; do
    wanted=invalid
    if [[ $mode == legacy_timing ]]; then wanted=not_reported; fi
    FLOW_MODE=$mode run_review --flow-context | jq -e --arg wanted "$wanted" '
        .findings[0] | .flow_context_status=="checked" and .flow_context.timing_status==$wanted
        and (.flow_context|has("cited_timing")|not) and (tostring|contains("private")|not)' >/dev/null
done
for mode in digest availability scope malformed frame_count trigger_status trigger_private old_reader \
    tcp_impossible_ack tcp_duplicate tcp_wrong_order dns_impossible_timing dns_unknown_basis dns_duplicate_reply; do
    wanted=check_failed
    if [[ $mode == digest || $mode == availability ]]; then wanted=changed_during_review; fi
    FLOW_MODE=$mode run_review --flow-context | jq -e --arg wanted "$wanted" '
        .findings[0] | .flow_context_status == $wanted and (has("flow_context") | not)' >/dev/null
done
TEST_MODE=no_refs run_review | jq -e '.unscoped_review_queue[0] |
    .evidence_frame_count==0 and .packet_evidence_status=="no_references"
    and .next_evidence_step=="corroborate_with_host_or_service_logs"' >/dev/null
FLOW_MODE=normal TEST_MODE=latency_valid run_review | jq -e '
    .sample_review_latency=={sampled_alerts:12,measured_alerts:3,unmeasured_alerts:9,min_ms:0,median_ms:100,max_ms:200,
        unmeasured_reasons:{missing_capture_scope:1,missing_first_save:2,missing_first_review:6,review_before_save:0}}' >/dev/null
TEST_MODE=latency_legacy run_review | jq -e '
    .sample_review_latency.measured_alerts==3 and (.sample_review_latency | has("unmeasured_reasons") | not)' >/dev/null
for mode in latency_bad_counts latency_bad_order latency_bad_reasons; do
    TEST_MODE=$mode run_review | jq -e '.sample_review_latency==null and (.findings | length)==5' >/dev/null
done
if TEST_MODE=bad_refs run_review >/dev/null 2>&1; then exit 1; fi
touch -- "$dir/socket context.jsonl"
TEST_MODE=socket run_review --socket-context "$dir/socket context.jsonl" | jq -e '
    [.findings[].socket_evidence] == ["latest","earlier",null,null,null]
    and .findings[1].packet_evidence_status == "unavailable"
    and (tostring | contains("private") | not)' >/dev/null
ln -s -- "$dir/socket context.jsonl" "$dir/socket-link"
if run_review --socket-context "$dir/socket-link" >/dev/null 2>&1; then exit 1; fi
TEST_MODE=invalid_counts run_review | jq -e '.findings[0].packet_evidence_status == "check_failed"' >/dev/null
: > "$dir/checks"
TEST_MODE=bounded run_review --review-offset 5 | jq -e '
    .review_offset == 5 and .next_review_offset == null and (.sample_scan_complete | not)
    and [.findings[].alert_id] == [6,7] and all(.findings[]; .packet_evidence_status == "partial")' >/dev/null
[[ $(cat "$dir/checks") == $'6\n7' ]]
token=$(run_review | jq -er '.review_snapshot_token | select(test("^[0-9a-f]{64}$"))')
: > "$dir/checks"
TZ=EST5 run_review --review-offset 5 --snapshot-token "$token" | jq -e --arg token "$token" '
    .review_snapshot_token==$token and [.findings[].alert_id]==[6,7]' >/dev/null
[[ $(cat "$dir/checks") == $'6\n7' ]]
: > "$dir/checks"
if run_review --review-rule other.rule --snapshot-token "$token" >"$dir/output" 2>/dev/null; then exit 1; fi
[[ ! -s $dir/output && ! -s $dir/checks ]]
printf 'later record\n' >>"$dir/previous.jsonl"
if run_review --review-offset 5 --snapshot-token "$token" >"$dir/output" 2>/dev/null; then exit 1; fi
[[ ! -s $dir/output && ! -s $dir/checks ]]
for mode in index_race evidence_race; do
    if TEST_MODE=$mode run_review >"$dir/output" 2>"$dir/error"; then exit 1; fi
    [[ ! -s $dir/output ]]
    grep -Fq 'logs changed during review' "$dir/error"
done
: > "$dir/checks"
run_review --review-offset 10 | jq -e '.sample_scan_complete and .findings == []' >/dev/null
[[ ! -s $dir/checks ]]
: > "$dir/checks"
TEST_MODE=empty run_review | jq -e '.findings == []' >/dev/null
[[ ! -s $dir/checks ]]
TEST_MODE=by_rule run_review --review-rule ipv6.ra_router_link_change | jq -e '
    .review_rule == "ipv6.ra_router_link_change" and .review_eligible_in_sample == 1
    and [.findings[] | [.rule_id,.severity,.packet_evidence_status]] == [["ipv6.ra_router_link_change","MEDIUM","complete"]]' >/dev/null
[[ $(cat "$dir/checks") == 1 ]]
: > "$dir/checks"
if TEST_MODE=wrong_rule run_review --review-rule other.rule >/dev/null 2>&1; then exit 1; fi
[[ ! -s $dir/checks ]]
TEST_MODE=info run_review --review-rule vlan.vid_one_observed | jq -e '
    [.findings[] | [.rule_id,.severity,.packet_evidence_status]] == [["vlan.vid_one_observed","INFO","complete"]]' >/dev/null
: > "$dir/checks"
TEST_MODE=by_rule run_review --review-scope session-a 00000000000000000000000000000001 \
    --review-rule ipv6.ra_router_link_change | jq -e '
    .review_scope == {session_id:"session-a",capture_id:"00000000000000000000000000000001"}
    and .unscoped_review_queue == [] and [.findings[].packet_evidence_status] == ["complete"]' >/dev/null
[[ $(cat "$dir/checks") == 1 ]]
: > "$dir/checks"
if run_review --review-scope session-b 00000000000000000000000000000001 >/dev/null 2>&1; then exit 1; fi
[[ ! -s $dir/checks ]]
if TEST_MODE=extra run_review >"$dir/output" 2>/dev/null; then exit 1; fi
[[ ! -s $dir/output && ! -s $dir/checks ]]
PACKRAT_BACKLOG_TIMEOUT=2 TEST_MODE=timed run_review | jq -e '
    [.findings[].packet_evidence_status] ==
        ["check_timed_out","check_deferred","check_deferred","check_deferred","check_deferred"]' >/dev/null
[[ $(wc -l < "$dir/checks") == 1 ]]
printf '%s\n' 'saved alert backlog evidence tests passed'
