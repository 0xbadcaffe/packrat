#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
coverage="$root/scripts/packrat-watch-coverage.sh"
sample=$(jq -cn '
    {record_type:"capture_triage_watch",status:"current",capture_id:"a",session_id:"a-1",packets:10,
     updated_at:"2023-11-14T22:13:20Z",healthy_capture_since:1700000000,buffer_drops:0,
     capture_queue_full_packets:0,truncated_frames:0,link_decodable:true,alert_saving:true,alert_save_failures:0,alert_save_backlog_dropped:0,
     alert_log_integrity:{invalid_records:0,oversized_records:0,stopped_at_scan_budget:null},
     alert_log_advanced_during_review:false,
     packet_counter_gap:false,alert_sample_gap:false,highest_observed_alert_id:4,journal_unconfirmed_events:0} as $base
    | [$base,
      ($base + {updated_at:"2023-11-14T22:14:20Z",packets:35,checkpoint:true}),
      ($base + {updated_at:"2023-11-14T22:15:20Z",packets:70,highest_observed_alert_id:6,alert_changes:{newly_observed:[5,6]}}),
      ($base + {updated_at:"2023-11-14T22:16:20Z",packets:90,highest_observed_alert_id:8,alert_changes:{newly_observed:[8]}}),
      ({record_type:"capture_triage_watch",status:"triage_unavailable",updated_at:"2023-11-14T22:17:20Z"}),
      ($base + {updated_at:"2023-11-14T22:18:20Z",packets:140,highest_observed_alert_id:8}),
      ($base + {updated_at:"2023-11-14T22:19:20Z",packets:160,highest_observed_alert_id:9,packet_counter_gap:true}),
      ($base + {updated_at:"2023-11-14T22:20:20Z",session_id:"b-2",packets:1,highest_observed_alert_id:0})]
    | to_entries[] | .value + {journal_writer:"writer-a",journal_sequence:(.key+1)}')

bash "$coverage" --capture-id a --session a-1 <<< "$sample" | jq -e '
    .status=="sampled" and .coverage_policy=="continuous_journal_v7" and .scope=={capture_id:"a",session_id:"a-1"}
    and .scoped_records==6 and .healthy_intervals==3 and .excluded_intervals==2
    and .journal_discontinuities==0 and .journal_tail_unconfirmed_events==0 and .alert_journal_counter_unverified_intervals==0
    and .alert_log_snapshot_unverified_intervals==0
    and .healthy_seconds==180 and .healthy_packets==80 and .alert_comparable_intervals==2
    and .alert_comparable_packets==60 and .alert_comparable_seconds==120 and .observed_openings==2
    and .opening_rule_breakdown=={rules:[],unattributed_openings:2,omitted_rule_openings:0}
    and .unobserved_alert_id_ranges==[{first_id:7,last_id:7,recorded_at:"2023-11-14T22:16:20Z"}]
    and (.observed_openings_per_10000_packets > 333 and .observed_openings_per_10000_packets < 334)' >/dev/null
bash "$coverage" <<< "$sample" | jq -e '.status=="insufficient_coverage" and .scope.session_id=="b-2"
    and .alert_comparable_seconds==0 and .observed_openings==null and .observed_openings_per_10000_packets==null' >/dev/null
bash "$coverage" </dev/null | jq -e '.status=="no_capture_records" and .scope==null' >/dev/null
bash "$coverage" --capture-id missing --session a-1 <<< "$sample" |
    jq -e '.status=="no_capture_records" and .scope.capture_id=="missing"' >/dev/null
jq -sc '.[0:3] | to_entries[] | .value + {journal_unconfirmed_events:(if .key==0 then 0 else 2 end)}' <<< "$sample" |
    bash "$coverage" | jq -e '.journal_tail_unconfirmed_events==2 and .journal_discontinuities==1
        and .excluded_intervals==1 and .healthy_intervals==1 and .alert_comparable_packets==35' >/dev/null
jq -sc '.[0:2][], (.[-1] + {journal_unconfirmed_events:7})' <<< "$sample" |
    bash "$coverage" --capture-id a --session a-1 | jq -e '.journal_tail_unconfirmed_events==7 and .scope.session_id=="a-1"' >/dev/null
jq -sc '.[0:2][] | del(.journal_unconfirmed_events)' <<< "$sample" |
    bash "$coverage" | jq -e '.journal_tail_unconfirmed_events==null and .healthy_intervals==1
        and .alert_journal_counter_unverified_intervals==1 and .alert_comparable_intervals==0
        and .observed_openings_per_10000_packets==null' >/dev/null

jq -sc '
    {alert_id:5,rule_id:"dns.competing_responders",revision:7} as $dns |
    {alert_id:6,rule_id:"http.unauthorized_burst",revision:13} as $http |
    .[1], (.[2] | .recent_alerts=[$dns] | .review_queue=[$dns,$http]),
    (.[3] | .recent_alerts=[{alert_id:8,rule_id:"dns.changed_answers",revision:10}])
' <<< "$sample" | bash "$coverage" | jq -e '
    .observed_openings == 2 and .opening_rule_breakdown == {
      rules:[{rule_id:"dns.competing_responders",revision:7,openings:1},{rule_id:"http.unauthorized_burst",revision:13,openings:1}],
      unattributed_openings:0,omitted_rule_openings:0}' >/dev/null
jq -sc '
    .[1], (.[2] | .recent_alerts=[{alert_id:5,rule_id:"dns.competing_responders",revision:7},
      {alert_id:6,rule_id:"http.unauthorized_burst"}] | .review_queue=[{alert_id:5,rule_id:"dns.competing_responders",revision:8}])
' <<< "$sample" | bash "$coverage" | jq -e '
    .observed_openings == 2 and .opening_rule_breakdown == {rules:[],unattributed_openings:2,omitted_rule_openings:0}' >/dev/null
jq -sc '
    .[0] as $base | range(0;67) as $i
    | $base + {updated_at:(1700000000 + $i | todateiso8601),packets:(10+$i),journal_sequence:($i+1),
       highest_observed_alert_id:(4+$i),alert_changes:{newly_observed:[4+$i]},
       recent_alerts:[{alert_id:(4+$i),rule_id:("rule."+($i|tostring)),revision:1}]}
' <<< "$sample" | bash "$coverage" | jq -e '
    .observed_openings == 66 and (.opening_rule_breakdown |
      (.rules | length) == 64 and .unattributed_openings == 0 and .omitted_rule_openings == 2)' >/dev/null

# Same-scope samples with a new healthy epoch or backwards timestamps are not joined.
for patch in '.healthy_capture_since+=1' '.updated_at="2023-11-14T22:12:59Z"' \
    '.capture_queue_full_packets+=1' '.truncated_frames+=1' 'del(.capture_queue_full_packets)' \
    '.truncated_frames="0"' '.link_decodable=false' 'del(.link_decodable)'; do
    jq -sc ".[0], (.[1] | $patch)" <<< "$sample" |
        bash "$coverage" | jq -e '.status=="insufficient_coverage" and .excluded_intervals==1' >/dev/null
done
for patch in '.alert_log_advanced_during_review=true' 'del(.alert_log_advanced_during_review)' \
    '.alert_log_advanced_during_review="false"'; do
    jq -sc ".[0],(.[1] | $patch),.[2]" <<< "$sample" | bash "$coverage" | jq -e '
        .healthy_intervals==2 and .healthy_packets==60 and .alert_log_snapshot_unverified_intervals==2
        and .alert_comparable_intervals==0 and .observed_openings==null' >/dev/null
    jq -sc "(.[0] | $patch),.[1],.[2]" <<< "$sample" | bash "$coverage" | jq -e '
        .healthy_intervals==2 and .alert_log_snapshot_unverified_intervals==1
        and .alert_comparable_intervals==1 and .alert_comparable_packets==35 and .observed_openings==2' >/dev/null
done
for patch in '.alert_saving=false' 'del(.alert_saving)' 'del(.alert_log_integrity)' \
    '.alert_log_integrity.invalid_records=1' '.alert_log_integrity.oversized_records=1' \
    '.alert_log_integrity.stopped_at_scan_budget=true'; do
    jq -sc "(.[0] | $patch), .[1], .[2]" <<< "$sample" |
        bash "$coverage" | jq -e '.healthy_intervals==2 and .alert_comparable_intervals==1
            and .alert_comparable_packets==35 and .observed_openings==2' >/dev/null
    jq -sc ".[0], (.[1] | $patch)" <<< "$sample" |
        bash "$coverage" | jq -e '.healthy_intervals==1 and .alert_comparable_intervals==0
            and .observed_openings==null' >/dev/null
done
jq -sc '.[0], ((.[1],.[2]) | .alert_save_failures=1)' <<< "$sample" |
    bash "$coverage" | jq -e '.healthy_intervals==2 and .alert_save_failure_intervals==1
        and .alert_save_counter_unverified_intervals==0 and .alert_comparable_intervals==1
        and .alert_comparable_packets==35 and .observed_openings==2' >/dev/null
jq -sc '.[0], ((.[1],.[2]) | .alert_save_backlog_dropped=1)' <<< "$sample" |
    bash "$coverage" | jq -e '.healthy_intervals==2 and .alert_save_backlog_drop_intervals==1 and .alert_save_failure_intervals==0
        and .alert_save_backlog_unverified_intervals==0 and .alert_comparable_intervals==1
        and .alert_comparable_packets==35 and .observed_openings==2' >/dev/null
for patch in 'del(.alert_save_backlog_dropped)' '.alert_save_backlog_dropped=-1' '.alert_save_backlog_dropped=1'; do
    jq -sc "(.[0] | $patch), .[1]" <<< "$sample" |
        bash "$coverage" | jq -e '.healthy_intervals==1 and .alert_save_backlog_unverified_intervals==1
            and .alert_save_backlog_drop_intervals==0 and .observed_openings==null' >/dev/null
done
for patch in 'del(.alert_save_failures)' '.alert_save_failures="0"' '.alert_save_failures=1'; do
    jq -sc "(.[0] | $patch), .[1]" <<< "$sample" |
        bash "$coverage" | jq -e '.healthy_intervals==1 and .alert_save_counter_unverified_intervals==1
            and .alert_save_failure_intervals==0 and .observed_openings==null' >/dev/null
done
jq -sc '(.[0],.[1]) | .capture_queue_full_packets = 2' <<< "$sample" | bash "$coverage" |
    jq -e '.healthy_intervals==1 and .alert_comparable_packets==25' >/dev/null
jq -sc '(.[0] | .capture_queue_full_packets = 3), (.[1] | .capture_queue_full_packets = 2)' <<< "$sample" |
    bash "$coverage" | jq -e '.excluded_intervals==1 and .observed_openings==null' >/dev/null

# A later valid pair still contributes after a restart, dropped record, or legacy boundary.
for patch in '.journal_writer="writer-b"' '.journal_sequence=9' 'del(.journal_writer,.journal_sequence)' \
    '.journal_sequence="1"' '.journal_sequence=2'; do
    jq -sc "(.[0] | $patch), .[1], .[2]" <<< "$sample" | bash "$coverage" | jq -e '
        .journal_discontinuities==1 and .excluded_intervals==1 and .healthy_intervals==1
        and .healthy_packets==35 and .alert_comparable_packets==35 and .observed_openings==2' >/dev/null
done
jq -c 'del(.journal_writer,.journal_sequence)' <<< "$sample" | bash "$coverage" --capture-id a --session a-1 |
    jq -e '.status=="insufficient_coverage" and .healthy_packets==0 and .observed_openings==null' >/dev/null

# Initial offsets are unknown. Only report holes bounded by observed IDs.
jq -sc '
    (.[0] | .recent_alerts = [{alert_id:2},{alert_id:4}]),
    (.[1] | del(.checkpoint) | .alert_sample_gap = true | .highest_observed_alert_id = 9
          | .alert_changes.newly_observed = [6,9] | .review_queue = [{alert_id:7}])
' <<< "$sample" | bash "$coverage" | jq -e '
    .alert_sample_gap_reported and .observed_openings == null
    and [.unobserved_alert_id_ranges[] | [.first_id,.last_id]] == [[3,3],[5,5],[8,8]]
    and (.unobserved_alert_id_ranges_truncated | not)' >/dev/null
jq -sc '
    .[0], (.[1] | .highest_observed_alert_id = 9007199254740991
        | .alert_changes.newly_observed = [9007199254740991])
' <<< "$sample" | bash "$coverage" | jq -e '
    [.unobserved_alert_id_ranges[] | [.first_id,.last_id]] == [[5,9007199254740990]]' >/dev/null
jq -sc '
    (.[0] | .highest_observed_alert_id = 0),
    (.[1] | .highest_observed_alert_id = 53 | .alert_changes.newly_observed = [51,53])
' <<< "$sample" | bash "$coverage" | jq -e '
    [.unobserved_alert_id_ranges[] | [.first_id,.last_id]] == [[52,52]]' >/dev/null
jq -sc '.[0], (.[1] | .highest_observed_alert_id = 7)' <<< "$sample" |
    bash "$coverage" | jq -e '
        [.unobserved_alert_id_ranges[] | [.first_id,.last_id]] == [[5,6]]' >/dev/null
jq -sc '
    .[0], (.[1] | .highest_observed_alert_id = 9 | .alert_changes.newly_observed = [9] | del(.checkpoint)),
    (.[2] | .highest_observed_alert_id = 9 | .alert_changes.newly_observed = []
        | .review_queue = [{alert_id:6},{alert_id:8}]),
    (.[3] | .capture_id = "another" | .recent_alerts = [{alert_id:5},{alert_id:7}])
' <<< "$sample" | bash "$coverage" --capture-id a --session a-1 | jq -e '
    [.unobserved_alert_id_ranges[] | [.first_id,.last_id,.recorded_at]] ==
        [[5,5,"2023-11-14T22:14:20Z"],[7,7,"2023-11-14T22:14:20Z"]]' >/dev/null
jq -sc '
    .[0], (.[1] | .highest_observed_alert_id = 8 | .alert_changes.newly_observed = [8] | del(.checkpoint)),
    (.[2] | .highest_observed_alert_id = 8 | .alert_changes.newly_observed = []
        | .recent_alerts = [{alert_id:5},{alert_id:6},{alert_id:7}] | .alert_sample_gap = true)
' <<< "$sample" | bash "$coverage" | jq -e '
    .alert_sample_gap_reported and .unobserved_alert_id_ranges == []' >/dev/null
jq -sc '
    .[0] as $base | range(0;66) as $i
    | $base + {highest_observed_alert_id:(4 + $i*2),updated_at:(1700000000 + $i | todateiso8601),
               alert_changes:{newly_observed:[4 + $i*2]}}
' <<< "$sample" | bash "$coverage" | jq -e '
    .unobserved_alert_id_ranges_truncated and (.unobserved_alert_id_ranges | length) == 64
    and [.unobserved_alert_id_ranges[0].first_id,.unobserved_alert_id_ranges[-1].last_id] == [5,131]' >/dev/null
if printf '%s\n' '{incomplete' | bash "$coverage" >/dev/null 2>&1; then exit 1; fi
if head -c 2097153 /dev/zero | tr '\000' 'x' | bash "$coverage" >/dev/null 2>&1; then exit 1; fi
if bash "$coverage" --capture-id a </dev/null >/dev/null 2>&1; then exit 1; fi
printf '%s\n' 'Packrat journal coverage tests passed'
