#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
coverage="$root/scripts/packrat-watch-coverage.sh"
sample=$(jq -cn '
    {record_type:"capture_triage_watch",status:"current",capture_id:"a",session_id:"a-1",packets:10,
     updated_at:"2023-11-14T22:13:20Z",healthy_capture_since:1700000000,buffer_drops:0,
     capture_queue_full_packets:0,truncated_frames:0,
     packet_counter_gap:false,alert_sample_gap:false,highest_observed_alert_id:4} as $base
    | $base,
      ($base + {updated_at:"2023-11-14T22:14:20Z",packets:35,checkpoint:true}),
      ($base + {updated_at:"2023-11-14T22:15:20Z",packets:70,highest_observed_alert_id:6,alert_changes:{newly_observed:[5,6]}}),
      ($base + {updated_at:"2023-11-14T22:16:20Z",packets:90,highest_observed_alert_id:8,alert_changes:{newly_observed:[8]}}),
      ({record_type:"capture_triage_watch",status:"triage_unavailable",updated_at:"2023-11-14T22:17:20Z"}),
      ($base + {updated_at:"2023-11-14T22:18:20Z",packets:140,highest_observed_alert_id:8}),
      ($base + {updated_at:"2023-11-14T22:19:20Z",packets:160,highest_observed_alert_id:9,packet_counter_gap:true}),
      ($base + {updated_at:"2023-11-14T22:20:20Z",session_id:"b-2",packets:1,highest_observed_alert_id:0})')

bash "$coverage" --capture-id a --session a-1 <<< "$sample" | jq -e '
    .status=="sampled" and .coverage_policy=="capture_loss_counters_v1" and .scope=={capture_id:"a",session_id:"a-1"}
    and .scoped_records==6 and .healthy_intervals==3 and .excluded_intervals==2
    and .healthy_seconds==180 and .healthy_packets==80 and .alert_comparable_intervals==2
    and .alert_comparable_packets==60 and .observed_openings==2
    and (.observed_openings_per_10000_packets > 333 and .observed_openings_per_10000_packets < 334)' >/dev/null
bash "$coverage" <<< "$sample" | jq -e '.status=="insufficient_coverage" and .scope.session_id=="b-2"
    and .observed_openings==null and .observed_openings_per_10000_packets==null' >/dev/null
bash "$coverage" </dev/null | jq -e '.status=="no_capture_records" and .scope==null' >/dev/null
bash "$coverage" --capture-id missing --session a-1 <<< "$sample" |
    jq -e '.status=="no_capture_records" and .scope.capture_id=="missing"' >/dev/null

# Same-scope samples with a new healthy epoch or backwards timestamps are not joined.
for patch in '.healthy_capture_since+=1' '.updated_at="2023-11-14T22:12:59Z"' \
    '.capture_queue_full_packets+=1' '.truncated_frames+=1' 'del(.capture_queue_full_packets)' '.truncated_frames="0"'; do
    jq -sc ".[0], (.[1] | $patch)" <<< "$sample" |
        bash "$coverage" | jq -e '.status=="insufficient_coverage" and .excluded_intervals==1' >/dev/null
done
jq -sc '(.[0],.[1]) | .capture_queue_full_packets = 2' <<< "$sample" | bash "$coverage" |
    jq -e '.healthy_intervals==1 and .alert_comparable_packets==25' >/dev/null
jq -sc '(.[0] | .capture_queue_full_packets = 3), (.[1] | .capture_queue_full_packets = 2)' <<< "$sample" |
    bash "$coverage" | jq -e '.excluded_intervals==1 and .observed_openings==null' >/dev/null
if printf '%s\n' '{incomplete' | bash "$coverage" >/dev/null 2>&1; then exit 1; fi
if head -c 2097153 /dev/zero | tr '\000' 'x' | bash "$coverage" >/dev/null 2>&1; then exit 1; fi
if bash "$coverage" --capture-id a </dev/null >/dev/null 2>&1; then exit 1; fi
printf '%s\n' 'Packrat journal coverage tests passed'
