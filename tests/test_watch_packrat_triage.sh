#!/usr/bin/env bash
# Each watcher PID is captured in the shell that launches it, not a sourced subshell.
# shellcheck disable=SC2031
set -euo pipefail
unset PACKRAT_TRIAGE_WATCH_CHECKPOINT_INTERVAL
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
watch="$root/scripts/watch-packrat-triage.sh"
scratch=$(mktemp -d)
watch_pid=''
cleanup() {
    if [[ -n $watch_pid ]]; then
        kill "$watch_pid" 2>/dev/null || :
        wait "$watch_pid" 2>/dev/null || :
    fi
    rm -rf -- "$scratch"
}
trap cleanup EXIT
state="$scratch/latest.json"
report="$scratch/report.json"
check_status() {
    local file=$1 expected_status=$2 expected_code=$3 response rc=0
    response=$(bash "$watch" --check "$file") || rc=$?
    [[ $rc == "$expected_code" ]]
    jq -e --arg status "$expected_status" '.status==$status' <<< "$response" >/dev/null
}
check_status "$state" snapshot_missing 2
live() {
    jq -cn --arg status "$1" --argjson packets "$2" --argjson queue "$3" --argjson alerts "${4-[]}" '{
        record_type:"capture_triage", status:$status,
        health:{capture_id:"a", alert_session_id:"1-2", capture_interface:"wlan1", issues:[],
            packets_total:$packets, pcap_buffer_drops:0, alert_saving:true, capture_truncated_frames:0,
            capture_queue_full_packets:8,capture_queue_full_packets_delta:3, flow_cache:{retained_summaries:8192,summary_evictions:4,extra:"private"},
            capture_link_type:1, capture_link_decodable:true, disk_free_mib:2048,
            archive_enabled:true,archive_alert_evidence_only:true,
            archive_evidence_rules:["traffic.periodic_fixed_size"],
            archive_usage:{frames:1,max_frames:100,payload_bytes:1024,max_payload_bytes:65536},
            archive_path:"private archive path"},
        live_packet_archive:"enabled", open_priority_alerts_in_sample:($queue | length),
        open_archive_rule_alerts_in_sample:0, review_queue_truncated:false,
        priority_sample_at_limit:false, has_more_alerts:($alerts | length > 50),
        alert_log_integrity:{invalid_records:0,oversized_records:0,stopped_at_limit:false,detail:"private context"},
        evidence_status:{alert_id:9,status:"checked",frames:[{bytes:"private payload"}]},
        evidence_checks:[{alert_id:9,status:"checked",frames:[{bytes:"private payload"}]}],
        review_queue:($queue | map(. + {title:"private detail", bytes:[1,2], verify:"private advice"})),
        alerts:($alerts | map(. + {detail:"private payload", flow:{src:"10.2.3.4"}, last_seen:$packets}))
    }'
}
queue='[{"alert_id":7,"severity":"HIGH","rule_id":"test.rule","revision":10,"confidence":"correlated","packet_evidence_status":"partial","next_evidence_step":"inspect_retained_and_recover_missing_frames"}]'
medium='[{"alert_id":9,"severity":"MEDIUM","rule_id":"test.medium","revision":65536,"disposition":"New","hit_count":1,"packet_evidence_status":"partial","evidence_frame_count":2,"evidence_frame_set_sha256":"invalid"}]'
live current 12 "$queue" "$medium" >"$report"
bash "$watch" --once "$state" -- bash -c 'cat -- "$1"; exit 1' mock "$report" >"$scratch/output"
cmp -s "$state" "$scratch/output"
bash "$watch" --check "$state" | jq -e '.status=="current" and (.healthy_capture_seconds | type=="number" and .>=0) and .flow_cache=={retained_summaries:8192,summary_evictions:4}' >/dev/null
[[ $(stat --format='%a' "$state") == 600 ]]
jq -e '.status=="current" and .packets==12 and .review_queue[0].alert_id==7
    and .journal_status=="not_checked" and .journal_pending_events==0
    and .link_type==1 and .link_decodable and .truncated_frames==0 and .disk_free_mib==2048
    and .capture_queue_full_packets==8 and .capture_queue_full_packets_delta==3 and .flow_cache=={retained_summaries:8192,summary_evictions:4}
    and .review_queue[0].packet_evidence_status=="partial" and .review_queue[0].revision==10
    and .archive_mode=="alert_evidence" and .archive_rule_ids==["traffic.periodic_fixed_size"]
    and .archive_usage=={frames:1,max_frames:100,payload_bytes:1024,max_payload_bytes:65536}
    and .archive_near_limit==false
    and .evidence_check=={alert_id:9,status:"checked"}
    and .evidence_checks==[{alert_id:9,status:"checked"}]
    and .recent_alerts==[{alert_id:9,severity:"MEDIUM",rule_id:"test.medium",disposition:"New",hit_count:1,packet_evidence_status:"partial"}]
    and .recent_alerts_at_limit==false and .has_older_alerts==false
    and .max_age_seconds==62
    and .healthy_capture_since==.poll_started_at and .poll_started_at > 0 and .poll_started_at <= (.updated_at | fromdateiso8601)
    and (tostring | contains("private") | not)' "$state" >/dev/null
jq '.updated_at=(now - 120 | todateiso8601)' "$state" >"$scratch/stale.json"
check_status "$scratch/stale.json" snapshot_stale 1
jq '.updated_at=(now + 120 | todateiso8601)' "$state" >"$scratch/future.json"
check_status "$scratch/future.json" snapshot_future 1
jq '.updated_at="invalid"' "$state" >"$scratch/invalid.json"
check_status "$scratch/invalid.json" snapshot_invalid 2
jq '.status="degraded" | .issues=["pcap_buffer_drops"] | .buffer_drops=100 | .buffer_drops_delta=0' \
    "$state" >"$scratch/historical.json"
check_status "$scratch/historical.json" triage_unhealthy 1
{ bash "$watch" --check "$scratch/historical.json" || [[ $? == 1 ]]; } |
    jq -e '.historical_drop_total==100' >/dev/null
for change in '.buffer_drops_delta=1' 'del(.buffer_drops_delta)' '.issues+=["capture_queue_high"]' \
    '.alert_log_integrity.invalid_records=1' '.alert_saving=false' '.updated_at=(now - 120 | todateiso8601)'; do
    jq "$change" "$scratch/historical.json" >"$scratch/not-historical.json"
    { bash "$watch" --check "$scratch/not-historical.json" || [[ $? == 1 ]]; } |
        jq -e '.historical_drop_total==null' >/dev/null
done
for change in 'del(.capture_id)' '.session_id="bad session"' '.recent_alerts=null' '.alert_saving=false' 'del(.packets)' \
    '.issues=["capture_stalled"]' '.alert_log_integrity.invalid_records=1' '.alert_log_integrity.stopped_at_scan_budget=true'; do
    jq "$change" "$state" >"$scratch/invalid.json"
    check_status "$scratch/invalid.json" snapshot_invalid 2
done
mixed_queue=$(jq -c '. + [.[0] + {alert_id:8,severity:"MEDIUM",archive_rule:true},
    .[0] + {alert_id:9,severity:"MEDIUM",archive_rule:false}] | .[1].in_recent_alerts=false' <<<"$queue")
live current 13 "$mixed_queue" "$medium" | jq '
    .open_archive_rule_alerts_in_sample=4 | .review_queue_truncated=true' >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '(.review_queue | map(.alert_id))==[7,8] and .review_queue[1].archive_rule
    and .review_queue[1].severity=="MEDIUM" and .review_queue[1].in_recent_alerts==false
    and .open_archive_rule_alerts==4 and .review_queue_truncated
    and (tostring | contains("private") | not)' "$state" >/dev/null
live current 14 '[]' | jq '.health.archive_evidence_rules=["unsafe data"] | .health.flow_cache.summary_evictions=0.25
    | .health.archive_usage.frames=90' >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.archive_rule_ids==null and .archive_near_limit and .archive_usage.frames==90 and .flow_cache==null' "$state" >/dev/null
(
    # shellcheck source=scripts/packrat-rollout.sh
    source "$root/scripts/packrat-rollout.sh"
    scope='{"capture_id":"a","capture_run_id":"run-a","alert_session_id":"1-2"}'
    curl() { jq -c '. + {service:"packrat",status:"ok",telemetry_fresh:true,capture_active:true,packets_total:14}' <<< "$scope"; }
    triage_check=$watch
    triage_state=
    triage_watcher_ready "$scope"
    triage_state=$state
    triage_watcher_ready "$scope"
    triage_journal_required=1
    if triage_watcher_ready "$scope"; then exit 1; fi
    triage_state="$scratch/journal-ready.json"
    jq '.journal_status="current" | .journal_pending_events=0' "$state" >"$triage_state"
    triage_watcher_ready "$scope"
    jq '.journal_status="write_failed" | .journal_pending_events=1' "$state" >"$triage_state"
    if triage_watcher_ready "$scope"; then exit 1; fi
    jq '.journal_status="current" | .journal_pending_events=1' "$state" >"$triage_state"
    if triage_watcher_ready "$scope"; then exit 1; fi
    triage_journal_required=0
    triage_state=$state
    if triage_watcher_ready '{"capture_id":"old","alert_session_id":"1-2"}'; then exit 1; fi
    if triage_watcher_ready '{"capture_id":"a","alert_session_id":"other"}'; then exit 1; fi
    triage_state="$scratch/stale.json"
    if triage_watcher_ready "$scope"; then exit 1; fi
    triage_state="$scratch/missing.json"
    if triage_watcher_ready "$scope"; then exit 1; fi
)
for change in 'del(.health.capture_id)' '.health.alert_session_id="bad session"' '.alerts=null' 'del(.health.packets_total)' \
    '.health.alert_saving=false' '.health.issues=[null]' '.alert_log_integrity.invalid_records=1'; do
    live current 12 '[]' "$medium" | jq "$change" >"$report"
    bash "$watch" --once "$state" -- cat "$report" >/dev/null
    jq -e '.status=="triage_unavailable"' "$state" >/dev/null
    check_status "$state" triage_unhealthy 1
done
many=$(jq -cn '[range(1; 52) | {alert_id:.,severity:"LOW",rule_id:"bad token",disposition:"unknown"}]')
live current 12 '[]' "$many" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.recent_alerts_at_limit and .has_older_alerts and (.recent_alerts | length)==50
    and .recent_alerts[-1].alert_id==50 and .recent_alerts[0].rule_id==null
    and .recent_alerts[0].disposition==null' "$state" >/dev/null

bash "$watch" --once "$state" -- printf '%s\n' 'private, not JSON' >/dev/null
jq -e '.status=="triage_unavailable" and (tostring | contains("private") | not)' "$state" >/dev/null
PACKRAT_TRIAGE_WATCH_TIMEOUT=1 bash "$watch" --once "$state" -- sleep 5 >/dev/null
jq -e '.status=="triage_timeout"' "$state" >/dev/null
check_status "$state" triage_unhealthy 1
mkdir -m 0755 "$scratch/public"
if bash "$watch" --once "$scratch/public/state" -- true >/dev/null 2>&1; then exit 1; fi
ln -s "$state" "$scratch/alias"
if bash "$watch" --once "$scratch/alias" -- true >/dev/null 2>&1; then exit 1; fi
await_packets() {
    local packets=$1
    for _ in {1..80}; do
        if jq -e --argjson packets "$packets" '.packets == $packets' "$state" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    return 1
}
state="$scratch/events-latest.json"
live current 30 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/events" &
watch_pid=$!
await_packets 30
check_status "$state" current 0
if bash "$watch" --once "$state" -- true >/dev/null 2>&1; then exit 1; fi
live current 31 '[]' | jq '.health.disk_free_mib=2047 | .health.archive_usage.frames=2' >"$report.next"
mv -- "$report.next" "$report"
await_packets 31
medium=$(jq -c '.[0] += {revision:9,evidence_frame_set_sha256:("a"*64)}' <<<"$medium")
live current 32 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"; await_packets 32
live current 33 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"; await_packets 33
medium=$(jq -c '.[0] += {hit_count:2,revision:10}' <<<"$medium")
live current 34 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"; await_packets 34
live degraded 35 "$queue" "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 35
live degraded 36 "$queue" "$medium" | jq '.health.pcap_buffer_drops=1' >"$report.next"
mv -- "$report.next" "$report"
await_packets 36
live degraded 37 "$queue" "$medium" |
    jq '.health.pcap_buffer_drops=1 | .alert_log_integrity.invalid_records=2 | .alert_log_integrity.stopped_at_scan_budget=true' >"$report.next"
mv -- "$report.next" "$report"
await_packets 37
check_status "$state" triage_unhealthy 1
jq '.health.packets_total=38 | .health.capture_truncated_frames=3 | .alerts[0].evidence_frame_set_sha256=("b"*64)' "$report" >"$report.next"
mv -- "$report.next" "$report"; await_packets 38
jq '.health.packets_total=39 | .health.archive_pause_reason="disk_reserve" | .live_packet_archive="paused"' "$report" >"$report.next"
mv -- "$report.next" "$report"
await_packets 39
jq '.health.packets_total=40 | .alerts[0].disposition="Reviewing" | .alerts[0].packet_evidence_status="complete"' "$report" >"$report.next"
mv -- "$report.next" "$report"
await_packets 40
jq '.health.packets_total=41 | .alerts[0].alert_id=2' "$report" >"$report.next"
mv -- "$report.next" "$report"
await_packets 41
jq '.health.packets_total=42 | .alerts[0].alert_id=9' "$report" >"$report.next"
mv -- "$report.next" "$report"
await_packets 42
jq '.health.packets_total=43 | .health.capture_id="b" | .alerts[0].alert_id=12' "$report" >"$report.next"
mv -- "$report.next" "$report"
await_packets 43
for _ in {1..80}; do
    if jq -se 'length == 12' "$scratch/events" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -se 'map(.packets)==[30,32,34,35,36,37,38,39,40,41,42,43] and .[1].recent_alerts[0].alert_id==9
    and .[2].recent_alerts[0].hit_count==2 and .[3].review_queue[0].alert_id==7
    and .[0].healthy_capture_since==.[2].healthy_capture_since and .[3].healthy_capture_since==null
    and .[0].buffer_drops_delta==null and .[1].buffer_drops_delta==0
    and .[4].buffer_drops==1 and .[4].buffer_drops_delta==1 and .[5].buffer_drops_delta==0
    and .[11].buffer_drops_delta==null and .[5].alert_log_integrity=={
        invalid_records:2,oversized_records:0,stopped_at_limit:false,stopped_at_scan_budget:true}
    and .[6].truncated_frames==3 and .[7].archive_pause_reason=="disk_reserve"
    and .[0].alert_changes==null and .[1].alert_changes.newly_observed==[9]
    and .[1].recent_alerts[0].revision==9 and .[2].recent_alerts[0].revision==10
    and .[2].alert_changes.updated==[{alert_id:9,fields:["hit_count","revision"]}]
    and .[6].recent_alerts[0].evidence_frame_count==.[5].recent_alerts[0].evidence_frame_count
    and .[6].alert_changes.updated==[{alert_id:9,fields:["evidence"]}] and .[6].alert_changes.newly_observed==[]
    and .[8].alert_changes.updated==[{alert_id:9,fields:["disposition","packet_evidence_status"]}]
    and .[9].highest_observed_alert_id==9 and .[10].alert_changes.newly_observed==[]
    and .[11].highest_observed_alert_id==12 and .[11].alert_changes==null' "$scratch/events" >/dev/null
cmp -s "$scratch/events" "$state.events.jsonl"
[[ $(stat --format='%a' "$state.events.jsonl") == 600 ]]
jq '.updated_at=(now - 360 | todateiso8601) | .capture_id="previous" | .highest_observed_alert_id=99' "$state" >"$scratch/stale.next"
mv -- "$scratch/stale.next" "$state"
live current 60 '[]' "$medium" >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=10 bash "$watch" --supervise "$state" -- cat -- "$report" >"$scratch/supervised" 2>"$scratch/retry" &
watch_pid=$!
await_packets 60
child=$(pgrep -P "$watch_pid" -x bash)
status=0
bash "$watch" --supervise "$state" -- true >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]
live current 61 '[]' "$(jq -c '.[0].hit_count=3 | . + [.[0] + {alert_id:12}]' <<<"$medium")" >"$report.next"
mv -- "$report.next" "$report"
kill -KILL "$child"
await_packets 61
replacement=$(pgrep -P "$watch_pid" -x bash)
[[ $replacement != "$child" ]]
for _ in {1..80}; do
    if jq -se 'length == 2' "$scratch/supervised" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
if kill -0 "$replacement" 2>/dev/null; then exit 1; fi
grep -Fq 'retrying in 2 seconds' "$scratch/retry"
jq -se 'length == 2 and .[0].alert_changes==null and .[0].highest_observed_alert_id==9
    and .[1].highest_observed_alert_id==12 and .[1].alert_changes.newly_observed==[12]
    and .[1].alert_changes.updated==[{alert_id:9,fields:["hit_count"]}]' "$scratch/supervised" >/dev/null
jq -e '.highest_observed_alert_id==12 and .alert_sample_gap and (has("alert_changes") | not)' "$state" >/dev/null

printf '%s\n' 'invalid triage output' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/outage" &
watch_pid=$!
for _ in {1..80}; do
    if jq -e '.status=="triage_unavailable"' "$state" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
jq -e '.status=="triage_unavailable" and .last_observed.highest_observed_alert_id==12
    and (.last_observed.recent_alerts | map(.alert_id))==[9,12]' "$state" >/dev/null
check_status "$state" triage_unhealthy 1
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -se 'length==1 and .[0].status=="triage_unavailable" and (.[0] | has("last_observed") | not)' "$scratch/outage" >/dev/null

live current 62 '[]' "$(jq -c '.[0].hit_count=4 | . + [.[0] + {alert_id:13}]' <<<"$medium")" >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/recovered" &
watch_pid=$!
await_packets 62
bulk=$(jq -cn '[range(65; 13; -1) | {alert_id:.,severity:"LOW",disposition:"New"}]')
live current 63 '[]' "$bulk" >"$report.next"
mv -- "$report.next" "$report"
await_packets 63
jq -e '.alert_sample_gap and .highest_observed_alert_id == 65 and .recent_alerts[0].alert_id == 16' "$state" >/dev/null
live current 64 '[]' "$bulk" >"$report.next"
mv -- "$report.next" "$report"
await_packets 64
jq -e '.alert_sample_gap' "$state" >/dev/null
live current 65 '[]' '[]' | jq '.health.capture_id="c"' >"$report.next"
mv -- "$report.next" "$report"
await_packets 65
for _ in {1..80}; do
    if jq -se 'length==3' "$scratch/recovered" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -se 'length==3 and .[0].highest_observed_alert_id==13 and .[0].alert_sample_gap
    and .[0].alert_changes=={newly_observed:[13],updated:[{alert_id:9,fields:["hit_count"]}],review_queue_entries:[],review_queue_exits:[]}
    and .[1].alert_sample_gap and .[1].alert_changes.newly_observed==[range(16;66)]
    and (.[2].alert_sample_gap | not) and .[2].alert_changes==null' \
    "$scratch/recovered" >/dev/null
jq -e '.status=="current" and .alert_sample_gap==false and .healthy_capture_since==.poll_started_at and (has("last_observed") | not)' "$state" >/dev/null

state="$scratch/one-shot.json"
live current 70 '[]' "$medium" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
live current 71 '[]' "$bulk" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.alert_sample_gap and .highest_observed_alert_id==65' "$state" >/dev/null
bash "$watch" --once "$state" -- printf '%s\n' 'invalid triage output' >/dev/null
jq -e '.status=="triage_unavailable" and .last_observed.alert_sample_gap
    and .last_observed.highest_observed_alert_id==65' "$state" >/dev/null
live current 72 '[]' "$medium" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.status=="current" and .alert_sample_gap and .highest_observed_alert_id==65 and .healthy_capture_since==.poll_started_at' "$state" >/dev/null
state="$scratch/stale-restart.json"
live current 73 '[]' "$medium" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq '.updated_at=(now - 360 | todateiso8601)' "$state" >"$state.next"
mv -- "$state.next" "$state"
{ bash "$watch" --check "$state" || [[ $? == 1 ]]; } | jq -e '.status=="snapshot_stale" and .healthy_capture_seconds==null' >/dev/null
live current 74 '[]' "$bulk" >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/stale-events" &
watch_pid=$!
await_packets 74
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -e '.alert_sample_gap and .highest_observed_alert_id==65 and .buffer_drops_delta==null and .healthy_capture_since==.poll_started_at' "$state" >/dev/null
jq -se 'length==1 and .[0].alert_changes.newly_observed==[range(16;66)]' "$scratch/stale-events" >/dev/null
state="$scratch/bounded-sample.json"
live current 75 '[]' "$bulk" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.alert_sample_gap and .highest_observed_alert_id==65' "$state" >/dev/null

# A new scope starts without a gap when its sample is complete.
live current 76 '[]' "$medium" | jq '.health.capture_id="second"' >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.alert_sample_gap==false and .highest_observed_alert_id==9' "$state" >/dev/null
for newest in 11 13; do
    expected=false
    if [[ $newest == 13 ]]; then expected=true; fi
    # An older alert can remain recent after another hit, despite the omitted records.
    sample=$(jq -c --argjson id "$newest" '. + [.[0] + {alert_id:10}, .[0] + {alert_id:$id}]' <<<"$medium")
    live current 77 '[]' "$sample" | jq '.health.capture_id="second" | .has_more_alerts=true' >"$report"
    bash "$watch" --once "$state" -- cat "$report" >/dev/null
    jq -e --argjson id "$newest" --argjson expected "$expected" '
        .has_older_alerts and .recent_alerts[0].alert_id==9 and
        .highest_observed_alert_id==$id and .alert_sample_gap==$expected' "$state" >/dev/null
done
state="$scratch/queue-updates.json"
backlog=$(jq -c '.[0] as $base | [2,7,8,9,10 | $base + {alert_id:.,in_recent_alerts:(.==9),disposition:"New",hit_count:1}]' <<<"$queue")
live current 80 "$backlog" "$(jq -c '. + [.[0] | . + {alert_id:6,disposition:"Benign"}, . + {alert_id:8}, . + {alert_id:10}]' <<<"$medium")" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
bash "$watch" --once "$state" -- printf '%s\n' 'invalid triage output' >/dev/null
backlog=$(jq -c '[.[0] + {disposition:"Reviewing",hit_count:2}, .[3] + {hit_count:2}, .[0] + {alert_id:6,hit_count:2}, .[0] + {alert_id:11}]' <<<"$backlog")
recent=$(jq -c '. + [.[0] + {alert_id:8,disposition:"Closed"}, .[0] + {alert_id:10,disposition:"Confirmed"}]' <<<"$medium")
live current 81 "$backlog" "$recent" >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/queue-events" &
watch_pid=$!
await_packets 81
for _ in {1..80}; do
    if jq -se 'length==1' "$scratch/queue-events" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -se 'length==1 and (.[0].alert_changes | .updated==
    [{alert_id:2,fields:["hit_count","disposition"]},{alert_id:6,fields:["severity","disposition"]},{alert_id:8,fields:["disposition"]},
     {alert_id:10,fields:["disposition"]}] and .newly_observed==[11]
    and .review_queue_exits==[{alert_id:7,disposition:null,outcome:"not_in_sample"},
     {alert_id:8,disposition:"Closed",outcome:"resolved"},{alert_id:10,disposition:"Confirmed",outcome:"still_in_recent_sample"}]
    and .review_queue_entries==[{alert_id:6,previously_in_recent_sample:true},{alert_id:11,previously_in_recent_sample:false}])
    ' "$scratch/queue-events" >/dev/null
state="$scratch/journal-rotation.json"
journal="$state.events.jsonl"
truncate -s 1048569 "$journal"
printf '\n' >>"$journal"
chmod 0600 "$journal"
live current 90 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/rotation-output" &
watch_pid=$!
await_packets 90
for _ in {1..80}; do
    if [[ -s $journal && -f $journal.1 ]] &&
       jq -se 'length==1 and .[0].packets==90' "$journal" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
[[ $(stat --format='%s' "$journal.1") == 1048570 ]]
cmp -s "$scratch/rotation-output" "$journal"
state="$scratch/journal-unsafe.json"
ln -s "$journal" "$state.events.jsonl"
live current 91 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/unsafe-output" 2>"$scratch/unsafe-errors" &
watch_pid=$!
await_packets 91
jq -e '.journal_status=="write_failed" and .journal_pending_events==1' "$state" >/dev/null
bash "$watch" --check "$state" | jq -e '.status=="current" and .journal_status=="write_failed"
    and .journal_pending_events==1' >/dev/null
for _ in {1..80}; do
    if grep -Fq 'Triage event journal write failed' "$scratch/unsafe-errors"; then break; fi
    sleep 0.1
done
grep -Fq 'Triage event journal write failed' "$scratch/unsafe-errors"
live current 92 '[]' | jq '.live_packet_archive="paused"' >"$report.next"
mv -- "$report.next" "$report"
await_packets 92
jq -e '.journal_status=="write_failed" and .journal_pending_events==2' "$state" >/dev/null
for _ in {1..80}; do
    if jq -se 'map(.packets)==[91,92]' "$scratch/unsafe-output" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
rm -- "$state.events.jsonl"
for _ in {1..80}; do
    if jq -se 'map(.packets)==[91,92]' "$state.events.jsonl" >/dev/null 2>&1 &&
       jq -e '.journal_status=="current" and .journal_pending_events==0' "$state" >/dev/null; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
grep -Fq 'Triage event journal write failed' "$scratch/unsafe-errors"
cmp -s "$scratch/rotation-output" "$journal"
cmp -s "$scratch/unsafe-output" "$state.events.jsonl"
jq -e '.journal_status=="current" and .journal_pending_events==0' "$state" >/dev/null

state="$scratch/journal-loss.json"
ln -s "$journal" "$state.events.jsonl"
live current 100 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/loss-output" 2>"$scratch/loss-errors" &
watch_pid=$!
await_packets 100
for count in {1..16}; do
    packets=$((100 + count))
    live current "$packets" '[]' | jq --argjson count "$count" '.health.capture_truncated_frames=$count' >"$report.next"
    mv -- "$report.next" "$report"
    await_packets "$packets"
done
jq -e '.journal_status=="write_failed" and .journal_pending_events==16
    and .journal_unconfirmed_events==1' "$state" >/dev/null
grep -Fq 'oldest pending event discarded' "$scratch/loss-errors"
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
rm -- "$state.events.jsonl"
live current 117 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/loss-restart" &
watch_pid=$!
await_packets 117
bash "$watch" --check "$state" | jq -e '.journal_status=="current" and .journal_pending_events==0
    and .journal_unconfirmed_events==17' >/dev/null
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
bash "$watch" --once "$state" -- cat -- "$report" | jq -e '.journal_unconfirmed_events==17' >/dev/null
history="$scratch/history.json"
install -m 0600 "$scratch/rotation-output" "$history.events.jsonl.1"
install -m 0600 "$scratch/unsafe-output" "$history.events.jsonl"
bash "$watch" --history "$history" >"$scratch/history-output"
jq -se 'map(.packets)==[90,91,92]' "$scratch/history-output" >/dev/null
# shellcheck disable=SC2329
head() {
    command head "$@" || return
    if [[ ${*: -1} == "$TEST_HISTORY_JOURNAL" ]]; then printf '\n' >>"$TEST_HISTORY_JOURNAL"; fi
}
export -f head
status=0
TEST_HISTORY_JOURNAL="$history.events.jsonl" bash "$watch" --history "$history" \
    >"$scratch/racing-history" 2>/dev/null || status=$?
[[ $status == 1 && ! -s $scratch/racing-history ]]
unset -f head
install -m 0600 "$scratch/unsafe-output" "$history.events.jsonl"
printf '%s\n' invalid >>"$history.events.jsonl"
status=0
bash "$watch" --history "$history" >"$scratch/invalid-history" 2>/dev/null || status=$?
[[ $status == 2 && ! -s $scratch/invalid-history ]]
ln -s "$journal" "$scratch/linked-history.json.events.jsonl"
status=0
bash "$watch" --history "$scratch/linked-history.json" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]
# shellcheck source=tests/support/watch_triage_atomic_journal.bash
source "$root/tests/support/watch_triage_atomic_journal.bash"
# shellcheck source=tests/support/watch_triage_counter_gap.bash
source "$root/tests/support/watch_triage_counter_gap.bash"
# shellcheck source=tests/support/watch_triage_checkpoints.bash
source "$root/tests/support/watch_triage_checkpoints.bash"
# shellcheck source=tests/support/watch_triage_evidence_counts.bash
source "$root/tests/support/watch_triage_evidence_counts.bash"
printf '%s\n' 'Packrat triage watcher tests passed'
