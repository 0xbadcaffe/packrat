#!/usr/bin/env bash
set -euo pipefail

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
            capture_link_type:1, capture_link_decodable:true, disk_free_mib:2048},
        live_packet_archive:"enabled", open_priority_alerts_in_sample:($queue | length),
        priority_sample_at_limit:false, has_more_alerts:($alerts | length > 50),
        alert_log_integrity:{invalid_records:0,oversized_records:0,stopped_at_limit:false,detail:"private context"},
        evidence_status:{alert_id:9,status:"checked",frames:[{bytes:"private payload"}]},
        review_queue:($queue | map(. + {title:"private detail", bytes:[1,2], verify:"private advice"})),
        alerts:($alerts | map(. + {detail:"private payload", flow:{src:"10.2.3.4"}, last_seen:$packets}))
    }'
}
queue='[{"alert_id":7,"severity":"HIGH","rule_id":"test.rule","confidence":"correlated","packet_evidence_status":"partial","next_evidence_step":"inspect_retained_and_recover_missing_frames"}]'
medium='[{"alert_id":9,"severity":"MEDIUM","rule_id":"test.medium","disposition":"New","hit_count":1,"packet_evidence_status":"partial"}]'
live current 12 "$queue" "$medium" >"$report"
bash "$watch" --once "$state" -- bash -c 'cat -- "$1"; exit 1' mock "$report" >"$scratch/output"
cmp -s "$state" "$scratch/output"
check_status "$state" current 0
[[ $(stat --format='%a' "$state") == 600 ]]
jq -e '.status=="current" and .packets==12 and .review_queue[0].alert_id==7
    and .link_type==1 and .link_decodable and .truncated_frames==0 and .disk_free_mib==2048
    and .review_queue[0].packet_evidence_status=="partial"
    and .evidence_check=={alert_id:9,status:"checked"}
    and .recent_alerts==[{alert_id:9,severity:"MEDIUM",rule_id:"test.medium",disposition:"New",hit_count:1,packet_evidence_status:"partial"}]
    and .recent_alerts_at_limit==false and .has_older_alerts==false
    and .max_age_seconds==62
    and (.updated_at | fromdateiso8601) > 0
    and (tostring | contains("private") | not)' "$state" >/dev/null
jq '.updated_at=(now - 120 | todateiso8601)' "$state" >"$scratch/stale.json"
check_status "$scratch/stale.json" snapshot_stale 1
jq '.updated_at=(now + 120 | todateiso8601)' "$state" >"$scratch/future.json"
check_status "$scratch/future.json" snapshot_future 1
jq '.updated_at="invalid"' "$state" >"$scratch/invalid.json"
check_status "$scratch/invalid.json" snapshot_invalid 2

(
    # shellcheck source=scripts/packrat-rollout.sh
    source "$root/scripts/packrat-rollout.sh"
    scope='{"capture_id":"a","alert_session_id":"1-2"}'
    triage_check=$watch
    triage_state=
    triage_watcher_ready "$scope"
    triage_state=$state
    triage_watcher_ready "$scope"
    if triage_watcher_ready '{"capture_id":"old","alert_session_id":"1-2"}'; then exit 1; fi
    if triage_watcher_ready '{"capture_id":"a","alert_session_id":"other"}'; then exit 1; fi
    triage_state="$scratch/stale.json"
    if triage_watcher_ready "$scope"; then exit 1; fi
    triage_state="$scratch/missing.json"
    if triage_watcher_ready "$scope"; then exit 1; fi
)

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
live current 30 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/events" &
watch_pid=$!
await_packets 30
check_status "$state" current 0
if bash "$watch" --once "$state" -- true >/dev/null 2>&1; then exit 1; fi
live current 31 '[]' | jq '.health.disk_free_mib=2047' >"$report.next"
mv -- "$report.next" "$report"
await_packets 31
live current 32 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 32
live current 33 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 33
medium=$(jq -c '.[0].hit_count=2' <<<"$medium")
live current 34 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 34
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
jq '.health.packets_total=38 | .health.capture_truncated_frames=3' "$report" >"$report.next"
mv -- "$report.next" "$report"
await_packets 38
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
    and .[4].buffer_drops==1 and .[5].alert_log_integrity=={
        invalid_records:2,oversized_records:0,stopped_at_limit:false,stopped_at_scan_budget:true}
    and .[6].truncated_frames==3 and .[7].archive_pause_reason=="disk_reserve"
    and .[0].alert_changes==null and .[1].alert_changes.newly_observed==[9]
    and .[2].alert_changes.updated==[{alert_id:9,fields:["hit_count"]}]
    and .[8].alert_changes.updated==[{alert_id:9,fields:["disposition","packet_evidence_status"]}]
    and .[9].highest_observed_alert_id==9 and .[10].alert_changes.newly_observed==[]
    and .[11].highest_observed_alert_id==12 and .[11].alert_changes==null' "$scratch/events" >/dev/null

jq '.updated_at=(now - 360 | todateiso8601) | .capture_id="a" | .highest_observed_alert_id=99' "$state" >"$scratch/stale.next"
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
jq -e '.highest_observed_alert_id==12 and (has("alert_changes") | not)' "$state" >/dev/null
printf '%s\n' 'Packrat triage watcher tests passed'
