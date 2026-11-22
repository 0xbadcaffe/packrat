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
live() {
    jq -cn --arg status "$1" --argjson packets "$2" --argjson queue "$3" --argjson alerts "${4-[]}" '{
        record_type:"capture_triage", status:$status,
        health:{capture_id:"a", alert_session_id:"1-2", capture_interface:"wlan1", issues:[],
            packets_total:$packets, pcap_buffer_drops:0, alert_saving:true},
        live_packet_archive:"enabled", open_priority_alerts_in_sample:($queue | length),
        priority_sample_at_limit:false, has_more_alerts:($alerts | length > 50),
        review_queue:($queue | map(. + {title:"private detail", bytes:[1,2], verify:"private advice"})),
        alerts:($alerts | map(. + {detail:"private payload", flow:{src:"10.2.3.4"}, last_seen:$packets}))
    }'
}
queue='[{"alert_id":7,"severity":"HIGH","rule_id":"test.rule","confidence":"correlated","packet_evidence_status":"partial","next_evidence_step":"inspect_retained_and_recover_missing_frames"}]'
medium='[{"alert_id":9,"severity":"MEDIUM","rule_id":"test.medium","disposition":"New","hit_count":1}]'
live current 12 "$queue" "$medium" >"$report"
bash "$watch" --once "$state" -- bash -c 'cat -- "$1"; exit 1' mock "$report" >"$scratch/output"
cmp -s "$state" "$scratch/output"
[[ $(stat --format='%a' "$state") == 600 ]]
jq -e '.status=="current" and .packets==12 and .review_queue[0].alert_id==7
    and .review_queue[0].packet_evidence_status=="partial"
    and .recent_alerts==[{alert_id:9,severity:"MEDIUM",rule_id:"test.medium",disposition:"New",hit_count:1}]
    and .recent_alerts_at_limit==false and .has_older_alerts==false
    and (.updated_at | fromdateiso8601) > 0
    and (tostring | contains("private") | not)' "$state" >/dev/null

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
if bash "$watch" --once "$state" -- true >/dev/null 2>&1; then exit 1; fi
live current 31 '[]' >"$report.next"
mv -- "$report.next" "$report"
await_packets 31
live current 32 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 32
live current 33 '[]' "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 33
live current 34 '[]' "$(jq -c '.[0].hit_count=2' <<<"$medium")" >"$report.next"
mv -- "$report.next" "$report"
await_packets 34
live degraded 35 "$queue" "$medium" >"$report.next"
mv -- "$report.next" "$report"
await_packets 35
for _ in {1..80}; do
    if jq -se 'length == 4' "$scratch/events" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -se 'map(.packets)==[30,32,34,35] and .[1].recent_alerts[0].alert_id==9
    and .[2].recent_alerts[0].hit_count==2 and .[3].review_queue[0].alert_id==7' "$scratch/events" >/dev/null
printf '%s\n' 'Packrat triage watcher tests passed'
