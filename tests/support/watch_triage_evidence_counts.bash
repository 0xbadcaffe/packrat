# shellcheck shell=bash
state="$scratch/evidence-counts.json"
evidence_sample() {
    live current "$1" '[]' "$medium" | jq --argjson counts "$2" '
        .alerts[0] += {packet_evidence_status:"partial",evidence_frame_count:3,
            evidence_frame_set_sha256:("a"*64),evidence_availability:$counts}'
}
evidence_sample 110 '{"complete":2,"missing":1}' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/evidence-events" &
watch_pid=$!
await_packets 110
evidence_sample 111 '{"complete":1,"missing":2}' >"$report.next"
mv -- "$report.next" "$report"; await_packets 111
jq -e '.recent_alerts[0].evidence_availability == {complete:1,missing:2}' "$state" >/dev/null
evidence_sample 112 '{"complete":1,"missing":1,"private_data":1}' >"$report.next"
mv -- "$report.next" "$report"; await_packets 112
jq -e '.recent_alerts[0] | has("evidence_availability") | not' "$state" >/dev/null
evidence_sample 113 '{"complete":1,"missing":1}' >"$report.next"
mv -- "$report.next" "$report"; await_packets 113
jq -e '.recent_alerts[0] | has("evidence_availability") | not' "$state" >/dev/null
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
bash "$watch" --history "$state" | jq -se '
    map(.packets) == [110,111,112]
    and .[1].alert_changes.updated == [{alert_id:9,fields:["evidence_availability"]}]
    and .[1].alert_changes.newly_observed == []
    and .[1].recent_alerts[0].evidence_availability == {complete:1,missing:2}
    and .[2].alert_changes.updated == []
    and (tostring | contains("private_data") | not)' >/dev/null
