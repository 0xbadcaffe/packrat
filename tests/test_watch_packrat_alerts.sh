#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
watch="$root/scripts/watch-packrat-alerts.sh"
export PACKRAT_WATCH_MAX_ALERTS=1024
bash -n "$watch"

fixture() {
    printf '%s\n' '{malformed' 'null' '{"schema_version":1,"record_type":"health"}'
    jq -cn '
        def alert($session; $id):
            {
                schema_version: 1, record_type: "alert", session_id: $session,
                alert: {
                    id: $id, source: "IDS", title: "Periodic traffic", severity: "MEDIUM", disposition: "New",
                    detail: "observed\u001b[31m\nnotes", hit_count: 1, last_packet: 41,
                    first_seen: 1700000000.125, last_seen: 1700000000.125,
                    packet_no: 41, packet_refs: [41], bytes: [1, 2, 3], capture_id: "capture-a",
                    provenance: {rule_id:"traffic.periodic",revision:1,confidence:"heuristic",verification_hint:"Inspect the owner"}
                }
            };
        alert("session-a"; 1) as $a |
        ($a | .alert.hit_count = 2 | .alert.packet_no = 42 | .alert.last_packet = 42 | .alert.last_seen = 1700000001.25) as $updated |
        $a, $a, ($a | .alert.last_seen = 1700000000.5),
        $updated,
        ($updated | .alert.disposition = "Benign"),
        ($updated | .alert.disposition = "Benign"),
        alert("session-b"; 1),
        ($a | .alert.capture_id = "capture-b"),
        (alert("session-a"; "bad") | .alert.provenance = ["unexpected"])
    '
}

fixture | bash "$watch" | jq -se '
    length == 5
    and map(.event) == ["first_seen","updated","updated","first_seen","first_seen"]
    and map(.session_id) == ["session-a","session-a","session-a","session-b","session-a"]
    and .[1].hits == 2 and .[1].last_packet == 42
    and .[0].source == "IDS" and .[0].packet_no == 41 and .[1].packet_no == 42
    and .[0].first_seen == 1700000000.125 and .[0].last_seen == .[0].first_seen
    and .[1].first_seen == .[0].first_seen and .[1].last_seen == 1700000001.25
    and .[2].disposition == "Benign"
    and .[0].capture_id == "capture-a"
    and .[4].capture_id == "capture-b"
    and .[0].rule_id == "traffic.periodic" and .[0].confidence == "heuristic"
    and .[0].verify == "Inspect the owner"
    and map(.evidence_frame_count) == [1,2,2,1,1]
    and all(.[]; .record_type == "capture_alert"
        and (has("bytes") or has("packet_refs") or has("evidence_frames_internal") | not))
' >/dev/null

jq -cn '
    {schema_version:1,record_type:"alert",session_id:"123-45",
     alert:{id:7,capture_id:("a"*128),packet_no:0}} as $a |
    ($a | .alert.capture_id += "suffix"),
    ($a | .alert.capture_id = []),
    ($a | .alert.capture_id = "scope\n"),
    ($a | .session_id = "session with spaces"),
    ($a | .alert.id = 0),
    ($a | .alert.id = 9007199254740992),
    $a,
    ($a | del(.alert.capture_id))
' | bash "$watch" | jq -se '
    length == 2 and all(.[]; .event == "first_seen" and .alert_id == 7 and .packet_no == null)
    and .[0].capture_id == ("a" * 128) and .[1].capture_id == null
' >/dev/null

jq -cn '
    {schema_version:1,record_type:"alert",session_id:"test",
     alert:{id:9,first_packet:1,last_packet:4,packet_no:4,packet_refs:[1,2,4],
            first_seen:"now",last_seen:-1}} as $alert |
    $alert,
    ($alert | .alert.packet_refs = [4,2,2,1,0,-1,2.5,null,"15"]),
    ($alert | .alert.packet_refs = [1,3,4]),
    ($alert | .alert.packet_refs = [1,3,4,5]),
    ($alert | .alert.packet_refs = "legacy"),
    ($alert | .alert.detail = ("x" * 1048576))
' | bash "$watch" | jq -se '
    map(.event) == ["first_seen","updated","updated","updated"]
    and map(.evidence_frame_count) == [3,3,4,2]
    and all(.[]; .first_seen == null and .last_seen == null
        and (has("evidence_frames_internal") or has("packet_refs") | not))
' >/dev/null

jq -cn '
    (1,2,3,1) as $id | {schema_version:1,record_type:"alert",session_id:"test",alert:{id:$id}}
' | PACKRAT_WATCH_MAX_ALERTS=2 bash "$watch" | jq -se '
    map(.alert_id) == [1,2,3,1] and all(.[]; .event == "first_seen")
' >/dev/null

status=0
PACKRAT_WATCH_MAX_ALERTS=0 bash "$watch" </dev/null >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]
printf '%s\n' 'Packrat alert watcher tests passed'
