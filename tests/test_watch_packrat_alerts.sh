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
                    id: $id, title: "Periodic traffic", severity: "MEDIUM", disposition: "New",
                    detail: "observed\u001b[31m\nnotes", hit_count: 1, last_packet: 41, last_seen: 1,
                    packet_refs: [41], bytes: [1, 2, 3], capture_id: "capture-a",
                    provenance: {rule_id:"traffic.periodic",revision:1,confidence:"heuristic",verification_hint:"Inspect the owner"}
                }
            };
        alert("session-a"; 1) as $a |
        $a, $a, ($a | .alert.last_seen = 2),
        ($a | .alert.hit_count = 2 | .alert.last_packet = 42),
        ($a | .alert.hit_count = 2 | .alert.last_packet = 42 | .alert.disposition = "Benign"),
        ($a | .alert.hit_count = 2 | .alert.last_packet = 42 | .alert.disposition = "Benign"),
        alert("session-b"; 1),
        (alert("session-a"; "bad") | .alert.provenance = ["unexpected"])
    '
}

fixture | bash "$watch" | jq -se '
    length == 4
    and map(.event) == ["first_seen","updated","updated","first_seen"]
    and map(.session_id) == ["session-a","session-a","session-a","session-b"]
    and .[1].hits == 2 and .[1].last_packet == 42
    and .[2].disposition == "Benign"
    and .[0].capture_id == "capture-a"
    and .[0].rule_id == "traffic.periodic" and .[0].confidence == "heuristic"
    and .[0].verify == "Inspect the owner"
    and all(.[]; .record_type == "capture_alert" and (has("bytes") or has("packet_refs") | not))
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
