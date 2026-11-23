# shellcheck shell=bash
state="$scratch/checkpoints.json"
live current 100 '[]' '[]' >"$report"
status=0
PACKRAT_TRIAGE_WATCH_CHECKPOINT_INTERVAL=0 bash "$watch" --once "$state" -- cat -- "$report" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

PACKRAT_TRIAGE_WATCH_INTERVAL=1 PACKRAT_TRIAGE_WATCH_CHECKPOINT_INTERVAL=2 \
    bash "$watch" "$state" -- cat -- "$report" >"$scratch/quiet-events" &
watch_pid=$!
await_packets 100
live current 120 '[]' '[]' >"$report.next"
mv -- "$report.next" "$report"
await_packets 120
for _ in {1..100}; do
    if jq -se 'any(.[]; .checkpoint==true and .packets==120)' "$state.events.jsonl" >/dev/null 2>&1; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -se 'length==1 and .[0].packets==100 and .[0].checkpoint==null' "$scratch/quiet-events" >/dev/null
bash "$watch" --history "$state" | jq -se 'length>=2 and .[0].checkpoint==null
    and any(.[]; .checkpoint==true and .packets==120)
    and all(.[1:][]; .checkpoint==true and .alert_changes==null and .capture_id=="a" and .buffer_drops==0)' >/dev/null
jq -e '.status=="current" and .packets==120 and .journal_status=="current" and .journal_pending_events==0' "$state" >/dev/null
