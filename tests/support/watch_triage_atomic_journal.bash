# shellcheck shell=bash
state="$scratch/atomic-journal.json"
original="$scratch/rotation-output"
install -m 0600 "$original" "$state.events.jsonl"
export TEST_STAGING_FAILURE="$scratch/fail-journal-stage"
touch -- "$TEST_STAGING_FAILURE"
# shellcheck disable=SC2329
cp() {
    command cp "$@" || return
    if [[ ${*: -1} == */.packrat-journal.* && -e $TEST_STAGING_FAILURE ]]; then
        printf '%s' '{"partial":' >>"${*: -1}"
        return 1
    fi
}
export -f cp
live current 120 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/atomic-output" 2>"$scratch/atomic-errors" &
watch_pid=$!
await_packets 120
jq -e '.journal_status=="write_failed" and .journal_pending_events==1' "$state" >/dev/null
cmp -s "$original" "$state.events.jsonl"
rm -- "$TEST_STAGING_FAILURE"
for _ in {1..80}; do
    if jq -e '.journal_status=="current" and .journal_pending_events==0' "$state" >/dev/null; then break; fi
    sleep 0.1
done
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
unset -f cp
jq -e '.journal_status=="current" and .journal_pending_events==0' "$state" >/dev/null
bash "$watch" --history "$state" | jq -se 'map(.packets)==[90,120]' >/dev/null

state="$scratch/torn-journal.json"
install -m 0600 "$original" "$state.events.jsonl"
printf '%s' '{"partial":' >>"$state.events.jsonl"
command cp -- "$state.events.jsonl" "$scratch/torn-original"
live current 121 '[]' >"$report"
PACKRAT_TRIAGE_WATCH_INTERVAL=1 bash "$watch" "$state" -- cat -- "$report" >"$scratch/torn-output" 2>"$scratch/torn-errors" &
watch_pid=$!
await_packets 121
kill "$watch_pid"
wait "$watch_pid"
watch_pid=''
jq -e '.journal_status=="write_failed" and .journal_pending_events==1' "$state" >/dev/null
cmp -s "$scratch/torn-original" "$state.events.jsonl"
