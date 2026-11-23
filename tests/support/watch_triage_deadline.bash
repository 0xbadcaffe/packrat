# shellcheck shell=bash
state="$scratch/held-pipe.json"
live current 200 '[]' '[]' >"$report"
# The command succeeds and emits a valid report, but a helper still owns stdout.
PACKRAT_TRIAGE_WATCH_TIMEOUT=1 bash "$watch" --once "$state" -- bash -c '
    sleep 4 &
    cat -- "$1"
' mock "$report" >/dev/null
jq -e '.status == "triage_timeout" and .packets == null' "$state" >/dev/null
check_status "$state" triage_unhealthy 1
