# shellcheck shell=bash
state="$scratch/counter-gap.json"
live current 100 '[]' '[]' >"$report"
bash "$watch" --once "$state" -- cat -- "$report" >/dev/null
bash "$watch" --check "$state" | jq -e '.status=="current" and .packets==100 and .packet_counter_gap==false' >/dev/null

# A failed poll must not discard the last comparable packet count.
bash "$watch" --once "$state" -- printf '%s\n' 'unavailable' >/dev/null
live current 99 '[]' '[]' >"$report"
bash "$watch" --once "$state" -- cat -- "$report" >/dev/null
check_status "$state" packet_counter_regressed 1
jq -e '.packet_counter_regressed and .packet_counter_gap and .healthy_capture_since==null' "$state" >/dev/null

# Resuming normally starts a fresh healthy interval without erasing the gap.
bash "$watch" --once "$state" -- cat -- "$report" >/dev/null
bash "$watch" --check "$state" |
    jq -e '.status=="current" and .packet_counter_gap and .packets==99 and .healthy_capture_seconds>=0' >/dev/null
jq -e '.packet_counter_regressed==false and .healthy_capture_since==.poll_started_at' "$state" >/dev/null

live current 1 '[]' '[]' | jq '.health.capture_id="new-capture"' >"$report"
bash "$watch" --once "$state" -- cat -- "$report" >/dev/null
bash "$watch" --check "$state" | jq -e '.status=="current" and .packet_counter_gap==false and .packets==1' >/dev/null
