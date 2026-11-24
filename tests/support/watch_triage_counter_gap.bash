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

state="$scratch/alert-id-gap.json"
alert_rows() {
    jq -nc --args '[ $ARGS.positional[] | {alert_id:tonumber,severity:"HIGH",disposition:"New"} ]' "$@"
}
live current 101 '[]' "$(alert_rows 51 52)" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.highest_observed_alert_id==52 and .alert_sample_gap==false' "$state" >/dev/null
live current 102 "$(alert_rows 54)" "$(alert_rows 53 52 51)" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.highest_observed_alert_id==54 and .alert_sample_gap==false' "$state" >/dev/null
live current 103 '[]' "$(alert_rows 56 54 53)" >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
bash "$watch" --check "$state" | jq -e '.status=="current" and .alert_sample_gap' >/dev/null
live current 104 '[]' "$(alert_rows 200)" | jq '.health.capture_id="scope-2"' >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.highest_observed_alert_id==200 and .alert_sample_gap==false' "$state" >/dev/null
live current 105 '[]' "$(alert_rows 300 302)" | jq '.health.capture_id="scope-3"' >"$report"
bash "$watch" --once "$state" -- cat "$report" >/dev/null
jq -e '.highest_observed_alert_id==302 and .alert_sample_gap and (.has_older_alerts | not)' "$state" >/dev/null

for retained_id in 41 42; do
    state="$scratch/alert-sample-regression-$retained_id.json"
    live current 101 '[]' "$(alert_rows 41 42)" >"$report"
    bash "$watch" --once "$state" -- cat "$report" >/dev/null
    if [[ $retained_id == 42 ]]; then
        live current 102 '[]' "$(alert_rows 42)" | jq '.has_more_alerts=true' >"$report"
        bash "$watch" --once "$state" -- cat "$report" >/dev/null
        jq -e '.highest_observed_alert_id==42 and .alert_sample_gap==false' "$state" >/dev/null
        live current 103 '[]' "$(alert_rows 41 42)" >"$report"
        bash "$watch" --once "$state" -- cat "$report" >/dev/null
    fi
    live current 104 '[]' "$(alert_rows "$retained_id")" >"$report"
    bash "$watch" --once "$state" -- cat "$report" >/dev/null
    bash "$watch" --check "$state" | jq -e '
        .status=="current" and .alert_counts.highest_observed_alert_id==42 and .alert_sample_gap
        and .alert_counts.status=="sampled"' >/dev/null
    live current 105 '[]' "$(alert_rows 41 42 43)" >"$report"
    bash "$watch" --once "$state" -- cat "$report" >/dev/null
    jq -e '.highest_observed_alert_id==43 and .alert_sample_gap' "$state" >/dev/null
    live current 1 '[]' '[]' | jq '.health.capture_id="new-capture"' >"$report"
    bash "$watch" --once "$state" -- cat "$report" >/dev/null
    jq -e '.highest_observed_alert_id==0 and .alert_sample_gap==false' "$state" >/dev/null
done
