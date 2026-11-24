dns_capacity_watcher_cases() {
    local state_file="$scratch/dns-capacity.json" report_file="$scratch/dns-capacity-report.json"
    local first='{"query_key_declines":4,"query_candidate_declines":7,"nxdomain_client_declines":1,"external_resolver_pair_declines":2}'
    local next='{"query_key_declines":5,"query_candidate_declines":7,"nxdomain_client_declines":4,"external_resolver_pair_declines":2}'
    local delta='{"query_key_declines":1,"query_candidate_declines":0,"nxdomain_client_declines":3,"external_resolver_pair_declines":0}'
    local patch
    live current 12 '[]' | jq --argjson stats "$first" '
        .health += {capture_active:true,telemetry_fresh:true,dns_capacity:($stats + {details:"private"})}
    ' > "$report_file"
    bash "$watch" --once "$state_file" -- cat "$report_file" | jq -e --argjson stats "$first" '
        .status=="current" and .dns_capacity==$stats and .dns_capacity_delta==null
        and (tostring | contains("private") | not)
    ' >/dev/null
    live current 13 '[]' | jq --argjson stats "$next" '
        .health += {capture_active:true,telemetry_fresh:true,dns_capacity:$stats}
    ' > "$report_file"
    bash "$watch" --once "$state_file" -- cat "$report_file" >/dev/null
    bash "$watch" --check "$state_file" | jq -e --argjson stats "$next" --argjson delta "$delta" '
        .status=="current" and .dns_capacity==$stats and .dns_capacity_delta==$delta
    ' >/dev/null

    for patch in '
        .health.dns_capacity.query_key_declines=3
    ' '.health.capture_id="replacement"' '.health.alert_session_id="new-session"' '.health.packets_total=11'; do
        jq "$patch" "$report_file" > "$scratch/dns-variation.json"
        cp "$state_file" "$scratch/dns-variation-state.json"
        bash "$watch" --once "$scratch/dns-variation-state.json" -- cat "$scratch/dns-variation.json" |
            jq -e '.dns_capacity!=null and .dns_capacity_delta==null' >/dev/null
    done
    for patch in 'del(.health.dns_capacity)' '.health.telemetry_fresh=false' \
        '.health.dns_capacity.query_candidate_declines=0.5' '.health.dns_capacity.nxdomain_client_declines=-1' \
        '.health.dns_capacity.external_resolver_pair_declines=9007199254740992'; do
        jq "$patch" "$report_file" > "$scratch/dns-variation.json"
        cp "$state_file" "$scratch/dns-variation-state.json"
        bash "$watch" --once "$scratch/dns-variation-state.json" -- cat "$scratch/dns-variation.json" |
            jq -e '.dns_capacity==null and .dns_capacity_delta==null' >/dev/null
    done
    jq '.updated_at=((now - 180) | floor | todateiso8601)' "$state_file" > "$scratch/dns-stale-state.json"
    { bash "$watch" --check "$scratch/dns-stale-state.json" || [[ $? == 1 ]]; } |
        jq -e '.status=="snapshot_stale" and .dns_capacity==null and .dns_capacity_delta==null' >/dev/null
    bash "$watch" --once "$scratch/dns-stale-state.json" -- cat "$report_file" |
        jq -e '.dns_capacity!=null and .dns_capacity_delta==null' >/dev/null

    local journal_state="$scratch/dns-journal.json" journal_report="$scratch/dns-journal-report.json"
    local journal="${journal_state}.events.jsonl" attempt
    jq --argjson stats "$first" '.health.dns_capacity=$stats' "$report_file" > "$journal_report"
    PACKRAT_TRIAGE_WATCH_INTERVAL=1 PACKRAT_TRIAGE_WATCH_TIMEOUT=2 PACKRAT_TRIAGE_WATCH_JOURNAL=1 \
        bash "$watch" "$journal_state" -- cat "$journal_report" >"$scratch/dns-journal-output.jsonl" &
    watch_pid=$!
    for ((attempt=0; attempt<100; attempt++)); do
        [[ -s "$journal" ]] && break
        sleep .05
    done
    jq --argjson stats "$first" -es '
        length==1 and .[0].dns_capacity==$stats and .[0].dns_capacity_delta==null
    ' "$journal" >/dev/null
    cp "$report_file" "$journal_report.next"
    mv -fT -- "$journal_report.next" "$journal_report"
    for ((attempt=0; attempt<120; attempt++)); do
        if jq -e --argjson stats "$next" '.dns_capacity==$stats and (.dns_capacity_delta | type=="object" and all(.[]; .==0))' "$journal_state" >/dev/null; then
            break
        fi
        sleep .05
    done
    jq -e --argjson stats "$next" '.dns_capacity==$stats and (.dns_capacity_delta | type=="object" and all(.[]; .==0))' "$journal_state" >/dev/null
    kill "$watch_pid"
    wait "$watch_pid" || :
    watch_pid=''
    jq -es --argjson delta "$delta" 'length==2 and .[1].status=="current" and .[1].dns_capacity_delta==$delta' "$journal" >/dev/null
}
dns_capacity_watcher_cases
