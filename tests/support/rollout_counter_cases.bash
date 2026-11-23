# shellcheck shell=bash
(
    triage_state="$scratch/triage.json"
    triage_journal_required=1
    archive_candidate=''
    capture_scope='{"capture_id":"capture-a","capture_run_id":"run-a","alert_session_id":"session-a"}'
    triage='{"status":"current","capture_id":"capture-a","session_id":"session-a","packets":100,
        "packet_counter_gap":false,"journal_status":"current","journal_pending_events":0}'
    live=$(jq -c '. + {service:"packrat",status:"ok",capture_active:true,telemetry_fresh:true,packets_total:103}' <<<"$capture_scope")
    timeout() { printf '%s\n' "$triage"; }
    curl() { printf '%s\n' "$live"; }

    triage_watcher_ready "$capture_scope" 0 1
    for patch in '.packets_total=99' '.capture_run_id="restarted"' '.alert_session_id="other"' '.telemetry_fresh=false'; do
        if live=$(jq -c "$patch" <<<"$live") triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi
    done
    triage=$(jq -c '.packet_counter_gap=true' <<<"$triage")
    triage_watcher_ready "$capture_scope" 0 0
    if triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi

    # Older watchers may not provide counters. They still require valid scope and journal state.
    triage=$(jq -c 'del(.packets,.packet_counter_gap)' <<<"$triage")
    curl() { return 99; }
    triage_watcher_ready "$capture_scope" 0 1
    for patch in '.journal_status="write_failed"' '.capture_id="other"' '.packets="100"' '.status="packet_counter_regressed"'; do
        if triage=$(jq -c "$patch" <<<"$triage") triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi
    done
)
