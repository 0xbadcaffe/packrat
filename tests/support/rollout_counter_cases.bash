# shellcheck shell=bash
(
    triage_state="$scratch/triage.json"
    triage_journal_required=1
    archive_candidate=''
    capture_scope='{"capture_id":"capture-a","capture_run_id":"run-a","alert_session_id":"session-a"}'
    triage='{"status":"current","capture_id":"capture-a","session_id":"session-a","packets":100,
        "packet_counter_gap":false,"alert_sample_gap":false,"journal_status":"current","journal_pending_events":0}'
    live=$(jq -c '. + {service:"packrat",status:"ok",capture_active:true,telemetry_fresh:true,packets_total:103,
        pcap_buffer_drops:0,capture_queue_full_packets:0,capture_truncated_frames:0}' <<<"$capture_scope")
    timeout() { printf '%s\n' "$triage"; }
    curl() { printf '%s\n' "$live"; }

    triage_watcher_ready "$capture_scope" 0 1
    for patch in '.packets_total=99' '.capture_run_id="restarted"' '.alert_session_id="other"' '.telemetry_fresh=false' \
        '.capture_queue_full_packets=1' '.capture_truncated_frames=1' '.pcap_buffer_drops=1' 'del(.capture_queue_full_packets)'; do
        if live=$(jq -c "$patch" <<<"$live") triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi
    done
    for patch in '.alert_sample_gap=true' 'del(.alert_sample_gap)'; do
        if triage=$(jq -c "$patch" <<<"$triage") triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi
    done
    triage=$(jq -c '.packet_counter_gap=true' <<<"$triage")
    triage_watcher_ready "$capture_scope" 0 0
    if triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi

    # Older watchers may not provide counters. They still require valid scope and journal state.
    triage=$(jq -c 'del(.packets,.packet_counter_gap)' <<<"$triage")
    curl() { return 99; }
    triage_watcher_ready "$capture_scope" 0 0
    if triage_watcher_ready "$capture_scope" 0 1; then exit 1; fi
    for patch in '.journal_status="write_failed"' '.capture_id="other"' '.packets="100"' '.status="packet_counter_regressed"'; do
        if triage=$(jq -c "$patch" <<<"$triage") triage_watcher_ready "$capture_scope" 0 0; then exit 1; fi
    done
)
(
    health_state="$scratch/health.json"
    # shellcheck disable=SC2329  # Invoked by the sourced rollout helper.
    date() { printf '%s\n' 1700000000; }
    touch "$data_dir/alerts.jsonl"
    primary_alert_log_identity() { stat -Lc '%d:%i' "$data_dir/alerts.jsonl"; }
    scope='{"pid":"42","capture_id":"00000000000000000000000000000002",
        "capture_run_id":"0000000000000001","alert_session_id":"1700000000-42"}'
    sample=$(jq -c --arg log "$data_dir/alerts.jsonl" --arg identity "$(primary_alert_log_identity)" '
        del(.pid) + {record_type:"capture_health",timestamp:"2023-11-14T22:13:10Z",
            poll_interval_seconds:15,capture_active:true,telemetry_fresh:true,
            alert_watcher_alive:true,alert_watcher_pipeline_alive:true,
            alert_watcher_source_matches:true,alert_watcher_open_log_required:true,alert_log_identity:$identity,
            alert_watcher_log:$log,alert_log_storage:"private",issues:[],pcap_buffer_drops:0}
    ' <<< "$scope")
    printf '%s\n' "$sample" >"$health_state"
    alert_watcher_ready "$scope"
    for update in '.alert_watcher_pipeline_alive = false' '.alert_watcher_source_matches = false' \
        '.alert_watcher_log += ".old"' '.capture_id = "00000000000000000000000000000003"' \
        '.alert_session_id = "1700000000-43"' '.timestamp = "2023-11-14T22:12:29Z"' \
        'del(.poll_interval_seconds)' 'del(.alert_log_storage)' 'del(.alert_log_identity)' \
        '.alert_watcher_open_log_required = false' '.alert_log_identity = "0:0"' \
        '.alert_log_storage = "unsafe"' '.alert_log_storage = "unavailable"' \
        '.issues = ["capture_queue_packets_dropped"]' '.pcap_buffer_drops = 1' 'del(.issues)'; do
        jq -c "$update" <<< "$sample" >"$health_state"
        if alert_watcher_ready "$scope"; then exit 1; fi
    done
    printf '%s\n' "$sample" >"$health_state"
    mv -- "$data_dir/alerts.jsonl" "$data_dir/alerts.previous"
    touch "$data_dir/alerts.jsonl"
    if alert_watcher_ready "$scope"; then exit 1; fi
    jq -c --arg id "$(primary_alert_log_identity)" '.alert_log_identity = $id' <<< "$sample" >"$health_state"
    alert_watcher_ready "$scope"
)
