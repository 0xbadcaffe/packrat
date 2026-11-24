run_scenario analyzer_success 0 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat analyzer retire-stage
run_scenario analyzer_failure 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat analyzer stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops retire-stage
run_scenario analyzer_watcher_fail 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    install:/candidate start:packrat:/usr/local/bin/packrat stop:packrat:/usr/local/bin/packrat \
    install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops retire-stage
for shutdown_case in shutdown_alert shutdown_staged_finding; do
    run_scenario "$shutdown_case" 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
        stop:packrat:/usr/local/bin/packrat install:/backup/packrat start:packrat:/usr/local/bin/packrat \
        allow-existing-drops retire-stage
    grep -Fq 'during primary shutdown; candidate not installed' "$scratch/rollout-output"
done
run_scenario shutdown_alert_watcher_lost 1 backup start:packrat-stage:/candidate stop:packrat:/usr/local/bin/packrat \
    stop:packrat:/usr/local/bin/packrat install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops
run_scenario evidence_shutdown_alert 1 backup start:packrat-stage:/candidate evidence-profile \
    "reserve:$data_dir/alert-evidence-archive" stop:packrat:/usr/local/bin/packrat \
    "unreserve:$data_dir/alert-evidence-archive" stop:packrat:/usr/local/bin/packrat install:/backup/packrat \
    start:packrat:/usr/local/bin/packrat original-profile allow-existing-drops retire-stage
prepare_retention_case() {
    archive_path=/existing archive_flag=--archive-alert-evidence
    if [[ $scenario == retain_rule_health_fail ]]; then
        retain_rule=ipv6.ra_router_link_change
        archive_rule_args=(--archive-evidence-rule tcp.payload_after_observed_reset)
    else
        remove_rule=ipv6.ra_router_link_change
        archive_rule_args=(--archive-evidence-rule "$remove_rule")
    fi
}
retention_trace() {
    local expected=''
    if [[ $scenario == retain_rule_health_fail ]]; then
        expected='--archive-evidence-rule tcp.payload_after_observed_reset'
        if [[ $1 != false ]]; then expected+=' --archive-evidence-rule ipv6.ra_router_link_change'; fi
    elif [[ $1 == false ]]; then
        expected='--archive-evidence-rule ipv6.ra_router_link_change'
    fi
    [[ ${archive_rule_args[*]} == "$expected" ]] || return 2
    trace+=("retention:$1")
}
for operation in retain remove; do
    run_scenario "${operation}_rule_health_fail" 1 backup start:packrat-stage:/candidate retention:true stop:packrat:/usr/local/bin/packrat \
        install:/candidate start:packrat:/usr/local/bin/packrat retention:true stop:packrat:/usr/local/bin/packrat \
        install:/backup/packrat start:packrat:/usr/local/bin/packrat allow-existing-drops retention:false retire-stage
done

(
    retain_rule=ipv6.ra_router_link_change enable_alert_evidence=false archive_path=/existing archive_flag=--archive-alert-evidence
    archive_rule_args=(--archive-evidence-rule tcp.payload_after_observed_reset)
    archive_limits=(--archive-max-mib 64 --archive-max-frames 8192)
    apply_requested_profile
    apply_requested_profile
    [[ ${archive_rule_args[*]} == '--archive-evidence-rule tcp.payload_after_observed_reset --archive-evidence-rule ipv6.ra_router_link_change' ]]
    [[ $archive_path == /existing && ${archive_limits[*]} == '--archive-max-mib 64 --archive-max-frames 8192' ]]
    for flag in --archive --archive-alert-evidence; do
        if archive_path='' archive_flag="$flag" apply_requested_profile 2>/dev/null; then exit 1; fi
    done
    if archive_flag=--archive apply_requested_profile 2>/dev/null; then exit 1; fi
    if retain_rule='bad choice' apply_requested_profile 2>/dev/null; then exit 1; fi
    if enable_alert_evidence=true apply_requested_profile 2>/dev/null; then exit 1; fi

    remove_rule=$retain_rule other=tcp.payload_after_observed_reset
    if apply_requested_profile 2>/dev/null; then exit 1; fi
    retain_rule=''
    archive_policy_changes
    apply_requested_profile
    if archive_policy_changes; then exit 1; fi
    apply_requested_profile
    [[ ${archive_rule_args[*]} == "--archive-evidence-rule $other" ]]
    remove_rule=$other
    apply_requested_profile
    [[ ${#archive_rule_args[@]} == 0 && $archive_path == /existing && $archive_flag == --archive-alert-evidence &&
        ${archive_limits[*]} == '--archive-max-mib 64 --archive-max-frames 8192' ]]
)
