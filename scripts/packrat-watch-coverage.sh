#!/usr/bin/env bash
# Summarize comparable intervals in the bounded watch-packrat-triage --history stream.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: watch-packrat-triage.sh --history STATE.json | packrat-watch-coverage.sh [--capture-id ID --session ID]' \
        'Reads retained journal records from stdin; defaults to the last observed capture scope.' \
        'Rates describe retained intervals with known coverage, not all traffic or all alerts.' \
        'Alert rates require decodable capture and a valid saved-alert log at both endpoints.' \
        'Alert rates exclude intervals whose endpoint alert log grew during the review or was not checked for growth.' \
        'Alert rates require known, unchanged save-failure and retry-buffer drop counters.' \
        'Alert rates also require a known, unchanged unconfirmed journal event count.' \
        'After a historical gap, only complete, consistent alert samples can reestablish comparable intervals.' \
        'Intervals spanning watcher restarts, missing journal records, or older unsequenced records are excluded.' \
        'The tail unconfirmed count is watcher-wide, not attributed to the selected capture.' \
        'Alert-ID gaps and IDs that disappeared between samples are not proof of deletion from the saved log.'
}

capture='' session=''
if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
if (( $# == 4 )) && [[ $1 == --capture-id && $3 == --session &&
    $2 =~ ^[A-Za-z0-9_.-]{1,128}$ && $4 =~ ^[A-Za-z0-9_.-]{1,128}$ ]]; then
    capture=$2 session=$4
elif (( $# != 0 )); then
    usage >&2
    exit 2
fi

head -c 2097153 | jq -Rces --arg capture "$capture" --arg session "$session" '
    def id: type == "string" and test("\\A[A-Za-z0-9_.-]{1,128}\\z");
    def scope: (.capture_id | id) and (.session_id | id);
    def counter: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def valid_record:
        type == "object" and .record_type == "capture_triage_watch"
        and (.status | id) and (.updated_at | type == "string" and test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z"));
    def same($key): .capture_id == $key.capture_id and .session_id == $key.session_id;
    def healthy:
        .status == "current" and .link_decodable == true and .buffer_drops == 0 and .packet_counter_gap == false
        and (.healthy_capture_since | counter and . > 0) and .healthy_capture_since <= .tick and (.packets | counter);
    def alert_log_usable:
        .alert_saving == true and .alert_log_integrity.invalid_records == 0
        and .alert_log_integrity.oversized_records == 0
        and (.alert_log_integrity.stopped_at_scan_budget | . == false or . == null);
    def counter_status($before; $after):
        if (($before | counter) and ($after | counter)) | not then "unverified"
          elif $after < $before then "unverified"
          elif $after > $before then "increased"
          else "unchanged" end;
    def opening_delta($earlier; $later):
        $earlier.highest_observed_alert_id as $low | $later.highest_observed_alert_id as $high
        | (if $later.checkpoint == true and $later.alert_changes == null
            then [] else $later.alert_changes.newly_observed end) as $ids
        | if ($low | counter) and ($high | counter) and $high >= $low
             and ($ids | type == "array" and length <= 55 and all(.[]; counter and . > $low and . <= $high) and . == unique)
          then $ids else null end;
    def alert_samples:
        ((.recent_alerts | arrays | .[:50][]), (.review_queue | arrays | .[:5][])) | objects;
    def attribute_openings($later; $ids):
        [$later | alert_samples] as $sample
        | [$ids[] as $id | [$sample[] | select(.alert_id == $id)
            | if (.rule_id | type == "string" and test("\\A[a-z0-9][a-z0-9_.-]{0,127}\\z"))
                 and (.revision | counter and . >= 1 and . <= 65535)
              then {rule_id,revision} else null end] | unique | if length == 1 then .[0] else null end];
    def sampled_ids:
        [alert_samples | .alert_id | select(counter and . > 0)] | unique;
    def valid_sample_rows($max):
        if type == "array" and length <= $max then
            all(.[]; if type == "object" then (.alert_id | counter and . > 0) else false end)
            and (map(.alert_id) | length == (unique | length))
        else false end;
    def comparable_alert_sample:
        (.status | IN("current","degraded")) and alert_log_usable and .alert_log_advanced_during_review == false
        and (.recent_alerts | valid_sample_rows(50)) and (.review_queue | valid_sample_rows(5));
    def complete_alert_sample:
        comparable_alert_sample and .recent_alerts_at_limit == false and .has_older_alerts == false
        and .alert_log_integrity.stopped_at_limit == false and .invalid_alert_rows == 0 and .duplicate_alert_ids == 0
        and ((sampled_ids | last // 0) == .highest_observed_alert_id)
        and (([.review_queue[].alert_id] - [.recent_alerts[].alert_id]) == []);
    def reverified($earlier; $later; $ids):
        $earlier.alert_sample_gap == true and $later.alert_sample_gap == true
        and ($earlier | complete_alert_sample) and ($later | complete_alert_sample)
        and (($earlier | sampled_ids) as $before | ($later | sampled_ids) as $after
             | ($before - $after) == [] and ($after - $before) == $ids);
    def verified_opening_ids($earlier; $later):
        opening_delta($earlier; $later) as $ids
        | if ($earlier | alert_log_usable) and ($later | alert_log_usable) and $ids != null
             and $later.highest_observed_alert_id - $earlier.highest_observed_alert_id == ($ids | length)
             and (($earlier.alert_sample_gap == false and $later.alert_sample_gap == false) or reverified($earlier; $later; $ids))
          then $ids else null end;
    def missing_observed_ids($samples):
        [range(1; $samples | length) as $i
        | $samples[$i - 1] as $before | $samples[$i] as $after
        | select($after.alert_sample_gap == true and $after.tick >= $before.tick
            and ($before | comparable_alert_sample) and ($after | comparable_alert_sample))
        | ($before | sampled_ids) as $prior | ($after | sampled_ids) as $current
        | if $after.recent_alerts_at_limit == false and $after.has_older_alerts == false
             and $after.alert_log_integrity.stopped_at_limit == false then
              ($prior - $current)[]
          elif $before.highest_observed_alert_id == $prior[-1] and $prior[-1] > ($current[-1] // 0) then
              $prior[-1]
          else empty end] | unique;
    def unobserved_ranges($low; $known; $at):
        # Walk the observed IDs, not every integer in a potentially wide range.
        reduce $known[] as $id ({cursor:$low,ranges:[]};
            if $id > .cursor + 1 then .ranges += [{first_id:(.cursor + 1),last_id:($id - 1),recorded_at:$at}]
            else . end | .cursor = $id)
        | .ranges[];
    def candidate_gaps($samples):
        ($samples[0] | sampled_ids) as $initial
        | (if ($initial | length) > 1 then
             unobserved_ranges($initial[0] - 1; $initial; $samples[0].updated_at)
           else empty end),
          (range(1; $samples | length) as $i | $samples[$i - 1] as $before | $samples[$i] as $after
           | $before.highest_observed_alert_id as $low | $after.highest_observed_alert_id as $high
           | opening_delta($before; $after) as $delta
           | select($delta != null and $high > $low and $after.tick >= $before.tick)
           | (($after | sampled_ids | map(select(. > $low and . <= $high))) + $delta + [$high] | unique) as $known
           | (if $low == 0 then $known[0] - 1 else $low end) as $floor
           | unobserved_ranges($floor; $known; $after.updated_at));
    def lower_bound($sorted; $value):
        ($sorted | bsearch($value)) as $index | if $index < 0 then -1 - $index else $index end;
    def alert_gaps($samples):
        ([$samples[] | sampled_ids | .[]] | unique) as $observed
        | candidate_gaps($samples) as $range
        | ($range.last_id + 1) as $end
        | (lower_bound($observed; $range.first_id)) as $start_index
        | (lower_bound($observed; $end)) as $end_index
        # Later queue entries can account for holes in an earlier poll.
        | unobserved_ranges($range.first_id - 1; $observed[$start_index:$end_index] + [$end]; $range.recorded_at);
    def no_capture_loss_between($earlier; $later):
        all([$earlier.capture_queue_full_packets, $later.capture_queue_full_packets,
             $earlier.truncated_frames, $later.truncated_frames][]; counter)
        and $earlier.capture_queue_full_packets == $later.capture_queue_full_packets
        and $earlier.truncated_frames == $later.truncated_frames;
    def journal_contiguous($earlier; $later):
        ($earlier.journal_writer | id) and $earlier.journal_writer == $later.journal_writer
        and ($earlier.journal_sequence | counter and . > 0)
        and ($later.journal_sequence | counter and . > 0)
        and $later.journal_sequence - $earlier.journal_sequence == 1
        and (if ($earlier.journal_unconfirmed_events | counter) and ($later.journal_unconfirmed_events | counter)
             then $earlier.journal_unconfirmed_events == $later.journal_unconfirmed_events else true end);
    def pair($earlier; $later):
        if ($earlier | healthy) and ($later | healthy)
            and $earlier.healthy_capture_since == $later.healthy_capture_since
            and $later.tick > $earlier.tick and $later.packets >= $earlier.packets
            and no_capture_loss_between($earlier; $later)
        then counter_status($earlier.alert_save_failures; $later.alert_save_failures) as $saving
          | counter_status($earlier.alert_save_backlog_dropped; $later.alert_save_backlog_dropped) as $backlog
          | counter_status($earlier.journal_unconfirmed_events; $later.journal_unconfirmed_events) as $journal
          | ($earlier.alert_log_advanced_during_review == false and $later.alert_log_advanced_during_review == false) as $stable_log
          | (if $saving == "unchanged" and $backlog == "unchanged" and $journal == "unchanged" and $stable_log
             then verified_opening_ids($earlier; $later) else null end) as $ids
          | {seconds:($later.tick - $earlier.tick), packets:($later.packets - $earlier.packets),
             save_counter_status:$saving,
             backlog_counter_status:$backlog,
             journal_counter_status:$journal, stable_alert_log:$stable_log, historical_alert_gap:($later.alert_sample_gap == true),
             opening_rules:(if $ids == null then null else attribute_openings($later; $ids) end)} else null end;
    if utf8bytelength > 2097152 then error("Journal exceeds the 2 MiB input limit") else . end
    | split("\n") | map(select(length > 0) | fromjson
        | if valid_record then . + {tick:(.updated_at | fromdateiso8601)} else error("Invalid triage journal record") end) as $all
    | (if $capture != "" then {capture_id:$capture,session_id:$session}
       else (last($all[] | select(scope)) // null) | if . == null then null else {capture_id,session_id} end end) as $key
    | [$all[] | select($key != null and same($key))] as $sample
    | [range(1; $all | length) as $i | $all[$i - 1] as $before | $all[$i] as $after
        | select($key != null and ($before | same($key)) and ($after | same($key)))
        | if journal_contiguous($before; $after) then pair($before; $after)
          else "journal_discontinuity" end] as $pairs
    | ($pairs | map(objects)) as $healthy
    | ($healthy | map(select(.opening_rules != null))) as $comparable
    | ([$comparable[].packets] | add // 0) as $measured_packets
    | [$comparable[].opening_rules[]] as $openings
    | ($openings | map(objects) | group_by([.rule_id,.revision])
        | map(.[0] + {openings:length}) | sort_by([-.openings,.rule_id,.revision])) as $by_rule
    | [limit(65; alert_gaps($sample))] as $alert_gaps
    | missing_observed_ids($sample) as $missing_ids
    | {record_type:"capture_coverage_report",coverage_policy:"continuous_journal_v8",
       status:(if ($sample | length) == 0 then "no_capture_records"
               elif ($healthy | length) == 0 then "insufficient_coverage" else "sampled" end),
       scope:$key, journal_tail_status:$all[-1].status,
       journal_tail_unconfirmed_events:($all[-1].journal_unconfirmed_events | if counter then . else null end),
       first_record_at:$sample[0].updated_at,last_record_at:$sample[-1].updated_at,
       scoped_records:($sample | length),
       healthy_intervals:($healthy | length), excluded_intervals:([($sample | length) - 1,0] | max) - ($healthy | length),
       journal_discontinuities:([$pairs[] | select(. == "journal_discontinuity")] | length),
       healthy_seconds:([$healthy[].seconds] | add // 0), healthy_packets:([$healthy[].packets] | add // 0),
       alert_comparable_intervals:($comparable | length), alert_comparable_packets:$measured_packets,
       alert_comparable_seconds:([$comparable[].seconds] | add // 0),
       alert_reverified_intervals:([$comparable[] | select(.historical_alert_gap)] | length),
       alert_save_failure_intervals:([$healthy[] | select(.save_counter_status == "increased")] | length),
       alert_save_counter_unverified_intervals:([$healthy[] | select(.save_counter_status == "unverified")] | length),
       alert_save_backlog_drop_intervals:([$healthy[] | select(.backlog_counter_status == "increased")] | length),
       alert_save_backlog_unverified_intervals:([$healthy[] | select(.backlog_counter_status == "unverified")] | length),
       alert_journal_counter_unverified_intervals:([$healthy[] | select(.journal_counter_status == "unverified")] | length),
       alert_log_snapshot_unverified_intervals:([$healthy[] | select(.stable_alert_log | not)] | length),
       alert_sample_gap_reported:any($sample[]; .alert_sample_gap == true),
       missing_previously_observed_alert_ids:$missing_ids[:64],
       missing_previously_observed_alert_ids_truncated:($missing_ids | length > 64),
       unobserved_alert_id_ranges:$alert_gaps[:64], unobserved_alert_id_ranges_truncated:($alert_gaps | length > 64),
       observed_openings:(if ($comparable | length) > 0 then ($openings | length) else null end),
       opening_rule_breakdown:(if ($comparable | length) > 0 then {rules:$by_rule[:64],
           unattributed_openings:([$openings[] | select(. == null)] | length),
           omitted_rule_openings:([$by_rule[64:][] | .openings] | add // 0)} else null end),
       observed_openings_per_10000_packets:(if $measured_packets > 0 then ($openings | length) * 10000 / $measured_packets else null end)}
'
