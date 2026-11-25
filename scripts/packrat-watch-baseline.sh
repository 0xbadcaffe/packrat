#!/usr/bin/env bash
# Record and compare retained capture coverage linked to verified builds.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-watch-baseline.sh BEFORE.json AFTER.json' \
        '       packrat-watch-baseline.sh --record INTERFACE STATE.json OUTPUT.json' \
        'Recording requires a healthy live capture and publishes a private file without overwriting.' \
        'Rate deltas require 300 comparable seconds and 1000 comparable packets in each capture by default.' \
        'Override with PACKRAT_BASELINE_MIN_SECONDS and PACKRAT_BASELINE_MIN_PACKETS.' \
        'Per-rule deltas require the same single revision to be observed in both windows.' \
        'Known different or mixed capture link types prevent rate comparison.' \
        'Observed alert openings do not measure detector accuracy or total network activity.'
}

read_baseline() {
    local path=$1
    if [[ ! -f $path ]]; then printf '%s\n' 'Expected a regular baseline file' >&2; return 1; fi
    head -c 65537 -- "$path" | jq -Rces '
        def token: type == "string" and test("\\A[A-Za-z0-9_.:-]{1,128}\\z");
        def scope: type == "object" and (.capture_id | token) and (.session_id | token);
        def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
        def capture_link:
            .capture_link | objects | {status,link_type}
            | select(if .status == "verified" then (.link_type | count and . <= 65535)
                     else (.status | IN("mixed","unverified")) and .link_type == null end);
        def dns_capacity_summary:
            . as $coverage | .dns_capacity_coverage | objects
            | {no_decline_intervals,decline_intervals,unverified_intervals,no_decline_packets,no_decline_seconds,
               observed_declines:(.observed_declines | if . == null then null else objects |
                   {query_key_declines,query_candidate_declines,nxdomain_client_declines,external_resolver_pair_declines}
                   | select(all(.[]; count)) end)}
            | select(all([.no_decline_intervals,.decline_intervals,.unverified_intervals,.no_decline_packets,.no_decline_seconds][];
                         count)
                and .no_decline_intervals + .decline_intervals + .unverified_intervals == $coverage.healthy_intervals
                and .no_decline_packets <= $coverage.healthy_packets and .no_decline_seconds <= $coverage.healthy_seconds
                and .no_decline_seconds >= .no_decline_intervals
                and (if .no_decline_intervals == 0 then .no_decline_packets == 0 and .no_decline_seconds == 0 else true end)
                and (if .observed_declines == null then .no_decline_intervals == 0 or .decline_intervals > 0
                     else .no_decline_intervals + .decline_intervals > 0
                        and any(.observed_declines[]; . > 0) == (.decline_intervals > 0) end));
        def tcp_stream_cache_summary:
            . as $coverage | .tcp_stream_cache_coverage | objects
            | {no_eviction_intervals,eviction_intervals,unverified_intervals,
               no_eviction_packets,no_eviction_seconds,observed_evictions}
            | select(all([.no_eviction_intervals,.eviction_intervals,.unverified_intervals,
                          .no_eviction_packets,.no_eviction_seconds][]; count)
                and .no_eviction_intervals + .eviction_intervals + .unverified_intervals == $coverage.healthy_intervals
                and .no_eviction_packets <= $coverage.healthy_packets and .no_eviction_seconds <= $coverage.healthy_seconds
                and .no_eviction_seconds >= .no_eviction_intervals
                and (if .no_eviction_intervals == 0 then .no_eviction_packets == 0 and .no_eviction_seconds == 0
                     elif .no_eviction_intervals == $coverage.healthy_intervals then
                        .no_eviction_packets == $coverage.healthy_packets and .no_eviction_seconds == $coverage.healthy_seconds
                     else true end)
                and (if .eviction_intervals > 0 then .observed_evictions == null
                        or ((.observed_evictions | count) and .observed_evictions >= .eviction_intervals)
                     elif .no_eviction_intervals > 0 then .observed_evictions == 0
                     else .observed_evictions == null end));
        def verified_rate_policy: IN("continuous_journal_v7","continuous_journal_v8");
        def rule_summary:
            (.rule_id | type == "string" and test("\\A[a-z0-9][a-z0-9_.-]{0,127}\\z"))
            and (.revision | count and . >= 1 and . <= 65535) and (.openings | count and . > 0);
        def valid_breakdown:
            .observed_openings as $observed | .opening_rule_breakdown
            | if . == null then true else
                ($observed | count) and type == "object"
                and (.rules | type == "array" and length <= 64 and all(.[]; rule_summary)
                    and length == (unique_by([.rule_id,.revision]) | length))
                and (.unattributed_openings | count) and (.omitted_rule_openings | count)
                and (([.rules[].openings] | add // 0) + .unattributed_openings + .omitted_rule_openings == $observed)
              end;
        def tick:
            strings | select(test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z"))
            | . as $stamp | fromdateiso8601 | select(todateiso8601 == $stamp);
        def valid_persistence_counts:
            (.coverage_policy | (IN("continuous_journal_v5","continuous_journal_v6") or verified_rate_policy) | not) or
            (all([.alert_save_failure_intervals,.alert_save_counter_unverified_intervals,
                  .alert_save_backlog_drop_intervals,.alert_save_backlog_unverified_intervals][]; count)
                and .alert_comparable_intervals + .alert_save_failure_intervals + .alert_save_counter_unverified_intervals <= .healthy_intervals
                and .alert_comparable_intervals + .alert_save_backlog_drop_intervals + .alert_save_backlog_unverified_intervals <= .healthy_intervals);
        def valid_journal_counts:
            (.coverage_policy | (. == "continuous_journal_v6" or verified_rate_policy) | not) or
            ((.alert_journal_counter_unverified_intervals | count) and
             (.journal_tail_unconfirmed_events | . == null or count) and
             .alert_comparable_intervals + .alert_journal_counter_unverified_intervals <= .healthy_intervals);
        def valid_log_snapshot_counts:
            (.coverage_policy | verified_rate_policy | not) or
            ((.alert_log_snapshot_unverified_intervals | count) and
             .alert_comparable_intervals + .alert_log_snapshot_unverified_intervals <= .healthy_intervals);
        def valid_reverification_counts:
            .coverage_policy != "continuous_journal_v8" or
            ((.alert_reverified_intervals | count) and .alert_reverified_intervals <= .alert_comparable_intervals
             and (.alert_reverified_intervals == 0 or .alert_sample_gap_reported == true));
        def valid_counts:
            ([.scoped_records,.healthy_seconds,.healthy_intervals,.healthy_packets,
              .excluded_intervals,.alert_comparable_intervals,.alert_comparable_packets] | all(.[]; count))
            and .healthy_intervals + .excluded_intervals == .scoped_records - 1
            and .healthy_seconds >= .healthy_intervals
            and .alert_comparable_intervals <= .healthy_intervals
            and .alert_comparable_packets <= .healthy_packets
            and (if has("alert_comparable_seconds") then
                  (.alert_comparable_seconds | count) and .alert_comparable_seconds <= .healthy_seconds
                  and .alert_comparable_seconds >= .alert_comparable_intervals
                  and (if .alert_comparable_intervals == 0 then .alert_comparable_seconds == 0
                       elif .alert_comparable_intervals == .healthy_intervals then .alert_comparable_seconds == .healthy_seconds
                       else .alert_comparable_seconds <= .healthy_seconds - (.healthy_intervals - .alert_comparable_intervals) end)
                 else true end)
            and (if .alert_comparable_intervals == 0 then
                    .observed_openings == null and .alert_comparable_packets == 0
                 else .observed_openings | count end)
            and (if .healthy_intervals == 0 then
                    .status == "insufficient_coverage" and .healthy_packets == 0 and .healthy_seconds == 0
                 else .status == "sampled" end);
        if utf8bytelength > 65536 then error("Baseline exceeds the 64 KiB input limit") else fromjson end
        | .build as $b | .coverage as $c
        | if .record_type == "capture_build_baseline"
            and ($b | .record_type == "verified_capture_build" and (.interface | token)
                and (.scope | scope) and (.capture_run_id | token) and (.packets | count)
                and (.sha256 | strings | test("\\A[0-9a-f]{64}\\z")))
            and ($c | .record_type == "capture_coverage_report" and (.scope | scope) and valid_counts
                and valid_breakdown and valid_persistence_counts and valid_journal_counts and valid_log_snapshot_counts
                and valid_reverification_counts)
            and $c.scope == $b.scope and $c.healthy_packets <= $b.packets
          then [($c.first_record_at | tick),($c.last_record_at | tick),($b.observed_at | tick)] as $times
            | if ($times | length) == 3 and $times[0] <= $times[1] and $times[1] <= $times[2]
                and $c.healthy_seconds <= $times[1] - $times[0] then
                  {interface:$b.interface,scope:$b.scope,capture_run_id:$b.capture_run_id,sha256:$b.sha256,
                   capture_link:($c | capture_link // null),
                   coverage_policy:(if $c.coverage_policy | IN("capture_loss_counters_v1","continuous_journal_v2","continuous_journal_v3","continuous_journal_v4","continuous_journal_v5","continuous_journal_v6") or verified_rate_policy then $c.coverage_policy else null end),
                   journal_tail_unconfirmed_events:($c.journal_tail_unconfirmed_events | if count then . else null end),
                   alert_journal_counter_unverified_intervals:($c.alert_journal_counter_unverified_intervals | if count then . else null end),
                   alert_log_snapshot_unverified_intervals:($c.alert_log_snapshot_unverified_intervals | if count then . else null end),
                   alert_reverified_intervals:(if $c.coverage_policy == "continuous_journal_v8" then $c.alert_reverified_intervals else null end),
                   first_record_at:$c.first_record_at,last_record_at:$c.last_record_at,
                   healthy_seconds:$c.healthy_seconds,excluded_intervals:$c.excluded_intervals,
                   dns_capacity_coverage:($c | dns_capacity_summary // null),
                   tcp_stream_cache_coverage:($c | tcp_stream_cache_summary // null),
                   comparable_seconds:(if $c | has("alert_comparable_seconds") then $c.alert_comparable_seconds
                       elif $c.alert_comparable_intervals == $c.healthy_intervals then $c.healthy_seconds else null end),
                   comparable_packets:$c.alert_comparable_packets,openings:$c.observed_openings,
                   opening_rule_breakdown:($c.opening_rule_breakdown | if . == null then null else
                       {rules:[.rules[] | {rule_id,revision,openings}],unattributed_openings,omitted_rule_openings} end),
                   openings_per_10000_packets:(if ($c.coverage_policy | verified_rate_policy) and $c.alert_comparable_packets > 0
                       then $c.observed_openings * 10000 / $c.alert_comparable_packets else null end)}
              else error("Inconsistent baseline observation window") end
          else error("Invalid or mismatched build and coverage baseline") end
    '
}

record_baseline() (
    set -euo pipefail
    umask 077
    local interface=$1 state=$2 output=$3 bin rollout watcher coverage stage before after report
    if [[ ! $interface =~ ^[A-Za-z0-9_.-]{1,128}$ || ! -f $state || -z ${output##*/} ]]; then
        printf '%s\n' 'Expected an interface, a watcher state file, and a new output file' >&2
        exit 2
    fi
    bin=$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")
    rollout="$bin/packrat-rollout" watcher="$bin/packrat-watch-triage" coverage="$bin/packrat-watch-coverage"
    if [[ -f $bin/packrat-rollout.sh ]]; then
        rollout="$bin/packrat-rollout.sh" watcher="$bin/watch-packrat-triage.sh" coverage="$bin/packrat-watch-coverage.sh"
    fi
    export PACKRAT_ROLLOUT_TRIAGE_STATE="$state" PACKRAT_ROLLOUT_TRIAGE_CHECK="$watcher"
    export PACKRAT_ROLLOUT_REQUIRE_TRIAGE_JOURNAL=1
    before=$(bash "$rollout" --identify "$interface")
    report=$("$watcher" --history "$state" | "$coverage")
    after=$(bash "$rollout" --identify "$interface")
    stage=$(mktemp -- "$(dirname -- "$output")/.packrat-baseline.XXXXXXXX")
    trap 'rm -f -- "$stage"' EXIT
    printf '%s\n' "$before" "$report" "$after" | jq -ces --arg interface "$interface" '
        if length == 3 then .[0] as $a | .[1] as $c | .[2] as $b
          | if $b.interface == $interface and $c.journal_tail_status == "current"
              and ($a | del(.packets,.observed_at)) == ($b | del(.packets,.observed_at))
              and ($a.packets | type == "number" and . >= 0 and floor == .)
              and $a.packets <= $b.packets and ($a.observed_at | type == "string")
              and $a.observed_at <= $b.observed_at
            then {record_type:"capture_build_baseline",build:$b,coverage:$c}
            else error("Capture or journal changed during baseline recording") end
        else error("Expected two build proofs and one coverage report") end
    ' > "$stage"
    read_baseline "$stage" >/dev/null
    ln -T -- "$stage" "$output"
)

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
if [[ ${1-} == --record ]]; then
    if (( $# != 4 )); then usage >&2; exit 2; fi
    record_baseline "$2" "$3" "$4"
    exit
fi
if (( $# != 2 )); then usage >&2; exit 2; fi
min_seconds=${PACKRAT_BASELINE_MIN_SECONDS:-300}
min_packets=${PACKRAT_BASELINE_MIN_PACKETS:-1000}
if [[ ! $min_seconds =~ ^[1-9][0-9]{0,8}$ || ! $min_packets =~ ^[1-9][0-9]{0,8}$ ]]; then
    printf '%s\n' 'Baseline minimums must be positive integers with at most nine digits.' >&2
    exit 2
fi

before=$(read_baseline "$1")
after=$(read_baseline "$2")
printf '%s\n' "$before" "$after" | jq -cs --argjson seconds "$min_seconds" --argjson packets "$min_packets" '
    def fully_attributed: .opening_rule_breakdown | . != null and .unattributed_openings == 0 and .omitted_rule_openings == 0;
    def observed_revisions($id):
        [.opening_rule_breakdown.rules[] | select(.rule_id == $id) | {revision,openings}] | sort_by(.revision);
    def compare_rules($before; $after):
        [$before.opening_rule_breakdown.rules[].rule_id, $after.opening_rule_breakdown.rules[].rule_id] | unique
        | map(. as $id | ($before | observed_revisions($id)) as $prior | ($after | observed_revisions($id)) as $next
            | (if ($prior | length) > 1 or ($next | length) > 1 then "mixed_revisions"
               elif $prior == [] or $next == [] then "not_observed_in_both_windows"
               elif $prior[0].revision != $next[0].revision then "different_revisions"
               else null end) as $reason
            | if $reason != null then {rule_id:$id,reason:$reason,before:$prior,after:$next}
              else {rule_id:$id,revision:$prior[0].revision,before_openings:$prior[0].openings,after_openings:$next[0].openings,
                    delta_per_10000_packets:($next[0].openings * 10000 / $after.comparable_packets
                        - $prior[0].openings * 10000 / $before.comparable_packets)} end)
        | {deltas:map(select(has("reason") | not)),unpaired:map(select(has("reason")))};
    .[0] as $before | .[1] as $after
    | ($before.scope.capture_id == $after.scope.capture_id
        or $before.scope.session_id == $after.scope.session_id
        or $before.capture_run_id == $after.capture_run_id) as $shared
    | ($before.sha256 == $after.sha256) as $same_build
    | (if $before.capture_link.status == "mixed" or $after.capture_link.status == "mixed" then "mixed"
       elif $before.capture_link.status == "verified" and $after.capture_link.status == "verified" then
           if $before.capture_link.link_type == $after.capture_link.link_type then "matched" else "different" end
       else "unverified" end) as $link_status
    | if $shared and ($before.scope != $after.scope or $before.capture_run_id != $after.capture_run_id
             or $before.interface != $after.interface or ($same_build | not)) then
        error("Conflicting metadata for the same capture")
      else
        (if $shared then "same_capture"
         elif $before.interface != $after.interface then "different_interfaces"
         elif $before.last_record_at > $after.first_record_at then "overlapping_or_reversed_windows"
         elif $link_status == "mixed" then "capture_link_type_mixed"
         elif $link_status == "different" then "different_capture_link_types"
         elif ($before.coverage_policy | IN("continuous_journal_v7","continuous_journal_v8") | not)
               or $before.coverage_policy != $after.coverage_policy then
           "coverage_policy_unverified"
         elif $before.openings_per_10000_packets == null or $after.openings_per_10000_packets == null then
           "insufficient_alert_coverage"
         elif $before.comparable_seconds == null or $after.comparable_seconds == null then "comparable_duration_unverified"
         elif ($before.comparable_seconds < $seconds or $after.comparable_seconds < $seconds
               or $before.comparable_packets < $packets or $after.comparable_packets < $packets) then "thin_alert_coverage"
         else "separate_capture_windows" end) as $status
        | (if $status == "separate_capture_windows" and ($before | fully_attributed) and ($after | fully_attributed)
           then compare_rules($before; $after) else null end) as $rules
        | (if $status != "separate_capture_windows" then "comparison_unavailable"
           elif $rules == null then "attribution_incomplete"
           elif $rules.unpaired == [] then
               if $rules.deltas == [] then "no_rule_openings" else "comparable" end
           elif $rules.deltas == [] then "rule_revisions_unverified"
           else "partially_comparable" end) as $rule_status
        | {record_type:"capture_build_comparison",status:$status,same_build:$same_build,
           capture_link_comparison:$link_status,
           before:$before,after:$after,comparison_minimums:{seconds:$seconds,packets:$packets},
           rule_rate_status:$rule_status,
           rule_rate_deltas:$rules.deltas,rule_rate_unpaired:$rules.unpaired,
           observed_rate_delta_per_10000_packets:(if $status == "separate_capture_windows"
               then $after.openings_per_10000_packets - $before.openings_per_10000_packets else null end)}
      end
'
