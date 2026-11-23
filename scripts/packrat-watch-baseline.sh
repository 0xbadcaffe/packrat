#!/usr/bin/env bash
# Compare two retained capture coverage reports linked to verified builds.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-watch-baseline.sh BEFORE.json AFTER.json' \
        'Compares observed alert openings, not detector accuracy or total network activity.'
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then usage; exit 0; fi
if (( $# != 2 )); then usage >&2; exit 2; fi

read_baseline() {
    local path=$1
    if [[ ! -f $path ]]; then printf '%s\n' 'Expected a regular baseline file' >&2; return 1; fi
    head -c 65537 -- "$path" | jq -Rces '
        def token: type == "string" and test("\\A[A-Za-z0-9_.:-]{1,128}\\z");
        def scope: type == "object" and (.capture_id | token) and (.session_id | token);
        def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
        def tick:
            strings | select(test("\\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\\z"))
            | . as $stamp | fromdateiso8601 | select(todateiso8601 == $stamp);
        def valid_counts:
            ([.scoped_records,.healthy_seconds,.healthy_intervals,.healthy_packets,
              .excluded_intervals,.alert_comparable_intervals,.alert_comparable_packets] | all(.[]; count))
            and .healthy_intervals + .excluded_intervals == .scoped_records - 1
            and .healthy_seconds >= .healthy_intervals
            and .alert_comparable_intervals <= .healthy_intervals
            and .alert_comparable_packets <= .healthy_packets
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
            and ($c | .record_type == "capture_coverage_report" and (.scope | scope) and valid_counts)
            and $c.scope == $b.scope and $c.healthy_packets <= $b.packets
          then [($c.first_record_at | tick),($c.last_record_at | tick),($b.observed_at | tick)] as $times
            | if ($times | length) == 3 and $times[0] <= $times[1] and $times[1] <= $times[2]
                and $c.healthy_seconds <= $times[1] - $times[0] then
                  {interface:$b.interface,scope:$b.scope,capture_run_id:$b.capture_run_id,sha256:$b.sha256,
                   first_record_at:$c.first_record_at,last_record_at:$c.last_record_at,
                   healthy_seconds:$c.healthy_seconds,excluded_intervals:$c.excluded_intervals,
                   comparable_packets:$c.alert_comparable_packets,openings:$c.observed_openings,
                   openings_per_10000_packets:(if $c.alert_comparable_packets > 0
                       then $c.observed_openings * 10000 / $c.alert_comparable_packets else null end)}
              else error("Inconsistent baseline observation window") end
          else error("Invalid or mismatched build and coverage baseline") end
    '
}

before=$(read_baseline "$1")
after=$(read_baseline "$2")
printf '%s\n' "$before" "$after" | jq -cs '
    .[0] as $before | .[1] as $after
    | ($before.scope.capture_id == $after.scope.capture_id
        or $before.scope.session_id == $after.scope.session_id
        or $before.capture_run_id == $after.capture_run_id) as $shared
    | ($before.sha256 == $after.sha256) as $same_build
    | if $shared and ($before.scope != $after.scope or $before.capture_run_id != $after.capture_run_id
             or $before.interface != $after.interface or ($same_build | not)) then
        error("Conflicting metadata for the same capture")
      else
        (if $shared then "same_capture"
         elif $before.interface != $after.interface then "different_interfaces"
         elif $before.last_record_at > $after.first_record_at then "overlapping_or_reversed_windows"
         elif $before.openings_per_10000_packets == null or $after.openings_per_10000_packets == null then
           "insufficient_alert_coverage"
         else "separate_capture_windows" end) as $status
        | {record_type:"capture_build_comparison",status:$status,same_build:$same_build,
           before:$before,after:$after,
           observed_rate_delta_per_10000_packets:(if $status == "separate_capture_windows"
               then $after.openings_per_10000_packets - $before.openings_per_10000_packets else null end)}
      end
'
