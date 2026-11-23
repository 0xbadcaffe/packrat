#!/usr/bin/env bash
# Record and compare retained capture coverage linked to verified builds.
set -euo pipefail
export LC_ALL=C

usage() {
    printf '%s\n' 'Usage: packrat-watch-baseline.sh BEFORE.json AFTER.json' \
        '       packrat-watch-baseline.sh --record INTERFACE STATE.json OUTPUT.json' \
        'Recording requires a healthy live capture and publishes a private file without overwriting.' \
        'Compares observed alert openings, not detector accuracy or total network activity.'
}

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
