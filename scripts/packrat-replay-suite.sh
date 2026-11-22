#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-replay-suite MANIFEST.json' \
        'Replay up to 32 labeled captures. Relative capture paths are relative to the manifest.' \
        'Example: {"version":1,"cases":[{"name":"baseline","capture":"baseline.pcapng","expect_counts":{"scan.horizontal":0}}]}' \
        'Use opening_frames to label exact frames, for example {"scan.horizontal":[12]}.' \
        'Use expect_snapshots to also check the total number of openings and updates in a case.' \
        'Set "strict":true to fail a case if any unlisted rule or unregistered finding opens.' \
        'Reports score exact frames separately from count-only expectations. Inconclusive cases are not scored.' \
        'Set PACKRAT_REPLAY_BASELINE_ANALYZER to an older analyzer command or executable path to compare results.'
}

if [[ ${1-} == --help || ${1-} == -h ]]; then usage; exit 0; fi
if (( $# != 1 )) || [[ ! -f $1 ]]; then usage >&2; exit 2; fi
for command in jq packrat-analyze; do
    if ! command -v "$command" >/dev/null; then
        printf 'Missing dependency: %s\n' "$command" >&2
        exit 2
    fi
done
baseline=${PACKRAT_REPLAY_BASELINE_ANALYZER:-}
if [[ -n $baseline ]] && ! command -v -- "$baseline" >/dev/null; then
    printf '%s\n' 'Baseline analyzer is unavailable.' >&2
    exit 2
fi

if ! validated=$(head -c 65537 -- "$1" | jq -Rces '
    def text($max): type == "string" and length > 0 and length <= $max and (test("[[:cntrl:]]") | not);
    def rules: all(keys[]; length <= 128 and test("\\A[A-Za-z0-9_.-]+\\z"));
    def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def valid_case:
        type == "object" and (.name | text(128)) and (.capture | text(1024))
        and ((has("expect_snapshots") | not) or (.expect_snapshots | count))
        and ((.expect_counts // {}) | type == "object" and rules and all(.[]; count))
        and ((.opening_frames // {}) | type == "object" and rules and all(.[]; type == "array"
             and length > 0 and all(.[]; count and . > 0) and (unique | length) == length))
        and (((.expect_counts // {} | length) + ([.opening_frames // {} | .[] | length] | add // 0)) as $n
             | $n >= 1 and $n <= 64);
    select(utf8bytelength <= 65536) | fromjson | objects
    | select(.version == 1 and ((has("strict") | not) or (.strict | type == "boolean"))
        and (.cases | type == "array" and length >= 1 and length <= 32
        and all(.[]; valid_case)
        and ((map(.name) | unique | length) == length)))
'); then
    printf '%s\n' 'Invalid replay suite manifest.' >&2
    exit 2
fi

base=$(cd -- "$(dirname -- "$1")" && pwd)
strict=$(jq -c '.strict // false' <<< "$validated")
replay_case() {
    local analyzer=$1 summary=null status=0
    if [[ -f $capture ]]; then
        summary=$("$analyzer" "${options[@]}" -- "$capture" |
            jq -cn 'reduce inputs as $row (null;
                if $row.type == "summary" then
                    $row | {packets,analyzed,skipped,alerts_opened,alert_snapshots,rule_counts,alert_expectations}
                else . end)') || status=$?
    fi
    jq -cn --arg name "$name" --argjson result "${summary:-null}" --argjson status "$status" \
        --argjson strict "$strict" --argjson label "$label" '
        (($label.expect_counts // {}) + ($label.opening_frames // {}) | keys) as $labeled |
        ($result.rule_counts | if type == "object" then . else {} end) as $rules |
        ($rules | with_entries(select(.key as $key | .value > 0 and ($labeled | index($key) == null)))) as $unlisted |
        ([$rules[]] | add // 0) as $registered |
        (if ($result.rule_counts | type) == "object" and ($result.alerts_opened | type) == "number"
            and $result.alerts_opened >= $registered then $result.alerts_opened - $registered else null end) as $unregistered |
        ($result.alert_expectations.verdict) as $evaluation |
        (if $label | has("expect_snapshots") then
            {expected:$label.expect_snapshots, observed:$result.alert_snapshots}
         else null end) as $snapshot_check |
        (if $evaluation == "failed" then "failed"
         elif $evaluation != "passed" or $status != 0 or ($strict and $unregistered == null) then "inconclusive"
         elif $snapshot_check != null and ($snapshot_check.observed | type) != "number" then "inconclusive"
         elif $snapshot_check != null and $snapshot_check.expected != $snapshot_check.observed then "failed"
         elif $strict and (($unlisted | length) > 0 or $unregistered > 0) then "failed"
         else "passed" end) as $verdict |
        ($result.alert_expectations.frame_checks // []) as $frames |
        ($result.alert_expectations.checks // [] |
            map(select(.rule_id as $id | all($frames[]; .rule_id != $id)))) as $counts |
        {name:$name, verdict:$verdict,
         unlisted_rule_counts:$unlisted, unregistered_alerts:$unregistered, summary:$result,
         snapshot_check:$snapshot_check,
         score:(if $verdict == "inconclusive" then null else {
             missed_opening_frames: ([$frames[].missing_frames | length] | add // 0),
             unexpected_openings: ([$frames[].unexpected_openings] | add // 0),
             count_deficit: ([$counts[] | [.expected - .observed, 0] | max] | add // 0),
             count_surplus: ([$counts[] | [.observed - .expected, 0] | max] | add // 0)
         } end)}
    '
}

capture_stamp() {
    stat -L --format='%d:%i:%s:%y:%z' -- "$capture" 2>/dev/null
}

results=()
while IFS= read -r label; do
    name=$(jq -er '.name' <<< "$label")
    capture=$(jq -er '.capture' <<< "$label")
    if [[ $capture != /* ]]; then capture="$base/$capture"; fi
    mapfile -t options < <(jq -r '
        (.expect_counts // {} | to_entries[] | "--expect-alert", (.key + "=" + (.value | floor | tostring))),
        (.opening_frames // {} | to_entries[] | .key as $id | .value[] |
            "--expect-alert-frame", ($id + "=" + (floor | tostring)))
    ' <<< "$label")

    if [[ -n $baseline ]]; then stamp=$(capture_stamp) || stamp=; fi
    candidate=$(replay_case packrat-analyze)
    if [[ -n $baseline ]]; then
        reference=$(replay_case "$baseline")
        after=$(capture_stamp) || after=
        candidate=$(jq -c --argjson reference "$reference" --arg before "$stamp" --arg after "$after" '
            def difference($candidate; $baseline):
                if ($candidate | type) == "number" and ($baseline | type) == "number"
                then $candidate - $baseline else null end;
            def rule_differences($candidate; $baseline):
                if ($candidate | type) == "object" and ($baseline | type) == "object" then
                    ($candidate + $baseline | keys) as $rules
                    | reduce $rules[] as $rule ({};
                        (($candidate[$rule] // 0) - ($baseline[$rule] // 0)) as $delta
                        | if $delta == 0 then . else .[$rule] = $delta end)
                else null end;
            .baseline = $reference
            | if $before == "" or $before != $after then
                .verdict = "inconclusive" | .score = null | .comparison = "capture_unstable"
              elif .score == null or $reference.score == null then
                .comparison = "inconclusive"
              else
                .comparison = "comparable"
                | .delta = ({
                    alerts_opened: difference(.summary.alerts_opened; $reference.summary.alerts_opened),
                    alert_snapshots: difference(.summary.alert_snapshots; $reference.summary.alert_snapshots),
                    unregistered_alerts: difference(.unregistered_alerts; $reference.unregistered_alerts),
                    rule_openings: rule_differences(.summary.rule_counts; $reference.summary.rule_counts)
                  } + (.score | with_entries(.key as $key | .value -= $reference.score[$key])))
              end
        ' <<< "$candidate")
    fi
    results+=("$candidate")
done < <(jq -c '.cases[]' <<< "$validated")

report=$(printf '%s\n' "${results[@]}" | jq -cs --argjson strict "$strict" --arg baseline "$baseline" '
    [.[].score | objects] as $scores |
    {
    record_type:"capture_replay_suite", strict:$strict, total:length,
    passed:([.[] | select(.verdict == "passed")] | length),
    failed:([.[] | select(.verdict == "failed")] | length),
    inconclusive:([.[] | select(.verdict == "inconclusive")] | length),
    score:{
        scored_cases: ($scores | length),
        missed_opening_frames: ([$scores[].missed_opening_frames] | add // 0),
        unexpected_openings: ([$scores[].unexpected_openings] | add // 0),
        count_deficit: ([$scores[].count_deficit] | add // 0),
        count_surplus: ([$scores[].count_surplus] | add // 0)
    }, cases:.
} | if $baseline == "" then . else
    . + {comparable: ([.cases[] | select(.comparison == "comparable")] | length)}
end')
printf '%s\n' "$report"
jq -e '.failed == 0 and .inconclusive == 0 and (.comparable // .total) == .total' <<< "$report" >/dev/null
