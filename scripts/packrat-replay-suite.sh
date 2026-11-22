#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-replay-suite MANIFEST.json' \
        'Replay up to 32 labeled captures. Relative capture paths are relative to the manifest.' \
        'Example: {"version":1,"cases":[{"name":"baseline","capture":"baseline.pcapng","expect_counts":{"scan.horizontal":0}}]}' \
        'Use opening_frames to label exact frames, for example {"scan.horizontal":[12]}.' \
        'Use opening_evidence to check exact supporting frames: [{"rule_id":"scan.horizontal","opening_frame":12,"frames":[2,12]}].' \
        'Use expect_snapshots to also check the total number of openings and updates in a case.' \
        'Set "allow_truncated":true only for a case intentionally replaying partial frames.' \
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
    def frame: count and . > 0;
    def frame_list: type == "array" and length > 0
        and all(.[]; frame) and (unique | length) == length;
    def valid_case:
        . as $case |
        type == "object" and (.name | text(128)) and (.capture | text(1024))
        and ((has("expect_snapshots") | not) or (.expect_snapshots | count))
        and ((has("allow_truncated") | not) or (.allow_truncated | type == "boolean"))
        and ((.expect_counts // {}) | type == "object" and rules and all(.[]; count))
        and ((.opening_frames // {}) | type == "object" and rules and all(.[]; frame_list))
        and ((if has("opening_evidence") then .opening_evidence else [] end)
            | type == "array" and length <= 64
            and all(.[]; type == "object" and (.rule_id | type == "string")
                and (.opening_frame | frame) and (.frames | frame_list and length <= 131)
                and (.opening_frame as $opening | (.frames | index($opening)) != null
                    and (($case.opening_frames[.rule_id] // []) | index($opening)) != null))
            and (map([.rule_id,.opening_frame]) | unique | length) == length)
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
    local analyzer=$1 replay=null status=0
    if [[ -f $capture ]]; then
        replay=$("$analyzer" "${options[@]}" -- "$capture" |
            jq -cn --argjson label "$label" '
                def key($rule; $frame): $rule + ":" + ($frame | tostring);
                def ordinal: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
                def frames:
                    if (.packet_refs | type == "array" and length <= 128 and all(.[]; ordinal)) and
                       all([.first_packet,.packet_no,.last_packet][]; ordinal)
                    then [.first_packet,.packet_no,.last_packet,.packet_refs[]] | map(select(. > 0)) | unique
                    else null end;
                ($label.opening_evidence // [] | map(key(.rule_id; .opening_frame))) as $keys |
                reduce inputs as $row ({summary:null, evidence:{}};
                if $row.type == "summary" then
                    .summary = ($row | {packets,analyzed,skipped,truncated_frames,allow_truncated,
                        alerts_opened,alert_snapshots,rule_counts,alert_expectations})
                elif ($keys | length) > 0 and $row.type == "alert" and $row.schema_version == 1
                    and $row.alert.hit_count == 1 and ($row.alert.provenance.rule_id | type == "string")
                    and ($row.alert.packet_no | ordinal)
                then key($row.alert.provenance.rule_id; $row.alert.packet_no) as $key
                     | if ($keys | index($key)) != null then
                         .evidence[$key] |= if . == null then {matches:1, frames:($row.alert | frames)}
                                           else {matches:(.matches + 1), frames:null} end
                       else . end
                else . end)') || status=$?
    fi
    jq -cn --arg name "$name" --argjson replay "${replay:-null}" --argjson status "$status" \
        --argjson strict "$strict" --argjson label "$label" '
        $replay.summary as $result |
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
        ($label.opening_evidence // [] | map(
            . as $spec | ($replay.evidence[$spec.rule_id + ":" + ($spec.opening_frame | tostring)]) as $match
            | ($spec.frames | sort) as $expected
            | {rule_id, opening_frame, expected_frames:$expected, observed_frames:$match.frames,
               matching_openings:($match.matches // 0),
               passed:($match.matches == 1 and $match.frames == $expected)}
        )) as $evidence_checks |
        (if $evaluation == "failed" then "failed"
         elif $evaluation != "passed" or $status != 0 or ($strict and $unregistered == null) then "inconclusive"
         elif $snapshot_check != null and ($snapshot_check.observed | type) != "number" then "inconclusive"
         elif $snapshot_check != null and $snapshot_check.expected != $snapshot_check.observed then "failed"
         elif any($evidence_checks[]; .passed | not) then "failed"
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
        | if ($evidence_checks | length) > 0 then . + {evidence_checks:$evidence_checks} else . end
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
        (if .allow_truncated == true then "--allow-truncated" else empty end),
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
