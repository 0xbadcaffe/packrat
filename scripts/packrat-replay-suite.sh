#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-replay-suite MANIFEST.json' \
        'Replay up to 32 labeled captures. Relative capture paths are relative to the manifest.' \
        'Example: {"version":1,"cases":[{"name":"baseline","capture":"baseline.pcapng","expect_counts":{"scan.horizontal":0}}]}' \
        'Use opening_frames to label exact frames, for example {"scan.horizontal":[12]}.' \
        'Set "strict":true to fail a case if any unlisted rule or unregistered finding opens.'
}

if [[ ${1-} == --help || ${1-} == -h ]]; then usage; exit 0; fi
if (( $# != 1 )) || [[ ! -f $1 ]]; then usage >&2; exit 2; fi
for command in jq packrat-analyze; do
    if ! command -v "$command" >/dev/null; then
        printf 'Missing dependency: %s\n' "$command" >&2
        exit 2
    fi
done

if ! validated=$(head -c 65537 -- "$1" | jq -Rces '
    def text($max): type == "string" and length > 0 and length <= $max and (test("[[:cntrl:]]") | not);
    def rules: all(keys[]; length <= 128 and test("\\A[A-Za-z0-9_.-]+\\z"));
    def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
    def valid_case:
        type == "object" and (.name | text(128)) and (.capture | text(1024))
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

    summary=null
    status=0
    if [[ -f $capture ]]; then
        summary=$(packrat-analyze "${options[@]}" -- "$capture" |
            jq -cn 'reduce inputs as $row (null;
                if $row.type == "summary" then
                    $row | {packets,analyzed,skipped,alerts_opened,rule_counts,alert_expectations}
                else . end)') || status=$?
    fi
    results+=("$(jq -cn --arg name "$name" --argjson result "${summary:-null}" --argjson status "$status" \
        --argjson strict "$strict" --argjson label "$label" '
        (($label.expect_counts // {}) + ($label.opening_frames // {}) | keys) as $labeled |
        ($result.rule_counts | if type == "object" then . else {} end) as $rules |
        ($rules | with_entries(select(.key as $key | .value > 0 and ($labeled | index($key) == null)))) as $unlisted |
        ([$rules[]] | add // 0) as $registered |
        (if ($result.rule_counts | type) == "object" and ($result.alerts_opened | type) == "number"
            and $result.alerts_opened >= $registered then $result.alerts_opened - $registered else null end) as $unregistered |
        ($result.alert_expectations.verdict) as $verdict |
        {name:$name,
         verdict:(if $verdict == "failed" then "failed"
                  elif $verdict != "passed" or $status != 0 or ($strict and $unregistered == null) then "inconclusive"
                  elif $strict and (($unlisted | length) > 0 or $unregistered > 0) then "failed"
                  else "passed" end),
         unlisted_rule_counts:$unlisted, unregistered_alerts:$unregistered, summary:$result}
    ')")
done < <(jq -c '.cases[]' <<< "$validated")

report=$(printf '%s\n' "${results[@]}" | jq -cs --argjson strict "$strict" '{
    record_type:"capture_replay_suite", strict:$strict, total:length,
    passed:([.[] | select(.verdict == "passed")] | length),
    failed:([.[] | select(.verdict == "failed")] | length),
    inconclusive:([.[] | select(.verdict == "inconclusive")] | length), cases:.
}')
printf '%s\n' "$report"
jq -e '.failed == 0 and .inconclusive == 0' <<< "$report" >/dev/null
