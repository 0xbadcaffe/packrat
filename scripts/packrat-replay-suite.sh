#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: packrat-replay-suite MANIFEST.json' \
        'Replay up to 32 labeled captures. Relative capture paths are relative to the manifest.' \
        'Example: {"version":1,"cases":[{"name":"baseline","capture":"baseline.pcapng","expect_counts":{"scan.horizontal":0}}]}' \
        'Use opening_frames to label exact frames, for example {"scan.horizontal":[12]}.' \
        'Use opening_evidence to check exact supporting frames: [{"rule_id":"scan.horizontal","opening_frame":12,"frames":[2,12]}].' \
        'An opening_evidence entry may include classification with severity, confidence, and/or revision.' \
        'Use expect_snapshots to also check the total number of openings and updates in a case.' \
        'Set "allow_truncated":true only for a case intentionally replaying partial frames.' \
        'Use "single_tag_interfaces":["access1"] to apply an exact interface-name VLAN policy during a case.' \
        'Set "strict":true to fail a case if any unlisted rule or unregistered finding opens.' \
        'Reports score openings, snapshots, strict-policy violations, cited evidence, and classification separately.' \
        'Cases without verified scoring inputs are not scored.' \
        'Known DNS capacity declines make affected DNS labels and strict cases inconclusive; older analyzers may not report counters.' \
        'TCP stream evictions make stream-dependent labels and strict cases inconclusive, independently of frame coverage.' \
        'A capture that changes during replay is marked inconclusive, even without a baseline.' \
        'Set PACKRAT_REPLAY_BASELINE_ANALYZER to compare analyzers; deltas require matching packet coverage.' \
        'Partial coverage requires frame fingerprints from both analyzers.'
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
    def classification:
        type == "object" and length > 0 and all(keys[]; IN("severity","confidence","revision"))
        and ((has("severity") | not) or (.severity | IN("CRITICAL","HIGH","MEDIUM","LOW","INFO")))
        and ((has("confidence") | not) or (.confidence | IN("heuristic","correlated","direct_observation")))
        and ((has("revision") | not) or (.revision | frame and . <= 65535));
    def valid_case:
        . as $case |
        type == "object" and (.name | text(128)) and (.capture | text(1024))
        and ((has("expect_snapshots") | not) or (.expect_snapshots | count))
        and ((has("allow_truncated") | not) or (.allow_truncated | type == "boolean"))
        and ((if has("single_tag_interfaces") then .single_tag_interfaces else [] end)
            | type == "array" and length <= 32 and (unique | length) == length
            and all(.[]; type == "string" and length <= 128 and test("\\A[ -~]+\\z") and (startswith("-") | not)))
        and ((.expect_counts // {}) | type == "object" and rules and all(.[]; count))
        and ((.opening_frames // {}) | type == "object" and rules and all(.[]; frame_list))
        and ((if has("opening_evidence") then .opening_evidence else [] end)
            | type == "array" and length <= 64
            and all(.[]; type == "object" and (.rule_id | type == "string")
                and (.opening_frame | frame) and (.frames | frame_list and length <= 131)
                and ((has("classification") | not) or (.classification | classification))
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
                def dns_capacity: objects |
                    {query_key_declines,query_candidate_declines,nxdomain_client_declines,external_resolver_pair_declines}
                    | select(all(.[]; ordinal));
                def frames:
                    if (.packet_refs | type == "array" and length <= 128 and all(.[]; ordinal)) and
                       all([.first_packet,.packet_no,.last_packet][]; ordinal)
                    then [.first_packet,.packet_no,.last_packet,.packet_refs[]] | map(select(. > 0)) | unique
                    else null end;
                def classification:
                    {severity:(.severity | if IN("CRITICAL","HIGH","MEDIUM","LOW","INFO") then . else null end),
                     confidence:(.provenance.confidence | if IN("heuristic","correlated","direct_observation") then . else null end),
                     revision:(.provenance.revision | if ordinal and . >= 1 and . <= 65535 then . else null end)};
                ($label.opening_evidence // [] | map(key(.rule_id; .opening_frame))) as $keys |
                reduce inputs as $row ({summary:null, summaries:0, evidence:{}};
                if $row.type == "summary" then
                    .summaries += 1 | .summary = ($row | {packets,analyzed,skipped,truncated_frames,allow_truncated,
                        frame_coverage_sha256_v1,alerts_opened,alert_snapshots,rule_counts,alert_expectations}
                        + (if has("dns_capacity") then {dns_capacity:(.dns_capacity | dns_capacity // null)} else {} end)
                        + (if has("evicted_streams") then {evicted_streams:(.evicted_streams | if ordinal then . else null end)} else {} end))
                elif ($keys | length) > 0 and $row.type == "alert" and $row.schema_version == 1
                    and (if $row | has("opening") then $row.opening == true else $row.alert.hit_count == 1 end)
                    and ($row.alert.provenance.rule_id | type == "string")
                    and ($row.alert.packet_no | ordinal)
                then key($row.alert.provenance.rule_id; $row.alert.packet_no) as $key
                     | if ($keys | index($key)) != null then
                         .evidence[$key] |= if . == null then {matches:1, frames:($row.alert | frames), classification:($row.alert | classification)}
                                           else {matches:(.matches + 1), frames:null} end
                       else . end
                else . end)') || status=$?
    fi
    jq -cn --arg name "$name" --argjson replay "${replay:-null}" --argjson status "$status" \
        --argjson strict "$strict" --argjson label "$label" '
        def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
        $replay.summary as $result |
        (($label.expect_counts // {}) + ($label.opening_frames // {}) | keys) as $labeled |
        ($result.rule_counts | if type == "object" and all(.[]; count) then . else null end) as $rules |
        (($rules // {}) | with_entries(select(.key as $key | .value > 0 and ($labeled | index($key) == null)))) as $unlisted |
        ([$rules[]?] | add // 0) as $registered |
        (if $rules != null and ($result.alerts_opened | count) and $result.alerts_opened >= $registered
            then $result.alerts_opened - $registered else null end) as $unregistered |
        ($result.alert_expectations.verdict) as $evaluation |
        (if ($result | has("dns_capacity") | not) then "not_reported"
         elif $result.dns_capacity == null then "unverified"
         elif any($result.dns_capacity[]; . > 0) then "declines" else "clear" end) as $dns_capacity_status |
        (any($labeled[]; startswith("dns."))) as $dns_labeled |
        ($result.alert_expectations.dns_capacity_limited_rules
            | if type == "array" and length <= 64 and all(.[]; . as $id | $labeled | index($id) != null)
              then . else null end) as $limited_rules |
        (if $dns_capacity_status == "unverified" then $strict or $dns_labeled
         elif $dns_capacity_status == "declines" then $strict or
            (if $limited_rules == null then $dns_labeled else ($limited_rules | length) > 0 end)
         else false end) as $dns_gate |
        (if ($result | has("evicted_streams") | not) then "not_reported"
         elif $result.evicted_streams == null then "unverified"
         elif $result.evicted_streams > 0 then "evictions" else "clear" end) as $tcp_stream_cache_status |
        (any($labeled[]; startswith("dns.") or startswith("tls.") or startswith("industrial.")
                         or . == "http.unauthorized_burst")) as $possibly_stream_labeled |
        ($result.alert_expectations.tcp_stream_limited_rules
            | if type == "array" and length <= 64 and all(.[]; . as $id | $labeled | index($id) != null)
              then . else null end) as $stream_limited_rules |
        (if $tcp_stream_cache_status == "unverified" then $strict or $possibly_stream_labeled
         elif $tcp_stream_cache_status == "evictions" then $strict or
            (if $stream_limited_rules == null then $possibly_stream_labeled else ($stream_limited_rules | length) > 0 end)
         else false end) as $tcp_gate |
        (if $label | has("expect_snapshots") then
            {expected:$label.expect_snapshots, observed:$result.alert_snapshots}
         else null end) as $snapshot_check |
        ($snapshot_check == null or ($snapshot_check.observed | count)) as $snapshots_verified |
        ($snapshots_verified and ($strict | not or $unregistered != null)) as $score_verified |
        (if $snapshot_check != null and $snapshots_verified
            then $snapshot_check.observed - $snapshot_check.expected else 0 end) as $snapshot_delta |
        ($label.opening_evidence // [] | map(
            . as $spec | ($replay.evidence[$spec.rule_id + ":" + ($spec.opening_frame | tostring)]) as $match
            | ($spec.frames | sort) as $expected
            | {rule_id, opening_frame, expected_frames:$expected, observed_frames:$match.frames,
               matching_openings:($match.matches // 0),
               passed:($match.matches == 1 and $match.frames == $expected)}
            | if $spec | has("classification") then
                ($spec.classification | keys) as $keys
                | ($match.classification | if . == null then null else with_entries(select(.key as $key | $keys | index($key) != null)) end) as $observed
                | .classification = {expected:$spec.classification,observed:$observed,passed:($observed == $spec.classification)}
                | .passed = (.passed and .classification.passed)
              else . end
        )) as $evidence_checks |
        (if $status > 1 or $replay.summaries != 1 or $dns_gate or $tcp_gate then "inconclusive"
         elif $evaluation == "failed" then "failed"
         elif $evaluation != "passed" or $status != 0 or ($score_verified | not) then "inconclusive"
         elif $snapshot_delta != 0 then "failed"
         elif any($evidence_checks[]; .passed | not) then "failed"
         elif $strict and (($unlisted | length) > 0 or $unregistered > 0) then "failed"
         else "passed" end) as $verdict |
        ($result.alert_expectations.frame_checks // []) as $frames |
        ($result.alert_expectations.checks // [] |
            map(select(.rule_id as $id | all($frames[]; .rule_id != $id)))) as $counts |
        {name:$name, verdict:$verdict,
         dns_capacity_status:$dns_capacity_status,
         tcp_stream_cache_status:$tcp_stream_cache_status,
         unlisted_rule_counts:$unlisted, unregistered_alerts:$unregistered, summary:$result,
         snapshot_check:$snapshot_check,
         score:(if $verdict == "inconclusive" or ($score_verified | not) then null else {
             missed_opening_frames: ([$frames[].missing_frames | length] | add // 0),
             unexpected_openings: ([$frames[].unexpected_openings] | add // 0),
             count_deficit: ([$counts[] | [.expected - .observed, 0] | max] | add // 0),
             count_surplus: ([$counts[] | [.observed - .expected, 0] | max] | add // 0),
             snapshot_deficit: ([-$snapshot_delta, 0] | max),
             snapshot_surplus: ([$snapshot_delta, 0] | max),
             strict_unlisted_openings: (if $strict then ([$unlisted[]] | add // 0) else 0 end),
             strict_unregistered_openings: (if $strict then $unregistered else 0 end),
             evidence_opening_mismatches: ([$evidence_checks[] | select(.matching_openings != 1)] | length),
             evidence_frame_mismatches: ([$evidence_checks[] | select(.matching_openings == 1 and .observed_frames != .expected_frames)] | length),
             classification_mismatches: ([$evidence_checks[] | select(.matching_openings == 1 and .classification.passed == false)] | length)
         } end)}
        | if ($evidence_checks | length) > 0 then . + {evidence_checks:$evidence_checks} else . end
    '
}

gnu_stamp='%d:%i:%s:%y:%z'
bsd_stamp='%d:%i:%z:%Fm:%Fc'
stat_style=unavailable
if stat -L --format="$gnu_stamp" -- "$base" >/dev/null 2>&1; then
    stat_style=gnu
elif stat -L -f "$bsd_stamp" -- "$base" >/dev/null 2>&1; then
    stat_style=bsd
fi

capture_stamp() {
    case $stat_style in
        gnu) stat -L --format="$gnu_stamp" -- "$capture" 2>/dev/null ;;
        bsd) stat -L -f "$bsd_stamp" -- "$capture" 2>/dev/null ;;
        *) return 1 ;;
    esac
}

results=()
while IFS= read -r label; do
    name=$(jq -er '.name' <<< "$label")
    capture=$(jq -er '.capture' <<< "$label")
    if [[ $capture != /* ]]; then capture="$base/$capture"; fi
    mapfile -t options < <(jq -r '
        (if .allow_truncated == true then "--allow-truncated" else empty end),
        (.single_tag_interfaces[]? | "--single-tag-interface", .),
        (.expect_counts // {} | to_entries[] | "--expect-alert", (.key + "=" + (.value | floor | tostring))),
        (.opening_frames // {} | to_entries[] | .key as $id | .value[] |
            "--expect-alert-frame", ($id + "=" + (floor | tostring)))
    ' <<< "$label")

    stamp=$(capture_stamp) || stamp=
    candidate=$(replay_case packrat-analyze)
    after_candidate=$(capture_stamp) || after_candidate=
    if [[ -z $stamp || $stamp != "$after_candidate" ]]; then
        candidate=$(jq -c --arg before "$stamp" --arg after "$after_candidate" --arg baseline "$baseline" '
            .verdict = "inconclusive" | .score = null
            | .capture_check = (if $before == "" and $after == "" then "unavailable" else "unstable" end)
            | if $baseline == "" then . else .comparison = "capture_unstable" end
        ' <<< "$candidate")
    elif [[ -n $baseline ]]; then
        reference=$(replay_case "$baseline")
        after=$(capture_stamp) || after=
        candidate=$(jq -c --argjson reference "$reference" --arg before "$stamp" --arg after "$after" '
            def count: type == "number" and . >= 0 and . <= 9007199254740991 and floor == .;
            def packet_coverage:
                .summary | {packets,analyzed,skipped,truncated_frames} | if all(.[]; count)
                    and .packets > 0 and .analyzed + .skipped == .packets and .truncated_frames <= .packets
                then . else null end;
            def frame_fingerprint:
                .summary.frame_coverage_sha256_v1;
            def valid_fingerprint:
                type == "string" and test("\\A[0-9a-f]{64}\\z");
            def difference($candidate; $baseline):
                if ($candidate | count) and ($baseline | count)
                then $candidate - $baseline else null end;
            def rule_differences($candidate; $baseline):
                def valid_rules: type == "object" and all(.[]; count);
                if ($candidate | valid_rules) and ($baseline | valid_rules) then
                    ($candidate + $baseline | keys) as $rules
                    | reduce $rules[] as $rule ({};
                        (($candidate[$rule] // 0) - ($baseline[$rule] // 0)) as $delta
                        | if $delta == 0 then . else .[$rule] = $delta end)
                else null end;
            (packet_coverage) as $candidate_coverage | ($reference | packet_coverage) as $baseline_coverage
            | frame_fingerprint as $candidate_frames | ($reference | frame_fingerprint) as $baseline_frames
            | .baseline = $reference
            | if $before == "" or $before != $after then
                .verdict = "inconclusive" | .score = null | .comparison = "capture_unstable" | .capture_check = "unstable"
              elif .score == null or $reference.score == null then
                .comparison = "inconclusive"
              elif $candidate_coverage == null or $baseline_coverage == null then
                .comparison = "replay_coverage_unverified"
              elif $candidate_coverage != $baseline_coverage then
                .comparison = "replay_coverage_mismatch"
              elif ($candidate_frames | valid_fingerprint) and ($baseline_frames | valid_fingerprint) then
                if $candidate_frames != $baseline_frames then .comparison = "replay_coverage_mismatch" else . end
              elif $candidate_coverage.skipped != 0 or $candidate_coverage.truncated_frames != 0
                   or any([$candidate_frames, $baseline_frames][]; . != null and (valid_fingerprint | not)) then
                .comparison = "replay_coverage_unverified"
              else . end
            | if .comparison != null then .
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
        count_surplus: ([$scores[].count_surplus] | add // 0),
        snapshot_deficit: ([$scores[].snapshot_deficit] | add // 0),
        snapshot_surplus: ([$scores[].snapshot_surplus] | add // 0),
        strict_unlisted_openings: ([$scores[].strict_unlisted_openings] | add // 0),
        strict_unregistered_openings: ([$scores[].strict_unregistered_openings] | add // 0),
        evidence_opening_mismatches: ([$scores[].evidence_opening_mismatches] | add // 0),
        evidence_frame_mismatches: ([$scores[].evidence_frame_mismatches] | add // 0),
        classification_mismatches: ([$scores[].classification_mismatches] | add // 0)
    }, cases:.
} | if $baseline == "" then . else
    . + {comparable: ([.cases[] | select(.comparison == "comparable")] | length)}
end')
printf '%s\n' "$report"
jq -e '.failed == 0 and .inconclusive == 0 and (.comparable // .total) == .total' <<< "$report" >/dev/null
