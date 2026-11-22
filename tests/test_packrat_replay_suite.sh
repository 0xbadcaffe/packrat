#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
suite="$root/scripts/packrat-replay-suite.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
manifest="$scratch/suite.json"
export PACKRAT_TEST_DIRECTORY="$scratch"
touch -- "$scratch/benign fixture.pcap" "$scratch/changed.pcap" "$scratch/partial.pcap"
touch -- "$scratch/unlisted.pcap" "$scratch/unregistered.pcap"
touch -- "$scratch/counts.pcap"
touch -- "$scratch/evidence.pcap"

packrat-analyze() {
    local verdict opened=0 rules='{}'
    local checks='[]' frames='[]'
    case ${*: -1} in
        "$PACKRAT_TEST_DIRECTORY/benign fixture.pcap")
            [[ $# == 4 && $1 == --expect-alert && $2 == scan.horizontal=0 && $3 == -- ]] || return 2
            verdict=passed
            case ${PACKRAT_TEST_CANDIDATE:-} in
                append) printf '%s\n' growth >>"${*: -1}" ;;
                replace) mv -- "$PACKRAT_TEST_DIRECTORY/next.pcap" "${*: -1}" ;;
            esac
            ;;
        "$PACKRAT_TEST_DIRECTORY/changed.pcap")
            [[ $# == 4 && $1 == --expect-alert-frame && $2 == scan.horizontal=12 && $3 == -- ]] || return 2
            verdict=failed
            frames='[{"rule_id":"scan.horizontal","missing_frames":[12],"unexpected_openings":1}]'
            ;;
        "$PACKRAT_TEST_DIRECTORY/counts.pcap")
            verdict=failed
            checks='[{"rule_id":"scan.horizontal","expected":0,"observed":2},
                {"rule_id":"scan.vertical","expected":2,"observed":1}]'
            ;;
        "$PACKRAT_TEST_DIRECTORY/evidence.pcap")
            [[ $# == 4 && $1 == --expect-alert-frame && $2 == scan.horizontal=12 && $3 == -- ]] || return 2
            verdict=passed; opened=1; rules='{"scan.horizontal":1}'
            local evidence='{"type":"alert","schema_version":1,"alert":{"hit_count":1,"packet_no":12,
                "first_packet":12,"last_packet":12,"packet_refs":[9,2,9],"provenance":{"rule_id":"scan.horizontal"}}}'
            case ${PACKRAT_TEST_EVIDENCE:-normal} in
                missing) : ;;
                duplicate) printf '%s\n' "$evidence" "$evidence" ;;
                changed) jq -c '.alert.packet_refs = [2,8]' <<< "$evidence" ;;
                normal) printf '%s\n' "$evidence" ;;
            esac
            jq -c '.alert.hit_count = 2 | .alert.packet_refs = [1,2,5]' <<< "$evidence"
            ;;
        "$PACKRAT_TEST_DIRECTORY/partial.pcap") verdict=inconclusive ;;
        "$PACKRAT_TEST_DIRECTORY/unlisted.pcap") verdict=passed; opened=1; rules='{"scan.vertical":1}' ;;
        "$PACKRAT_TEST_DIRECTORY/unregistered.pcap") verdict=passed; opened=1 ;;
        *) return 2 ;;
    esac
    printf '%s\n' '{"type":"alert","payload":"not in the suite report"}'
    jq -cn --arg verdict "$verdict" --argjson opened "$opened" --argjson rules "$rules" \
        --argjson snapshots "${PACKRAT_TEST_SNAPSHOTS:-null}" \
        --argjson checks "$checks" --argjson frames "$frames" '
        {type:"summary",packets:20,alerts_opened:$opened,alert_snapshots:$snapshots,rule_counts:$rules,
            alert_expectations:{verdict:$verdict,checks:$checks,frame_checks:$frames}}
    '
    [[ $verdict == passed ]]
}
export -f packrat-analyze

packrat-baseline() {
    [[ $# == 4 && $1 == --expect-alert && $2 == scan.horizontal=0 && $3 == -- ]] || return 2
    case $4 in
        "$PACKRAT_TEST_DIRECTORY/benign fixture.pcap"|"$PACKRAT_TEST_DIRECTORY/unlisted.pcap") ;;
        *) return 2 ;;
    esac
    case ${PACKRAT_TEST_BASELINE:-} in
        unstable) printf '%s\n' changed >>"${*: -1}" ;;
        unavailable) return 2 ;;
        record) touch -- "$PACKRAT_TEST_DIRECTORY/baseline-called" ;;
    esac
    printf '%s\n' '{"type":"summary","alerts_opened":1,"rule_counts":{"scan.horizontal":1},
        "alert_expectations":{"verdict":"failed","checks":[{"rule_id":"scan.horizontal","expected":0,"observed":1}]}}' |
        jq -c .
    return 1
}
export -f packrat-baseline

sample='{"version":1,"cases":[
    {"name":"benign","capture":"benign fixture.pcap","expect_counts":{"scan.horizontal":0}},
    {"name":"changed","capture":"changed.pcap","opening_frames":{"scan.horizontal":[12]}},
    {"name":"partial","capture":"partial.pcap","expect_counts":{"scan.horizontal":0}},
    {"name":"missing","capture":"missing.pcap","expect_counts":{"scan.horizontal":0}}]}'
printf '%s\n' "$sample" >"$manifest"
status=0
result=$(bash "$suite" "$manifest") || status=$?
[[ $status == 1 ]]
jq -e '
    .total == 4 and .passed == 1 and .failed == 1 and .inconclusive == 2
    and ([.cases[].verdict] == ["passed","failed","inconclusive","inconclusive"])
    and .score == {scored_cases:2,missed_opening_frames:1,unexpected_openings:1,count_deficit:0,count_surplus:0}
    and .cases[2].score == null and .cases[3].score == null
    and .cases[3].summary == null and (tostring | contains("not in the suite report") | not)
' <<< "$result" >/dev/null

jq -c '.cases = [.cases[0]]' <<< "$sample" >"$manifest"
bash "$suite" "$manifest" | jq -e '.total == 1 and .passed == 1' >/dev/null
(
    # shellcheck disable=SC2329 # Exported to the replay script.
    stat() {
        [[ $# == 5 && $1 == -L && $2 == -f && $3 == '%d:%i:%z:%Fm:%Fc' && $4 == -- ]] || return 1
        command stat -L --format='%d:%i:%s:%y:%z' -- "$5"
    }
    export -f stat
    bash "$suite" "$manifest" | jq -e '.passed == 1' >/dev/null
    status=0
    result=$(PACKRAT_TEST_CANDIDATE=append bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e '.inconclusive == 1 and .cases[0].capture_check == "unstable"' <<< "$result" >/dev/null
)
for mode in append replace; do
    cp -- "$scratch/benign fixture.pcap" "$scratch/next.pcap"
    status=0
    result=$(PACKRAT_TEST_CANDIDATE="$mode" bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e '.inconclusive == 1 and .score.scored_cases == 0 and
        (.cases[0] | .capture_check == "unstable" and .score == null and
         .summary.alert_expectations.verdict == "passed")' <<< "$result" >/dev/null
done
status=0
result=$(PACKRAT_TEST_CANDIDATE=append PACKRAT_TEST_BASELINE=record PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline \
    bash "$suite" "$manifest") || status=$?
[[ $status == 1 && ! -e $scratch/baseline-called ]]
jq -e '.inconclusive == 1 and .comparable == 0 and
    (.cases[0] | .comparison == "capture_unstable" and .capture_check == "unstable" and .baseline == null)' \
    <<< "$result" >/dev/null
PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline bash "$suite" "$manifest" |
    jq -e '.comparable == 1 and .passed == 1 and .cases[0].baseline.verdict == "failed"
        and .cases[0].comparison == "comparable" and .cases[0].delta.alerts_opened == -1
        and .cases[0].delta.count_surplus == -1 and .cases[0].delta.alert_snapshots == null
        and .cases[0].delta.rule_openings == {"scan.horizontal":-1}' >/dev/null

shifted="$scratch/shifted.json"
jq -c '.cases[0].capture = "unlisted.pcap"' "$manifest" >"$shifted"
PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline bash "$suite" "$shifted" |
    jq -e '.comparable == 1 and .cases[0].delta.alerts_opened == 0
        and .cases[0].delta.unregistered_alerts == 0
        and .cases[0].delta.rule_openings == {"scan.horizontal":-1,"scan.vertical":1}' >/dev/null
for mode in unstable unavailable; do
    status=0
    result=$(PACKRAT_TEST_BASELINE="$mode" PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline \
        bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e --arg mode "$mode" '
        .comparable == 0 and (.cases[0] | (.delta == null)
          and if $mode == "unstable" then .comparison == "capture_unstable" and .score == null
              else .comparison == "inconclusive" and .verdict == "passed" end)
    ' <<< "$result" >/dev/null
done

evidence_case='{"version":1,"cases":[{"name":"evidence","capture":"evidence.pcap",
    "opening_frames":{"scan.horizontal":[12]},
    "opening_evidence":[{"rule_id":"scan.horizontal","opening_frame":12,"frames":[12,2,9]}]}]}'
printf '%s\n' "$evidence_case" >"$manifest"
bash "$suite" "$manifest" | jq -e '
    .passed == 1 and .cases[0].evidence_checks[0] == {
        rule_id:"scan.horizontal",opening_frame:12,expected_frames:[2,9,12],observed_frames:[2,9,12],
        matching_openings:1,passed:true
    }' >/dev/null
for sample_type in changed missing duplicate; do
    status=0
    result=$(PACKRAT_TEST_EVIDENCE="$sample_type" bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e --arg sample "$sample_type" '.failed == 1 and (.cases[0].evidence_checks[0] |
        .passed == false and (if $sample == "changed" then .observed_frames == [2,8,12] and .matching_openings == 1
            elif $sample == "missing" then .observed_frames == null and .matching_openings == 0
            else .observed_frames == null and .matching_openings == 2 end))' <<< "$result" >/dev/null
done
for change in 'del(.cases[0].opening_frames)' '.cases[0].opening_evidence[0].frames = [2,9]' \
    '.cases[0].opening_evidence[0].frames = [2,12,2]' '.cases[0].opening_evidence |= . + .'; do
    jq -c "$change" <<< "$evidence_case" >"$manifest"
    status=0
    bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
status=0
PACKRAT_REPLAY_BASELINE_ANALYZER=/missing/baseline bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

jq -c '.cases = [(.cases[0] | .expect_snapshots = 0)]' <<< "$sample" >"$manifest"
PACKRAT_TEST_SNAPSHOTS=0 bash "$suite" "$manifest" | jq -e '.passed == 1' >/dev/null
for snapshots in 1 null; do
    status=0
    result=$(PACKRAT_TEST_SNAPSHOTS="$snapshots" bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e --argjson observed "$snapshots" '
        .cases[0].snapshot_check == {expected:0,observed:$observed}
        and (if $observed == null then .inconclusive == 1 else .failed == 1 end)
    ' <<< "$result" >/dev/null
done

jq -c '.cases = [{name:"counts",capture:"counts.pcap",
                   expect_counts:{"scan.horizontal":0,"scan.vertical":2}}]' <<< "$sample" >"$manifest"
status=0
result=$(bash "$suite" "$manifest") || status=$?
[[ $status == 1 ]]
jq -e '.score == {scored_cases:1,missed_opening_frames:0,unexpected_openings:0,
                  count_deficit:1,count_surplus:2}' <<< "$result" >/dev/null

strict_sample=$(jq -c '.cases = [
    .cases[0],
    (.cases[0] | .name = "unlisted" | .capture = "unlisted.pcap"),
    (.cases[0] | .name = "unregistered" | .capture = "unregistered.pcap")]' <<< "$sample")
printf '%s\n' "$strict_sample" >"$manifest"
bash "$suite" "$manifest" | jq -e '
    .strict == false and .passed == 3
    and .cases[1].unlisted_rule_counts == {"scan.vertical":1}
    and .cases[2].unregistered_alerts == 1
' >/dev/null
jq -c '.strict = true' <<< "$strict_sample" >"$manifest"
status=0
result=$(bash "$suite" "$manifest") || status=$?
[[ $status == 1 ]]
jq -e '.strict == true and .passed == 1 and .failed == 2 and .inconclusive == 0' <<< "$result" >/dev/null

for invalid in '.version = 2' 'del(.cases[0].expect_counts)' '.strict = "true"' \
    '.cases[0].expect_snapshots = false' '.cases[0].expect_snapshots = -1' \
    '.cases[1].opening_frames["scan.horizontal"] = [12,12]' \
    '.cases[1].name = .cases[0].name'; do
    jq -c "$invalid" <<< "$sample" >"$manifest"
    status=0
    bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
printf '%s\n' 'Packrat replay suite tests passed'
