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

packrat-analyze() {
    local verdict opened=0 rules='{}'
    local checks='[]' frames='[]'
    case ${*: -1} in
        "$PACKRAT_TEST_DIRECTORY/benign fixture.pcap")
            [[ $# == 4 && $1 == --expect-alert && $2 == scan.horizontal=0 && $3 == -- ]] || return 2
            verdict=passed
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
        "$PACKRAT_TEST_DIRECTORY/partial.pcap") verdict=inconclusive ;;
        "$PACKRAT_TEST_DIRECTORY/unlisted.pcap") verdict=passed; opened=1; rules='{"scan.vertical":1}' ;;
        "$PACKRAT_TEST_DIRECTORY/unregistered.pcap") verdict=passed; opened=1 ;;
        *) return 2 ;;
    esac
    printf '%s\n' '{"type":"alert","payload":"not in the suite report"}'
    jq -cn --arg verdict "$verdict" --argjson opened "$opened" --argjson rules "$rules" \
        --argjson checks "$checks" --argjson frames "$frames" '
        {type:"summary",packets:20,alerts_opened:$opened,rule_counts:$rules,
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
status=0
PACKRAT_REPLAY_BASELINE_ANALYZER=/missing/baseline bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

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
    '.cases[1].opening_frames["scan.horizontal"] = [12,12]' \
    '.cases[1].name = .cases[0].name'; do
    jq -c "$invalid" <<< "$sample" >"$manifest"
    status=0
    bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
printf '%s\n' 'Packrat replay suite tests passed'
