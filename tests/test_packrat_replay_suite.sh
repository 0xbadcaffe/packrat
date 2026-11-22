#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
suite="$root/scripts/packrat-replay-suite.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
manifest="$scratch/suite.json"
export PACKRAT_TEST_DIRECTORY="$scratch"
touch -- "$scratch/benign fixture.pcap" "$scratch/changed.pcap" "$scratch/partial.pcap"

packrat-analyze() {
    local verdict
    case ${*: -1} in
        "$PACKRAT_TEST_DIRECTORY/benign fixture.pcap")
            [[ $# == 4 && $1 == --expect-alert && $2 == scan.horizontal=0 && $3 == -- ]] || return 2
            verdict=passed
            ;;
        "$PACKRAT_TEST_DIRECTORY/changed.pcap")
            [[ $# == 4 && $1 == --expect-alert-frame && $2 == scan.horizontal=12 && $3 == -- ]] || return 2
            verdict=failed
            ;;
        "$PACKRAT_TEST_DIRECTORY/partial.pcap") verdict=inconclusive ;;
        *) return 2 ;;
    esac
    printf '%s\n' '{"type":"alert","payload":"not in the suite report"}'
    jq -cn --arg verdict "$verdict" '{type:"summary",packets:20,alert_expectations:{verdict:$verdict}}'
    [[ $verdict == passed ]]
}
export -f packrat-analyze

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
    and .cases[3].summary == null and (tostring | contains("not in the suite report") | not)
' <<< "$result" >/dev/null

jq -c '.cases = [.cases[0]]' <<< "$sample" >"$manifest"
bash "$suite" "$manifest" | jq -e '.total == 1 and .passed == 1' >/dev/null

for invalid in '.version = 2' 'del(.cases[0].expect_counts)' \
    '.cases[1].opening_frames["scan.horizontal"] = [12,12]' \
    '.cases[1].name = .cases[0].name'; do
    jq -c "$invalid" <<< "$sample" >"$manifest"
    status=0
    bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
printf '%s\n' 'Packrat replay suite tests passed'
