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
touch -- "$scratch/dns.pcap"
touch -- "$scratch/tcp.pcap"

packrat-analyze() {
    local verdict opened=0 rules='{}' summary
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
                "first_packet":12,"last_packet":12,"packet_refs":[9,2,9],"severity":"MEDIUM",
                "provenance":{"rule_id":"scan.horizontal","revision":14,"confidence":"heuristic"}}}'
            case ${PACKRAT_TEST_EVIDENCE:-normal} in
                missing) : ;;
                duplicate) printf '%s\n' "$evidence" "$evidence" ;;
                changed) jq -c '.alert.packet_refs = [2,8]' <<< "$evidence" ;;
                normal) printf '%s\n' "$evidence" ;;
            esac
            jq -c '.alert.hit_count = 2 | .alert.packet_refs = [1,2,5]' <<< "$evidence"
            ;;
        "$PACKRAT_TEST_DIRECTORY/partial.pcap") verdict=inconclusive ;;
        "$PACKRAT_TEST_DIRECTORY/dns.pcap")
            [[ $# == 4 && $1 == --expect-alert && $2 == dns.unmatched_response=0 && $3 == -- ]] || return 2
            verdict=passed
            ;;
        "$PACKRAT_TEST_DIRECTORY/tcp.pcap")
            [[ $# == 4 && $1 == --expect-alert && $2 == http.unauthorized_burst=0 && $3 == -- ]] || return 2
            verdict=passed
            ;;
        "$PACKRAT_TEST_DIRECTORY/unlisted.pcap") verdict=passed; opened=1; rules='{"scan.vertical":1}' ;;
        "$PACKRAT_TEST_DIRECTORY/unregistered.pcap") verdict=passed; opened=1 ;;
        *) return 2 ;;
    esac
    if [[ ${PACKRAT_TEST_CANDIDATE:-} == invalid_rule_counts ]]; then
        rules='{"scan.horizontal":"bad"}'
    fi
    printf '%s\n' '{"type":"alert","payload":"not in the suite report"}'
    summary=$(jq -cn --arg verdict "$verdict" --argjson opened "$opened" --argjson rules "$rules" \
        --argjson snapshots "${PACKRAT_TEST_SNAPSHOTS:-null}" \
        --argjson checks "$checks" --argjson frames "$frames" '
        {type:"summary",packets:20,analyzed:20,skipped:0,truncated_frames:0,alerts_opened:$opened,alert_snapshots:$snapshots,rule_counts:$rules,
            alert_expectations:{verdict:$verdict,checks:$checks,frame_checks:$frames}}
    ')
    if [[ ${PACKRAT_TEST_CANDIDATE:-} == partial_coverage ]]; then
        summary=$(jq -c '.truncated_frames = 1 | .frame_coverage_sha256_v1 = ("a" * 64)' <<< "$summary")
    fi
    if [[ -v PACKRAT_TEST_DNS_CAPACITY ]]; then
        summary=$(jq -c --argjson capacity "$PACKRAT_TEST_DNS_CAPACITY" '.dns_capacity=$capacity' <<< "$summary")
    fi
    if [[ -v PACKRAT_TEST_TCP_EVICTIONS ]]; then
        summary=$(jq -c --argjson evictions "$PACKRAT_TEST_TCP_EVICTIONS" '.evicted_streams=$evictions' <<< "$summary")
    fi
    if [[ -v PACKRAT_TEST_TCP_RULES ]]; then
        summary=$(jq -c --argjson rules "$PACKRAT_TEST_TCP_RULES" \
            '.alert_expectations.tcp_stream_limited_rules=$rules' <<< "$summary")
    fi
    printf '%s\n' "$summary"
    case ${PACKRAT_TEST_CANDIDATE:-} in
        duplicate_summary) printf '%s\n' "$summary" ;;
        interrupted) return 2 ;;
    esac
    [[ $verdict == passed ]]
}
export -f packrat-analyze

packrat-baseline() {
    if [[ ${*: -1} == "$PACKRAT_TEST_DIRECTORY/evidence.pcap" ]]; then
        PACKRAT_TEST_EVIDENCE=changed packrat-analyze "$@"
        return
    fi
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
    printf '%s\n' '{"type":"summary","packets":20,"analyzed":20,"skipped":0,"truncated_frames":0,"alerts_opened":1,"rule_counts":{"scan.horizontal":1},
        "alert_expectations":{"verdict":"failed","checks":[{"rule_id":"scan.horizontal","expected":0,"observed":1}]}}' |
        jq -c --arg mode "${PACKRAT_TEST_BASELINE:-}" --argjson snapshots "${PACKRAT_TEST_BASELINE_SNAPSHOTS:-null}" '
            .alert_snapshots = $snapshots
            | if $mode == "different_coverage" then .analyzed -= 1 | .skipped += 1
            elif $mode == "unverified_coverage" then del(.truncated_frames)
            elif $mode == "invalid_coverage" then .analyzed = 19
            elif $mode == "same_frames" then .truncated_frames = 1 | .frame_coverage_sha256_v1 = ("a" * 64)
            elif $mode == "different_frames" then .truncated_frames = 1 | .frame_coverage_sha256_v1 = ("b" * 64)
            elif $mode == "legacy_partial" then .truncated_frames = 1
            elif $mode == "malformed_frames" then .truncated_frames = 1 | .frame_coverage_sha256_v1 = (("a" * 64) + "\n")
            else . end'
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
    and .score == {scored_cases:2,missed_opening_frames:1,unexpected_openings:1,count_deficit:0,count_surplus:0,
        evidence_opening_mismatches:0,evidence_frame_mismatches:0,classification_mismatches:0,
        snapshot_deficit:0,snapshot_surplus:0,strict_unlisted_openings:0,strict_unregistered_openings:0}
    and .cases[2].score == null and .cases[3].score == null
    and .cases[3].summary == null and (tostring | contains("not in the suite report") | not)
' <<< "$result" >/dev/null

jq -c '.cases = [.cases[0]]' <<< "$sample" >"$manifest"
bash "$suite" "$manifest" | jq -e '.total == 1 and .passed == 1 and .cases[0].dns_capacity_status=="not_reported"' >/dev/null
dns_capacity='{"query_key_declines":1,"query_candidate_declines":0,"nxdomain_client_declines":0,"external_resolver_pair_declines":0,"other":"private"}'
PACKRAT_TEST_DNS_CAPACITY="$dns_capacity" bash "$suite" "$manifest" | jq -e '
    .passed==1 and .cases[0].dns_capacity_status=="declines" and .cases[0].summary.dns_capacity.query_key_declines==1
    and (.cases[0].summary.dns_capacity | has("other") | not)' >/dev/null
jq '.strict=true' "$manifest" > "$scratch/dns-strict.json"
jq '.cases[0] |= (.capture="dns.pcap" | .expect_counts={"dns.unmatched_response":0})' "$manifest" > "$scratch/dns-labeled.json"
for case_manifest in "$scratch/dns-strict.json" "$scratch/dns-labeled.json"; do
    status=0
    result=$(PACKRAT_TEST_DNS_CAPACITY="$dns_capacity" bash "$suite" "$case_manifest") || status=$?
    [[ $status == 1 ]]
    jq -e '.inconclusive==1 and .cases[0].dns_capacity_status=="declines" and .cases[0].score==null' <<< "$result" >/dev/null
done
status=0
result=$(PACKRAT_TEST_DNS_CAPACITY='{"query_key_declines":"private"}' bash "$suite" "$scratch/dns-strict.json") || status=$?
[[ $status == 1 ]]
jq -e '.inconclusive==1 and .cases[0].dns_capacity_status=="unverified" and .cases[0].summary.dns_capacity==null' <<< "$result" >/dev/null
jq '.strict=true' "$manifest" > "$scratch/tcp-strict.json"
jq '.cases[0] |= (.capture="tcp.pcap" | .expect_counts={"http.unauthorized_burst":0})' \
    "$manifest" > "$scratch/tcp-labeled.json"
bash "$suite" "$scratch/tcp-strict.json" | jq -e '
    .passed==1 and .cases[0].tcp_stream_cache_status=="not_reported"' >/dev/null
PACKRAT_TEST_TCP_EVICTIONS=0 bash "$suite" "$scratch/tcp-labeled.json" | jq -e '
    .passed==1 and .cases[0].tcp_stream_cache_status=="clear" and .cases[0].summary.evicted_streams==0' >/dev/null
PACKRAT_TEST_TCP_EVICTIONS=3 bash "$suite" "$manifest" | jq -e '
    .passed==1 and .cases[0].tcp_stream_cache_status=="evictions" and .cases[0].summary.evicted_streams==3' >/dev/null
for case_manifest in "$scratch/tcp-strict.json" "$scratch/tcp-labeled.json"; do
    status=0
    result=$(PACKRAT_TEST_TCP_EVICTIONS=3 bash "$suite" "$case_manifest") || status=$?
    [[ $status == 1 ]]
    jq -e '.inconclusive==1 and .cases[0].tcp_stream_cache_status=="evictions"
        and .cases[0].score==null' <<< "$result" >/dev/null
done
for junk in '-1' '0.5' '"private"' '9007199254740992' 'null'; do
    status=0
    result=$(PACKRAT_TEST_TCP_EVICTIONS="$junk" bash "$suite" "$scratch/tcp-labeled.json") || status=$?
    [[ $status == 1 ]]
    jq -e '.inconclusive==1 and .cases[0].tcp_stream_cache_status=="unverified"
        and .cases[0].summary.evicted_streams==null' <<< "$result" >/dev/null
done
status=0
result=$(PACKRAT_TEST_TCP_EVICTIONS=3 PACKRAT_TEST_TCP_RULES='["http.unauthorized_burst"]' \
    bash "$suite" "$scratch/tcp-labeled.json") || status=$?
[[ $status == 1 ]]
jq -e '.inconclusive==1 and .score.scored_cases==0' <<< "$result" >/dev/null
for mode in duplicate_summary interrupted; do
    status=0
    result=$(PACKRAT_TEST_CANDIDATE="$mode" bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e '.inconclusive == 1 and .cases[0].score == null' <<< "$result" >/dev/null
done
scored_failure="$scratch/scored-failure.json"
jq -c '.cases = [.cases[1]]' <<< "$sample" > "$scored_failure"
status=0
result=$(PACKRAT_TEST_CANDIDATE=interrupted bash "$suite" "$scored_failure") || status=$?
[[ $status == 1 ]]
jq -e '.inconclusive == 1 and .failed == 0 and .cases[0].score == null' <<< "$result" >/dev/null
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
for mode in unstable unavailable different_coverage unverified_coverage invalid_coverage; do
    status=0
    result=$(PACKRAT_TEST_BASELINE="$mode" PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline \
        bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e --arg mode "$mode" '
        .comparable == 0 and (.cases[0] | (.delta == null)
          and if $mode == "unstable" then .comparison == "capture_unstable" and .score == null
              elif $mode == "unavailable" then .comparison == "inconclusive" and .verdict == "passed"
              elif $mode == "different_coverage" then .comparison == "replay_coverage_mismatch" and .verdict == "passed"
              else .comparison == "replay_coverage_unverified" and .verdict == "passed" end)
    ' <<< "$result" >/dev/null
done

for mode in same_frames different_frames legacy_partial malformed_frames; do
    status=0
    result=$(PACKRAT_TEST_CANDIDATE=partial_coverage PACKRAT_TEST_BASELINE="$mode" \
        PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline bash "$suite" "$manifest") || status=$?
    if [[ $mode == same_frames ]]; then [[ $status == 0 ]]; else [[ $status == 1 ]]; fi
    jq -e --arg mode "$mode" '
        .passed == 1 and (.cases[0] |
            .summary.truncated_frames == .baseline.summary.truncated_frames
            and if $mode == "same_frames" then .comparison == "comparable" and .delta.alerts_opened == -1
                elif $mode == "different_frames" then .comparison == "replay_coverage_mismatch" and .delta == null
                else .comparison == "replay_coverage_unverified" and .delta == null end)
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
classified=$(jq -c '.cases[0].opening_evidence[0].classification = {severity:"MEDIUM",confidence:"heuristic",revision:14}' <<< "$evidence_case")
printf '%s\n' "$classified" >"$manifest"
bash "$suite" "$manifest" | jq -e '
    .passed == 1 and (.cases[0].evidence_checks[0].classification |
    .passed and .observed == {severity:"MEDIUM",confidence:"heuristic",revision:14} and .expected == .observed)' >/dev/null
for mismatch in '.severity="HIGH"' '.severity="INFO"' '.confidence="correlated"' '.revision=15'; do
    jq -c ".cases[0].opening_evidence[0].classification |= ($mismatch)" <<< "$classified" > "$manifest"
    status=0
    result=$(bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e '.failed == 1 and .score.classification_mismatches == 1 and .score.evidence_frame_mismatches == 0
        and (.cases[0].evidence_checks[0] | (.classification.passed | not)
        and (.passed | not) and .expected_frames == .observed_frames)' <<< "$result" >/dev/null
done
for invalid_class in '{}' '{"revision":0}' '{"severity":"medium"}' '{"confidence":"guess"}' '{"unexpected":true}'; do
    jq -c --argjson classification "$invalid_class" '.cases[0].opening_evidence[0].classification = $classification' \
        <<< "$evidence_case" > "$manifest"
    status=0
    bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
printf '%s\n' "$evidence_case" >"$manifest"
for sample_type in changed missing duplicate; do
    status=0
    result=$(PACKRAT_TEST_EVIDENCE="$sample_type" bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e --arg sample "$sample_type" '.failed == 1
        and .score.evidence_frame_mismatches == (if $sample == "changed" then 1 else 0 end)
        and .score.evidence_opening_mismatches == (if $sample == "changed" then 0 else 1 end)
        and .score.classification_mismatches == 0 and (.cases[0].evidence_checks[0] |
        .passed == false and (if $sample == "changed" then .observed_frames == [2,8,12] and .matching_openings == 1
            elif $sample == "missing" then .observed_frames == null and .matching_openings == 0
            else .observed_frames == null and .matching_openings == 2 end))' <<< "$result" >/dev/null
done
PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline bash "$suite" "$manifest" | jq -e '
    .comparable == 1 and .cases[0].baseline.verdict == "failed"
    and (.cases[0].delta | .alerts_opened == 0 and .evidence_frame_mismatches == -1
        and .evidence_opening_mismatches == 0 and .classification_mismatches == 0)' >/dev/null
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
for snapshots in 1 null -1 0.5; do
    status=0
    result=$(PACKRAT_TEST_SNAPSHOTS="$snapshots" bash "$suite" "$manifest") || status=$?
    [[ $status == 1 ]]
    jq -e --argjson observed "$snapshots" '
        .cases[0].snapshot_check == {expected:0,observed:$observed}
        and (if $observed == 1 then .failed == 1 and .score.snapshot_surplus == 1 and .score.snapshot_deficit == 0
             else .inconclusive == 1 and .cases[0].score == null end)
    ' <<< "$result" >/dev/null
done

jq -c '.cases[0].expect_snapshots = 2' "$manifest" >"$scratch/snapshots.json"
status=0
result=$(PACKRAT_TEST_SNAPSHOTS=1 PACKRAT_TEST_BASELINE_SNAPSHOTS=4 \
    PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline bash "$suite" "$scratch/snapshots.json") || status=$?
[[ $status == 1 ]]
jq -e '.failed == 1 and .comparable == 1 and .score.snapshot_deficit == 1 and .score.snapshot_surplus == 0
    and (.cases[0].delta | .snapshot_deficit == 1 and .snapshot_surplus == -2)' <<< "$result" >/dev/null

jq -c '.cases = [{name:"counts",capture:"counts.pcap",
                   expect_counts:{"scan.horizontal":0,"scan.vertical":2}}]' <<< "$sample" >"$manifest"
status=0
result=$(bash "$suite" "$manifest") || status=$?
[[ $status == 1 ]]
jq -e '.score == {scored_cases:1,missed_opening_frames:0,unexpected_openings:0,
                  count_deficit:1,count_surplus:2,evidence_opening_mismatches:0,
                  evidence_frame_mismatches:0,classification_mismatches:0,
                  snapshot_deficit:0,snapshot_surplus:0,strict_unlisted_openings:0,strict_unregistered_openings:0}' <<< "$result" >/dev/null

strict_sample=$(jq -c '.cases = [
    .cases[0],
    (.cases[0] | .name = "unlisted" | .capture = "unlisted.pcap"),
    (.cases[0] | .name = "unregistered" | .capture = "unregistered.pcap")]' <<< "$sample")
printf '%s\n' "$strict_sample" >"$manifest"
bash "$suite" "$manifest" | jq -e '
    .strict == false and .passed == 3
    and .cases[1].unlisted_rule_counts == {"scan.vertical":1}
    and .cases[2].unregistered_alerts == 1
    and .score.strict_unlisted_openings == 0 and .score.strict_unregistered_openings == 0
' >/dev/null
jq -c '.strict = true' <<< "$strict_sample" >"$manifest"
status=0
result=$(bash "$suite" "$manifest") || status=$?
[[ $status == 1 ]]
jq -e '.strict == true and .passed == 1 and .failed == 2 and .inconclusive == 0
    and .score.strict_unlisted_openings == 1 and .score.strict_unregistered_openings == 1
    and .cases[1].score.strict_unlisted_openings == 1 and .cases[2].score.strict_unregistered_openings == 1' <<< "$result" >/dev/null
status=0
result=$(PACKRAT_TEST_CANDIDATE=invalid_rule_counts bash "$suite" "$manifest") || status=$?
[[ $status == 1 ]]
jq -e '.inconclusive == 3 and .score.scored_cases == 0
    and all(.cases[]; .score == null and .unregistered_alerts == null)' <<< "$result" >/dev/null
jq -c '.strict = true' "$shifted" >"$scratch/strict-baseline.json"
status=0
result=$(PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline bash "$suite" "$scratch/strict-baseline.json") || status=$?
[[ $status == 1 ]]
jq -e '.failed == 1 and .comparable == 1 and .cases[0].delta.strict_unlisted_openings == 1
    and .cases[0].delta.strict_unregistered_openings == 0' <<< "$result" >/dev/null
PACKRAT_TEST_CANDIDATE=invalid_rule_counts PACKRAT_REPLAY_BASELINE_ANALYZER=packrat-baseline \
    bash "$suite" "$shifted" | jq -e '.passed == 1 and .comparable == 1 and .cases[0].delta.rule_openings == null' >/dev/null

for invalid in '.version = 2' 'del(.cases[0].expect_counts)' '.strict = "true"' \
    '.cases[0].expect_snapshots = false' '.cases[0].expect_snapshots = -1' \
    '.cases[1].opening_frames["scan.horizontal"] = [12,12]' \
    '.cases[1].name = .cases[0].name'; do
    jq -c "$invalid" <<< "$sample" >"$manifest"
    status=0
    bash "$suite" "$manifest" >/dev/null 2>&1 || status=$?
    [[ $status == 2 ]]
done
real_tool_dir="$scratch/analyzer binaries"
mkdir -- "$real_tool_dir"
cat > "$real_tool_dir/packrat-analyze" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"type":"summary","packets":20,"analyzed":20,"skipped":0,"truncated_frames":0,"alerts_opened":0,"rule_counts":{},"alert_expectations":{"verdict":"passed"}}'
if [[ -f $0.next ]]; then mv -fT -- "$0.next" "$0"; fi
STUB
chmod +x "$real_tool_dir/packrat-analyze"
cp -- "$real_tool_dir/packrat-analyze" "$real_tool_dir/baseline analyzer"
jq '.cases = [.cases[0],(.cases[0] | .name="second observation")]' <<< "$sample" > "$scratch/tool-stamps.json"
(
    unset -f packrat-analyze
    export PATH="$real_tool_dir:$PATH"
    bash "$suite" "$scratch/tool-stamps.json" | jq -e '
        .passed==2 and .analyzer_check=={candidate:"stable",baseline:null}' >/dev/null
    cp -- "$real_tool_dir/packrat-analyze" "$real_tool_dir/packrat-analyze.next"
    status=0
    result=$(bash "$suite" "$scratch/tool-stamps.json") || status=$?
    [[ $status == 1 ]]
    jq -e '.analyzer_check=={candidate:"changed",baseline:null} and .inconclusive==2 and .score.scored_cases==0
        and all(.cases[]; .score==null and .summary.alert_expectations.verdict=="passed")' <<< "$result" >/dev/null
    cp -- "$real_tool_dir/baseline analyzer" "$real_tool_dir/baseline analyzer.next"
    status=0
    result=$(PACKRAT_REPLAY_BASELINE_ANALYZER="$real_tool_dir/baseline analyzer" \
        bash "$suite" "$scratch/tool-stamps.json") || status=$?
    [[ $status == 1 ]]
    jq -e '.analyzer_check=={candidate:"stable",baseline:"changed"} and .passed==2 and .comparable==0
        and all(.cases[]; .comparison=="analyzer_unstable" and .baseline.score==null and (has("delta") | not))' \
        <<< "$result" >/dev/null
)
printf '%s\n' 'Packrat replay suite tests passed'
