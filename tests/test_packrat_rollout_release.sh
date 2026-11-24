#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/packrat-rollout.sh
source "$root/scripts/packrat-rollout.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
data_dir="$scratch/data"
installed="$scratch/packrat"
installed_analyzer="$scratch/packrat-analyze"
analyzer_candidate="$scratch/candidate"
fail_replace=false
fail_destination=''
fail_cleanup=false
fail_receipt=false
append_alert_on_copy=false
sudo() {
    [[ $1 == -n ]] || return 1
    shift
    case $1 in
        install)
            if [[ $2 == -d ]]; then
                command install -d -m 0700 -- "${*: -1}"
            else
                command install -m "$7" -- "${@: -2}" || return 1
                if "$append_alert_on_copy" && [[ ${*: -2:1} == "$data_dir/alerts.jsonl" ]]; then
                    printf '%s\n' 'new alert' >> "$data_dir/alerts.jsonl"
                fi
            fi
            ;;
        mv) if "$fail_replace" || [[ ${*: -1} == "$fail_destination" ]]; then return 1; fi; command "$@" ;;
        rm) if "$fail_cleanup" && [[ ${*: -1} == */packrat-analyze.next ]]; then return 1; fi; command "$@" ;;
        tee) if "$fail_receipt"; then return 1; fi; command "$@" ;;
        mktemp|cmp|sha256sum|test|env|find|stat) command "$@" ;;
        *) return 1 ;;
    esac
}

mkdir -- "$data_dir"
backup_inventory | jq -e '.record_type == "rollout_backup_inventory"
    and .allocated_kib == 0 and .available_kib > 0
    and .rollout_directories == 0 and .budget_mib == null' >/dev/null
printf '%s\n' 'previous capture' >"$installed"
printf '%s\n' 'alert evidence' >"$data_dir/alerts.jsonl"
printf '%s\n' '#!/usr/bin/env bash' 'echo wrong-candidate' >"$analyzer_candidate"
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze old"' >"$installed_analyzer"
chmod 0755 -- "$analyzer_candidate" "$installed_analyzer"
if companion_candidates_ready; then exit 1; fi
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze new"' >"$analyzer_candidate"
companion_candidates_ready
create_rollout_backup
stage_companion_updates
cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
(
    export LC_ALL=C
    backup_inventory | jq -e '.allocated_kib > 0 and .rollout_directories == 1' >/dev/null
    backup_reserve_mib=1
    backup_limit_mib=1
    backup_space_ready --companions-only
    dd if=/dev/zero of="$backup_dir/private-fixture" bs=1024 count=2048 status=none
    if backup_space_ready --companions-only 2>"$scratch/backup-budget"; then exit 1; fi
    grep -Fq 'Rollout backup budget would be exceeded' "$scratch/backup-budget"
    [[ -f $backup_dir/private-fixture ]]
    backup_limit_mib=8
    backup_space_ready --companions-only
    backup_inventory | jq -e '.allocated_kib >= 2048 and .rollout_directories == 1 and .budget_mib == 8' >/dev/null
    enable_alert_evidence=true
    evidence_max_mib=4
    backup_limit_mib=4
    if backup_space_ready --enable-alert-evidence 2>"$scratch/stage-budget"; then exit 1; fi
    grep -Fq 'Rollout backup budget would be exceeded' "$scratch/stage-budget"
    backup_limit_mib=8
    backup_space_ready --enable-alert-evidence
    backup_limit_mib=01
    if backup_inventory; then exit 1; fi
    if backup_space_ready --companions-only; then exit 1; fi
)
(
    linked_data="$scratch/linked-data"
    mkdir -- "$linked_data"
    ln -s -- "$backup_dir" "$linked_data/backups"
    if data_dir="$linked_data" backup_inventory; then exit 1; fi
)
(
    large_data="$scratch/large-log"
    mkdir -- "$large_data"
    truncate -s 2097152 -- "$large_data/alerts.jsonl"
    backup_limit_mib=1
    backup_reserve_mib=1
    data_dir="$large_data" backup_space_ready --companions-only
    if data_dir="$large_data" backup_space_ready 2>"$scratch/full-backup-budget"; then exit 1; fi
    grep -Fq 'Rollout backup budget would be exceeded' "$scratch/full-backup-budget"
)
(
    companion_candidates_ready() { :; }
    preflight() { :; }
    backup_space_ready() { [[ $1 == --companions-only ]]; }
    main --check "$installed" wlan1
    main --check "$installed" wlan1 --companions-only
    if main --check "$analyzer_candidate" wlan1 2>"$scratch/full-budget-route"; then exit 1; fi
    grep -Fq 'Insufficient or unverified free space' "$scratch/full-budget-route"
)
(
    baseline_recorder="$scratch/recorder"
    triage_state="$scratch/triage.json"
    interface=wlan1
    export FIXTURE="$scratch/baseline.json"
    cat >"$baseline_recorder" <<'STUB'
#!/usr/bin/env bash
[[ $# == 4 && $1 == --record && $2 == wlan1 && $3 == */triage.json ]] || exit 1
cp -- "$FIXTURE" "$4"
STUB
    chmod +x -- "$baseline_recorder"
    stamp='{"capture_id":"capture-a","alert_session_id":"session-a","capture_run_id":"run-a"}'
    checksum=$(sha256sum -- "$backup_dir/packrat")
    jq -nc --arg sha "${checksum%% *}" '{capture_id:"capture-a",session_id:"session-a"} as $scope |
        {record_type:"capture_build_baseline",build:{scope:$scope,capture_run_id:"run-a",interface:"wlan1",sha256:$sha},coverage:{scope:$scope}}' >"$FIXTURE"
    record_pre_cutover_baseline "$stamp" >"$scratch/baseline-result"
    grep -Fq 'Pre-cutover baseline:' "$scratch/baseline-result"
    cmp -s -- "$FIXTURE" "$backup_dir/before-baseline.json"
    [[ $(stat -c %a -- "$backup_dir/before-baseline.json") == 600 ]]
    for patch in '.build.sha256="wrong"' '.build.scope.session_id="other"' '.coverage.scope.capture_id="other"'; do
        jq "$patch" "$backup_dir/before-baseline.json" >"$FIXTURE"
        if record_pre_cutover_baseline "$stamp" >/dev/null; then exit 1; fi
    done
    jq -e '.build.scope.session_id == "session-a" and .coverage.scope.capture_id == "capture-a"' "$backup_dir/before-baseline.json" >/dev/null
)
fail_replace=true
if promote_companions; then exit 1; fi
cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
fail_replace=false
printf '%s\n' '#!/usr/bin/env bash' 'echo independent-update' >"$installed_analyzer"
if promote_companions; then exit 1; fi
[[ $("$installed_analyzer") == independent-update ]]
capture_stamp='{"pid":"42","capture_run_id":"run-a","capture_id":"capture-a","alert_session_id":"session-a"}'
primary_capture_stamp() { printf '%s\n' "$capture_stamp"; }
interface=wlan1
(
    verify_archive_promotion() { capture_stamp=$(jq -c '.capture_id="other"' <<< "$capture_stamp"); }
    if update_companions_only 2>"$scratch/capture-changed"; then exit 1; fi
    grep -Fq 'Capture continuity or companion receipt could not be verified' "$scratch/capture-changed"
    cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
    [[ ! -e $backup_dir/verified-companions.json ]]
)
fail_receipt=true
if update_companions_only 2>"$scratch/receipt-failed"; then exit 1; fi
cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
[[ ! -e $backup_dir/verified-companions.json ]]
fail_receipt=false
append_alert_on_copy=true
update_companions_only >"$scratch/result"
append_alert_on_copy=false
grep -Fq 'Companions updated; capture unchanged' "$scratch/result"
cmp -s -- "$analyzer_candidate" "$installed_analyzer"
[[ ! -e $backup_dir/packrat && ! -e $backup_dir/alerts.jsonl ]]
[[ $(<"$data_dir/alerts.jsonl") == 'alert evidence' ]]
[[ $("$backup_dir/packrat-analyze") == independent-update ]]
[[ ! -e $backup_dir/packrat-analyze.next ]]
new_hash=$(sha256sum -- "$installed_analyzer")
old_hash=$(sha256sum -- "$backup_dir/packrat-analyze")
jq -e --arg new "${new_hash%% *}" --arg old "${old_hash%% *}" '
    .record_type=="verified_companion_rollout" and .capture_pid=="42" and .capture_run_id=="run-a"
    and .interface=="wlan1" and .scope=={capture_id:"capture-a",session_id:"session-a"}
    and .companions==[{tool:"packrat-analyze",previous_sha256:$old,sha256:$new}]
' "$backup_dir/verified-companions.json" >/dev/null
[[ $(stat -c %a -- "$backup_dir/verified-companions.json") == 600 ]]
update_companions_only >"$scratch/result"
grep -Fq 'Candidate is already installed; capture unchanged' "$scratch/result"

printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze another candidate"' >"$analyzer_candidate"
create_rollout_backup
stage_companion_updates
fail_cleanup=true
promote_companions 2>"$scratch/warning"
grep -Fq 'Staged companion cleanup failed' "$scratch/warning"
cmp -s -- "$analyzer_candidate" "$installed_analyzer"
cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
[[ $("$backup_dir/packrat-analyze") == 'Usage: packrat-analyze new' ]]

fail_cleanup=false
installed_archive="$scratch/packrat-archive"
archive_candidate="$scratch/next-archive"
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-archive old"' >"$installed_archive"
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze wrong-tool"' >"$archive_candidate"
chmod 0755 -- "$installed_archive" "$archive_candidate"
if companion_candidates_ready; then exit 1; fi
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-archive new"' >"$archive_candidate"
companion_candidates_ready
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze later"' >"$analyzer_candidate"
create_rollout_backup
stage_companion_updates
fail_destination=$installed_archive
if promote_companions; then exit 1; fi
cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
cmp -s -- "$installed_archive" "$backup_dir/packrat-archive"
cmp -s -- "$archive_candidate" "$backup_dir/packrat-archive.next"
fail_destination=''
update_companions_only >"$scratch/result"
cmp -s -- "$analyzer_candidate" "$installed_analyzer"
cmp -s -- "$archive_candidate" "$installed_archive"
[[ $("$backup_dir/packrat-archive") == 'Usage: packrat-archive old' ]]
[[ ! -e $backup_dir/packrat-archive.next ]]

analyzer_candidate=''
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-archive later"' >"$archive_candidate"
update_companions_only >"$scratch/result"
grep -Fq 'Companions updated; capture unchanged' "$scratch/result"
cmp -s -- "$archive_candidate" "$installed_archive"
[[ ! -e $backup_dir/packrat-analyze ]]
[[ $("$installed_analyzer") == 'Usage: packrat-analyze later' ]]

(
    triage_state="$scratch/post-promotion.json"
    analyzer_candidate="$scratch/candidate"
    printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze after"' >"$analyzer_candidate"
    printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-archive after"' >"$archive_candidate"
    # shellcheck disable=SC2329  # Called by the sourced release helper.
    date() { printf '%s\n' 1700000000; }
    # shellcheck disable=SC2329  # Called by the sourced release helper.
    await_primary_watcher() {
        [[ $triage_after == 1700000000 && $1 == 1 ]] &&
            cmp -s -- "$archive_candidate" "$installed_archive" &&
            cmp -s -- "$analyzer_candidate" "$installed_analyzer" &&
            touch -- "$triage_state"
        return 1
    }
    allow_historical_drops=1
    if update_companions_only 2>"$scratch/post-promotion-error"; then exit 1; fi
    [[ -f $triage_state ]]
    grep -Fq 'Triage did not verify the promoted archive tool' "$scratch/post-promotion-error"
    cmp -s -- "$installed_archive" "$backup_dir/packrat-archive"
    cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
)

(
    scope='{"capture_id":"00000000000000000000000000000001","capture_run_id":"0000000000000002",
        "alert_session_id":"1700000000-31"}'
    triage_state="$scratch/triage.json"
    archive_candidate=''
    health_state="$scratch/health.json"
    triage_journal_required=1
    # shellcheck disable=SC2329  # Invoked by the sourced rollout helper.
    primary_alert_log_identity() { printf '%s\n' '1:2'; }
    # shellcheck disable=SC2329
    date() { printf '%s\n' 1700000000; }
    # shellcheck disable=SC2329
    timeout() { printf '%s\n' "$triage_sample"; return 1; }
    network_sample=$(jq -c '. + {status:"ok", telemetry_fresh:true, capture_active:true, pcap_buffer_drops:100}' <<< "$scope")
    # shellcheck disable=SC2329
    curl() { printf '%s\n' "$network_sample"; }
    health_sample=$(jq -c --arg log "$data_dir/alerts.jsonl" '. + {
        record_type:"capture_health",timestamp:"2023-11-14T22:13:10Z",poll_interval_seconds:15,
        capture_active:true,telemetry_fresh:true,alert_watcher_alive:true,alert_watcher_pipeline_alive:true,
        alert_watcher_source_matches:true,alert_watcher_open_log_required:true,alert_log_identity:"1:2",
        alert_watcher_log:$log,alert_log_storage:"private",issues:["pcap_buffer_drops"],
        pcap_buffer_drops:100,pcap_buffer_drops_delta:0}' <<< "$scope")
    triage_sample=$(jq -c '{capture_id,session_id:.alert_session_id,status:"triage_unhealthy",
        historical_drop_total:100,journal_status:"current",journal_pending_events:0}' <<< "$scope")
    printf '%s\n' "$health_sample" >"$health_state"
    if alert_watcher_ready "$scope"; then exit 1; fi
    alert_watcher_ready "$scope" 1
    for change in '.pcap_buffer_drops_delta=1' '.issues+=["capture_queue_high"]' '.pcap_buffer_drops=101'; do
        jq "$change" <<< "$health_sample" >"$health_state"
        if alert_watcher_ready "$scope" 1; then exit 1; fi
    done
    printf '%s\n' "$health_sample" >"$health_state"
    if (network_sample=$(jq '.pcap_buffer_drops=101' <<< "$network_sample"); alert_watcher_ready "$scope" 1); then exit 1; fi
    valid_triage_sample=$triage_sample
    for change in '.journal_pending_events=1' '.session_id="1700000000-32"' '.historical_drop_total=null'; do
        if (triage_sample=$(jq "$change" <<< "$valid_triage_sample"); alert_watcher_ready "$scope" 1); then exit 1; fi
    done
    archive_candidate="$scratch/next-archive"
    for started in null 1699999999 1700000000 1700000001; do
        (
            triage_after=1700000000
            triage_sample=$(jq --argjson start "$started" '.poll_started_at=$start | .evidence_check_failures=0' <<< "$valid_triage_sample")
            if [[ $started == 1700000001 ]]; then alert_watcher_ready "$scope" 1
            elif alert_watcher_ready "$scope" 1; then exit 1
            fi
        )
    done
    for failures in 1 null; do
        (
            triage_sample=$(jq --argjson failures "$failures" '
                .poll_started_at=1700000001 | .evidence_check_failures=$failures' <<< "$valid_triage_sample")
            alert_watcher_ready "$scope" 1
            triage_after=1700000000
            if alert_watcher_ready "$scope" 1; then exit 1; fi
        )
    done
)
# shellcheck source=tests/support/rollout_identity_cases.bash
source "$root/tests/support/rollout_identity_cases.bash"
printf '%s\n' 'Packrat paired rollout tests passed'
