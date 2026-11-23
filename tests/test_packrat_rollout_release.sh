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
fail_cleanup=false
sudo() {
    [[ $1 == -n ]] || return 1
    shift
    case $1 in
        install)
            if [[ $2 == -d ]]; then
                command install -d -m 0700 -- "${*: -1}"
            else
                command install -m "$7" -- "${@: -2}"
            fi
            ;;
        mv) "$fail_replace" && return 1; command "$@" ;;
        rm) if "$fail_cleanup" && [[ ${*: -1} == */packrat-analyze.next ]]; then return 1; fi; command "$@" ;;
        mktemp|cmp) command "$@" ;;
        *) return 1 ;;
    esac
}

mkdir -- "$data_dir"
printf '%s\n' 'previous capture' >"$installed"
printf '%s\n' 'alert evidence' >"$data_dir/alerts.jsonl"
printf '%s\n' '#!/usr/bin/env bash' 'echo wrong-candidate' >"$analyzer_candidate"
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze old"' >"$installed_analyzer"
chmod 0755 -- "$analyzer_candidate" "$installed_analyzer"
if analyzer_candidate_ready; then exit 1; fi
printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze new"' >"$analyzer_candidate"
analyzer_candidate_ready
create_rollout_backup
stage_analyzer_update
cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
fail_replace=true
if promote_analyzer; then exit 1; fi
cmp -s -- "$installed_analyzer" "$backup_dir/packrat-analyze"
cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
fail_replace=false
printf '%s\n' '#!/usr/bin/env bash' 'echo independent-update' >"$installed_analyzer"
if promote_analyzer; then exit 1; fi
[[ $("$installed_analyzer") == independent-update ]]
update_analyzer_only >"$scratch/result"
grep -Fq 'Analyzer updated; capture unchanged' "$scratch/result"
cmp -s -- "$analyzer_candidate" "$installed_analyzer"
cmp -s -- "$installed" "$backup_dir/packrat"
cmp -s -- "$data_dir/alerts.jsonl" "$backup_dir/alerts.jsonl"
[[ $("$backup_dir/packrat-analyze") == independent-update ]]
[[ ! -e $backup_dir/packrat-analyze.next ]]
update_analyzer_only >"$scratch/result"
grep -Fq 'Candidate is already installed; capture unchanged' "$scratch/result"

printf '%s\n' '#!/usr/bin/env bash' 'echo "Usage: packrat-analyze another candidate"' >"$analyzer_candidate"
create_rollout_backup
stage_analyzer_update
fail_cleanup=true
promote_analyzer 2>"$scratch/warning"
grep -Fq 'Staged analyzer cleanup failed' "$scratch/warning"
cmp -s -- "$analyzer_candidate" "$installed_analyzer"
cmp -s -- "$analyzer_candidate" "$backup_dir/packrat-analyze.next"
[[ $("$backup_dir/packrat-analyze") == 'Usage: packrat-analyze new' ]]

(
    scope='{"capture_id":"00000000000000000000000000000001","capture_run_id":"0000000000000002",
        "alert_session_id":"1700000000-31"}'
    triage_state="$scratch/triage.json"
    health_state="$scratch/health.json"
    triage_journal_required=1
    primary_alert_log_identity() { printf '%s\n' '1:2'; }
    date() { printf '%s\n' 1700000000; }
    timeout() { printf '%s\n' "$triage_sample"; return 1; }
    network_sample=$(jq -c '. + {status:"ok", telemetry_fresh:true, capture_active:true, pcap_buffer_drops:100}' <<< "$scope")
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
    for change in '.journal_pending_events=1' '.session_id="1700000000-32"' '.historical_drop_total=null'; do
        if (triage_sample=$(jq "$change" <<< "$triage_sample"); alert_watcher_ready "$scope" 1); then exit 1; fi
    done
)
printf '%s\n' 'Packrat paired rollout tests passed'
