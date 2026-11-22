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
        mktemp|cmp|rm) command "$@" ;;
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
fail_replace=false
printf '%s\n' '#!/usr/bin/env bash' 'echo independent-update' >"$installed_analyzer"
if promote_analyzer; then exit 1; fi
[[ $("$installed_analyzer") == independent-update ]]
update_analyzer_only >"$scratch/result"
grep -Fq 'Analyzer updated; capture unchanged' "$scratch/result"
cmp -s -- "$analyzer_candidate" "$installed_analyzer"
cmp -s -- "$installed" "$backup_dir/packrat"
[[ $("$backup_dir/packrat-analyze") == independent-update ]]
update_analyzer_only >"$scratch/result"
grep -Fq 'Candidate is already installed; capture unchanged' "$scratch/result"
printf '%s\n' 'Packrat paired rollout tests passed'
