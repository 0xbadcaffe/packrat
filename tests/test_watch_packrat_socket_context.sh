#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
watch="$root/scripts/watch-packrat-socket-context.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
export PACKRAT_SOCKET_CALLS="$scratch/calls"

ss() {
    printf '%s\n' called >>"$PACKRAT_SOCKET_CALLS"
    [[ $* == '-H -n -t -p ( sport = :40001 and dport = :443 ) or ( sport = :443 and dport = :40001 )' ]] || return 2
    local row='ESTAB 0 0 [2001:db8::4]:40001 [2001:db8::8]:443'
    printf '%s\n' 'ESTAB 0 0 [2001:db8::9]:40001 [2001:db8::8]:443 users:(("other",pid=91,fd=2))'
    case ${PACKRAT_SOCKET_MODE:-match} in
        match) printf '%s users:(("test client",pid=56,fd=2))\n' "$row" ;;
        reverse) printf '%s\n' 'ESTAB 0 0 [2001:db8::8]:443 [2001:db8::4]:40001 users:(("https",pid=57,fd=2))' ;;
        hidden) printf '%s\n' "$row" ;;
        ambiguous) printf '%s\n' "$row" "$row" ;;
        shared) printf '%s users:(("a",pid=56,fd=2),("b",pid=57,fd=3))\n' "$row" ;;
        none) ;;
        failure) return 124 ;;
    esac
}

timeout() {
    [[ $1 == --kill-after=1s && $2 == 1s ]] || return 2
    shift 2
    "$@"
}
export -f ss timeout

fixture() {
    jq -cn '{record_type:"capture_alert",event:"first_seen",last_seen:now,
       capture_id:"00000000000000000000000000000001",
       flow:{transport:"tcp",source:"[2001:db8::4]:40001",destination:"[2001:db8::8]:443"}}'
}

result=$(fixture | bash "$watch")
jq -e '.socket_context.status == "exact_tuple_snapshot" and .socket_context.process == "test client"
    and .socket_context.pid == 56 and .socket_context.local == .flow.source
    and (.socket_context.observed_at | fromdateiso8601) > 0' <<< "$result" >/dev/null
result=$(fixture | PACKRAT_SOCKET_MODE=reverse bash "$watch")
jq -e '.socket_context.status == "exact_tuple_snapshot" and .socket_context.pid == 57
    and .socket_context.local == .flow.destination' <<< "$result" >/dev/null

for spec in 'hidden socket_owner_unavailable' 'shared socket_owner_unavailable' \
    'none socket_not_observed' 'ambiguous ambiguous_socket_snapshot' 'failure lookup_unavailable'; do
    read -r mode status <<< "$spec"
    result=$(fixture | PACKRAT_SOCKET_MODE="$mode" bash "$watch")
    jq -e --arg status "$status" '.socket_context.status == $status and (.socket_context | has("process") | not)' \
        <<< "$result" >/dev/null
done

: >"$PACKRAT_SOCKET_CALLS"
fixture | jq -c '
    (.last_seen -= 20), (.last_seen += 20), (.event = "updated"), (.flow.transport = "udp"),
    (.flow.source = "bad input:443"), (.flow.source = "[2001:db8::4]:99999"), (del(.capture_id))
' | bash "$watch" | jq -se 'length == 7 and all(.[]; has("socket_context") | not)' >/dev/null
[[ ! -s $PACKRAT_SOCKET_CALLS ]]

printf '%s\n' 'Packrat socket context watcher tests passed'
