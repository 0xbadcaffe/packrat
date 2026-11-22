#!/usr/bin/env bash
set -euo pipefail

case $#:${1-} in
    0:) ;;
    1:--help|1:-h)
        printf '%s\n' 'Usage: watch-packrat-alerts.sh | watch-packrat-socket-context.sh' \
            'Adds a read-only TCP socket snapshot to fresh first sightings, at most once per second.' \
            'Run on the capture host. Results depend on its network namespace and process visibility.'
        exit 0 ;;
    *) exit 2 ;;
esac
for dependency in jq ss timeout head; do
    command -v "$dependency" >/dev/null || {
        printf 'Missing socket context dependency: %s\n' "$dependency" >&2
        exit 2
    }
done

eligible_endpoints() {
    jq -er '
        def endpoint:
            type == "string" and length <= 64
            and test("\\A([0-9.]+|\\[[0-9a-fA-F:.]+\\]):[1-9][0-9]{0,4}\\z")
            and (split(":") | last | tonumber <= 65535);
        select(.record_type == "capture_alert" and .event == "first_seen"
            and (.capture_id | type == "string" and test("\\A[0-9a-f]{32}\\z"))
            and (.last_seen | type == "number" and isfinite and . > 0)
            and ((now - .last_seen) | . >= 0 and . <= 5)
            and .flow.transport == "tcp"
            and (.flow.source | endpoint) and (.flow.destination | endpoint))
        | [.flow.source, .flow.destination] | @tsv
    ' <<< "$1"
}

lookup_context() {
    local source=$1 destination=$2 sport dport sockets observed
    sport=${source##*:}
    dport=${destination##*:}
    if ! sockets=$(LC_ALL=C timeout --kill-after=1s 1s ss -H -n -t -p \
        "( sport = :$sport and dport = :$dport ) or ( sport = :$dport and dport = :$sport )" |
        LC_ALL=C head -c 65537) || (( ${#sockets} > 65536 )); then
        printf '%s\n' '{"status":"lookup_unavailable"}'
        return
    fi
    observed=$(date -u +%FT%TZ)
    jq -Rsc --arg source "$source" --arg destination "$destination" --arg time "$observed" '
        [splits("\n") |
            capture("\\AESTAB\\s+[0-9]+\\s+[0-9]+\\s+(?<local>\\S+)\\s+(?<peer>\\S+)(?:\\s+(?<owners>.*))?\\z") |
            select((.local == $source and .peer == $destination)
                or (.local == $destination and .peer == $source))]
        | if length == 0 then {status:"socket_not_observed"}
          elif length > 1 then {status:"ambiguous_socket_snapshot"}
          else .[0] as $row
            | ([($row.owners // "") | capture(
                "\\Ausers:\\(\\(\"(?<process>[A-Za-z0-9_. -]{1,64})\",pid=(?<pid>[1-9][0-9]{0,9}),fd=[0-9]+\\)\\)\\z"
              )][0] // null) as $owner
            | if $owner == null then {status:"socket_owner_unavailable"}
              else {status:"exact_tuple_snapshot", local:$row.local, peer:$row.peer,
                    process:$owner.process, pid:($owner.pid | tonumber)}
              end
          end
        | . + {observed_at:$time}
    ' <<< "$sockets"
}

last_lookup=-1
while IFS= read -r line; do
    if (( SECONDS > last_lookup )) && endpoints=$(eligible_endpoints "$line" 2>/dev/null); then
        last_lookup=$SECONDS
        IFS=$'\t' read -r source destination <<< "$endpoints"
        if context=$(lookup_context "$source" "$destination"); then
            jq -c --argjson context "$context" '.socket_context = $context' <<< "$line"
            continue
        fi
    fi
    printf '%s\n' "$line"
done
