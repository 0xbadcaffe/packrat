#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: bash watch-packrat-alerts.sh < alerts.jsonl' \
        'Reads Packrat JSONL from stdin and emits first sightings and changed snapshots.' \
        'PACKRAT_WATCH_MAX_ALERTS sets the in-memory alert history (default: 1024).'
}
case ${1-} in
    '') ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac
if (( $# > 0 )); then usage >&2; exit 2; fi

limit=${PACKRAT_WATCH_MAX_ALERTS:-1024}
if [[ ! $limit =~ ^[1-9][0-9]{0,4}$ ]] || (( limit > 10000 )); then
    printf '%s\n' 'PACKRAT_WATCH_MAX_ALERTS must be between 1 and 10000.' >&2
    exit 2
fi
if ! command -v jq >/dev/null; then
    printf '%s\n' 'jq is required to read Packrat alerts.' >&2
    exit 2
fi

exec jq --unbuffered -cRn --argjson limit "$limit" '
    def text($limit):
        if type == "string" then .[:$limit] else null end;
    def counter:
        if type == "number" and . >= 0 and floor == . then . else null end;
    def record:
        (try fromjson catch empty)
        | objects
        | select(.record_type == "alert" and .schema_version == 1)
        | select((.session_id | type == "string" and length > 0 and length <= 128)
                 and (.alert | type == "object"))
        | select((.alert.id | counter) != null)
        | .alert as $a
        | (if ($a.provenance | type) == "object" then $a.provenance else {} end) as $rule
        | {
            session_id,
            alert_id: $a.id,
            severity: ($a.severity | text(16)),
            disposition: ($a.disposition | text(24)),
            title: ($a.title | text(160)),
            detail: ($a.detail | text(512)),
            hits: ($a.hit_count | counter),
            last_packet: ($a.last_packet | counter),
            capture_id: ($a.capture_id | text(128)),
            rule_id: ($rule.rule_id | text(128)),
            revision: ($rule.revision | counter),
            confidence: ($rule.confidence | text(32)),
            verify: ($rule.verification_hint | text(240))
        };

    foreach (inputs | record) as $alert (
        {seen: {}, slots: [], next: 0, emit: null};
        ([$alert.session_id, $alert.alert_id] | tojson) as $key
        | .seen[$key] as $previous
        | if $previous == $alert then
            .emit = null
          else
            if $previous == null then
                .slots[.next] as $evicted
                | if $evicted == null then . else del(.seen[$evicted]) end
                | .slots[.next] = $key
                | .next = ((.next + 1) % $limit)
            else . end
            | .seen[$key] = $alert
            | .emit = ($alert + {
                record_type: "capture_alert",
                event: (if $previous == null then "first_seen" else "updated" end)
            })
          end;
        .emit | select(. != null)
    )'
