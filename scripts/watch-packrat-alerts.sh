#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: bash watch-packrat-alerts.sh < alerts.jsonl' \
        'Reads Packrat JSONL from stdin and emits first sightings, existing findings, and changed snapshots.' \
        'Notifications include update reasons and time since the latest observed packet.' \
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
        if type == "number" and . >= 0 and . <= 9007199254740991 and floor == .
        then . else null end;
    def positive_counter:
        counter | if . == 0 then null else . end;
    def identifier:
        type == "string" and length <= 128 and test("\\A[A-Za-z0-9_-]+\\z");
    def observation_time:
        if type == "number" and isfinite and . > 0 then . else null end;
    def event_kind($previous; $alert):
        if $previous != null then "updated"
        elif ($alert.hits != null and $alert.hits > 1)
            or ($alert.disposition != null and $alert.disposition != "New") then "existing"
        else "first_seen" end;
    def evidence($alert):
        ([$alert.first_packet, $alert.packet_no, $alert.last_packet]
         + ($alert.packet_refs | if type == "array" then .[:128] else [] end))
        | map(positive_counter | select(. != null))
        | unique;
    def changes($before; $after):
        if $before == null then [] else [
            if $before.severity != $after.severity then "severity" else empty end,
            if $before.disposition != $after.disposition then "disposition" else empty end,
            if ($before | [.packet_no, .last_packet, .evidence_frames_internal]) !=
               ($after | [.packet_no, .last_packet, .evidence_frames_internal]) then "evidence" else empty end,
            if $before.hits != $after.hits then "hit_count" else empty end,
            if ($before | [.rule_id, .revision, .confidence, .verify]) !=
               ($after | [.rule_id, .revision, .confidence, .verify]) then "provenance" else empty end,
            if ($before | [.source, .title, .detail]) !=
               ($after | [.source, .title, .detail]) then "description" else empty end
        ] end;
    def record:
        select(utf8bytelength <= 1048576)
        | (try fromjson catch empty)
        | objects
        | select(.record_type == "alert" and .schema_version == 1)
        | select((.session_id | identifier) and (.alert | type == "object"))
        | .alert as $a
        | select(($a.id | positive_counter) != null)
        | select($a.capture_id == null or ($a.capture_id | identifier))
        | evidence($a) as $frames
        | (if ($a.provenance | type) == "object" then $a.provenance else {} end) as $rule
        | {
            session_id,
            alert_id: $a.id,
            source: ($a.source | text(64)),
            severity: ($a.severity | text(16)),
            disposition: ($a.disposition | text(24)),
            title: ($a.title | text(160)),
            detail: ($a.detail | text(512)),
            hits: ($a.hit_count | counter),
            packet_no: ($a.packet_no | positive_counter),
            last_packet: ($a.last_packet | counter),
            first_seen: ($a.first_seen | observation_time),
            last_seen: ($a.last_seen | observation_time),
            evidence_frame_count: ($frames | length),
            evidence_frames_internal: $frames,
            capture_id: $a.capture_id,
            rule_id: ($rule.rule_id | text(128)),
            revision: ($rule.revision | counter),
            confidence: ($rule.confidence | text(32)),
            verify: ($rule.verification_hint | text(240))
        };

    foreach (inputs | record) as $alert (
        {seen: {}, slots: [], next: 0, emit: null};
        ([$alert.session_id, $alert.alert_id, $alert.capture_id] | tojson) as $key
        | .seen[$key] as $previous
        # A clock-only change is context for the next finding, not a notification.
        | if ($previous | del(.first_seen, .last_seen)) ==
             ($alert | del(.first_seen, .last_seen)) then
            .emit = null
          else
            if $previous == null then
                .slots[.next] as $evicted
                | if $evicted == null then . else del(.seen[$evicted]) end
                | .slots[.next] = $key
                | .next = ((.next + 1) % $limit)
            else . end
            | .seen[$key] = $alert
            | now as $emitted
            | .emit = (($alert | del(.evidence_frames_internal)) + {
                record_type: "capture_alert",
                event: event_kind($previous; $alert),
                changes: changes($previous; $alert),
                emitted_at: ($emitted | todateiso8601),
                observation_to_notification_seconds: (
                    if $alert.last_seen != null and $alert.last_seen <= $emitted
                    then $emitted - $alert.last_seen else null end
                )
            })
          end;
        .emit | select(. != null)
    )'
