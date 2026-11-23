#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf '%s\n' 'Usage: bash watch-packrat-alerts.sh < alerts.jsonl' \
        'Reads Packrat JSONL from stdin and emits first sightings, existing findings, and changed snapshots.' \
        'Notifications include update reasons and time since the latest observed packet; credential text is omitted.' \
        'Rejected alert input is counted and reported to stderr without its contents.' \
        'Older hit counts for a known capture-scoped alert are rejected as stale snapshots.' \
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
    def socket_endpoint:
        type == "string" and length <= 64
        and test("\\A([0-9.]+|\\[[0-9a-fA-F:.]+\\]):[1-9][0-9]{0,4}\\z")
        and (split(":") | last | tonumber <= 65535);
    def flow_context:
        if type == "object" and (.transport == "tcp" or .transport == "udp")
            and (.source | socket_endpoint) and (.destination | socket_endpoint)
        then {transport,source,destination} else null end;
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
            if $before.flow != $after.flow then "flow" else empty end,
            if ($before | [.rule_id, .revision, .confidence, .verify]) !=
               ($after | [.rule_id, .revision, .confidence, .verify]) then "provenance" else empty end,
            if ($before | [.source, .title, .detail]) !=
               ($after | [.source, .title, .detail]) then "description" else empty end
        ] end;
    def record:
        select(.schema_version == 1)
        | select((.session_id | identifier) and (.alert | type == "object"))
        | .alert as $a
        | select(($a.id | positive_counter) != null)
        | select($a.capture_id == null or ($a.capture_id | identifier))
        | evidence($a) as $frames
        | ($a.source == "CREDENTIAL") as $credential
        | (if ($credential | not) and ($a.provenance | type) == "object" then $a.provenance else {} end) as $rule
        | {
            session_id,
            alert_id: $a.id,
            source: ($a.source | text(64)),
            severity: ($a.severity | text(16)),
            disposition: ($a.disposition | text(24)),
            title: (if $credential then "Possible cleartext credential material" else ($a.title | text(160)) end),
            detail: (if $credential then "Possible cleartext credential material observed; value omitted from the alert."
                     else ($a.detail | text(512)) end),
            hits: ($a.hit_count | counter),
            packet_no: ($a.packet_no | positive_counter),
            last_packet: ($a.last_packet | counter),
            first_seen: ($a.first_seen | observation_time),
            last_seen: ($a.last_seen | observation_time),
            evidence_frame_count: ($frames | length),
            evidence_frames_internal: $frames,
            capture_id: $a.capture_id,
            flow: ($a.flow | flow_context),
            rule_id: ($rule.rule_id | text(128)),
            revision: ($rule.revision | counter),
            confidence: ($rule.confidence | text(32)),
            verify: ($rule.verification_hint | text(240))
        };

    def input_record:
        if length == 0 then empty
        elif utf8bytelength > 1048576 then {reason:"oversized"}
        else (try {row:fromjson} catch {reason:"malformed_json"})
            | if .reason != null then .
              elif (.row | type) != "object" then {reason:"invalid_record"}
              elif .row.record_type != "alert" then empty
              else [.row | record]
                | if length == 0 then {reason:"invalid_alert"} else {alert:.[0]} end
              end
        end;

    def reject($reason):
        .emit = null
        | .rejected[$reason] as $previous
        | (($previous.count // 0) + 1) as $count
        | ($previous.next // 1) as $next
        # Report the first rejection, then powers of two, to bound terminal noise.
        | .rejected[$reason] = {count:$count, next:(if $count == $next then $next * 2 else $next end)}
        | if $count == $next then
            ({record_type:"capture_alert_input", reason:$reason, rejected:$count} | tostring + "\n" | stderr)
            as $notice | .
          else . end;

    foreach (inputs | input_record) as $input (
        {seen: {}, slots: [], next: 0, emit: null, rejected:{}};
        if $input.reason != null then reject($input.reason)
        else $input.alert as $alert
        | ([$alert.session_id, $alert.alert_id, $alert.capture_id] | tojson) as $key
        | .seen[$key] as $previous
        # Within a capture the producer only increments this counter. Review edits can keep it unchanged.
        | if $alert.capture_id != null and $previous.hits != null and $alert.hits != null
                and $alert.hits < $previous.hits then reject("stale_snapshot")
          elif ($previous | del(.first_seen, .last_seen)) ==
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
          end
        end;
        .emit | select(. != null)
    )'
