# shellcheck shell=bash
(
    export PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE="$scratch/socket context.jsonl"
    context=$PACKRAT_TRIAGE_SOCKET_CONTEXT_FILE
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status == "not_recorded" and (.alerts[0] | has("socket_context") | not)' <<< "$result" >/dev/null
    valid=$(jq -cn '
        {alert_id:42,session_id:"1700000000-432",capture_id:"00000000000000000000000000000001",
         flow:{transport:"tcp",source:"192.0.2.1:4321",destination:"192.0.2.2:443"},alert_last_seen:1700000000,
         socket_context:{status:"exact_tuple_snapshot",tcp_state:"SYN-SENT",observed_at:"2023-11-14T22:13:20Z",
            local:"192.0.2.1:4321",peer:"192.0.2.2:443",process:"client",pid:123,private:"do not export"}}')
    jq -c '.alert_last_seen=1699999999.5 | .socket_context.process="old process"' <<<"$valid" >"$context"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status=="available" and (.alerts[0] | has("socket_context") | not)' <<<"$result" >/dev/null
    jq -c '.,
        (.capture_id="00000000000000000000000000000002" | .socket_context.process="wrong capture"),
        (.session_id="1700000000-567" | .socket_context.process="wrong session"),
        (.flow.source="192.0.2.1:4322" | .socket_context.process="wrong port"),
        (.socket_context.observed_at="2023-11-14T22:20:00Z"),
        (.socket_context |= (.local as $local | .local=.peer | .peer=$local | .process="wrong direction"))
    ' <<< "$valid" >>"$context"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status=="available" and .alerts[0].socket_context.process=="client"
        and .alerts[0].socket_context.alert_last_seen==1700000000 and .alerts[0].socket_context.tcp_state=="SYN-SENT"
        and (.alerts[0].socket_context | has("private") | not)' <<<"$result" >/dev/null
    result=$(bash "$triage" --saved 1700000000-432 00000000000000000000000000000001 "$PACKRAT_TEST_LOG")
    jq -e '.mode=="saved" and .status=="saved" and .health==null
        and .scope=={session_id:"1700000000-432",capture_id:"00000000000000000000000000000001"}
        and .alerts[0].socket_context.process=="client"' <<<"$result" >/dev/null
    jq -c '.socket_context.pid=124' <<<"$valid" >>"$context"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status=="available" and (.alerts[0] | has("socket_context") | not)' <<<"$result" >/dev/null
    printf '%s\n' '{malformed' >>"$context"
    result=$(bash "$triage" "$health" "$PACKRAT_TEST_LOG")
    jq -e '.socket_context_status=="unavailable" and (.alerts[0] | has("socket_context") | not)' <<<"$result" >/dev/null
)
