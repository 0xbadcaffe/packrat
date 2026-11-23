#!/usr/bin/env bash

archive_samples=$(jq -c '
    [. + {archive_enabled:false,archive_paused:false},
     . + {archive_enabled:true,archive_paused:false},
     . + {archive_enabled:true,archive_paused:true},
     . + {archive_enabled:true},
     . + {archive_enabled:"true",archive_paused:false}]
' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_REQUIRE_ARCHIVE=1 PACKRAT_FAKE_STEPS=5 PACKRAT_FAKE_SAMPLES="$archive_samples" bash "$watch" | jq -se '
    map(.issues) == [["archive_disabled"], ["archive_usage_unavailable"], ["archive_paused"], ["archive_status_unavailable"], ["archive_status_unavailable"]]
    and map(.archive_enabled) == [false,true,true,true,null]
    and map(.archive_paused) == [false,false,true,null,false]
    and all(.[]; .archive_requirement == "active")
' >/dev/null
PACKRAT_FAKE_STEPS=5 PACKRAT_FAKE_SAMPLES="$archive_samples" bash "$watch" | jq -se '
    map(.issues) == [[], [], ["archive_paused"], [], []]
    and map(.archive_enabled) == [false,true,true,true,null]
' >/dev/null
status=0
PACKRAT_REQUIRE_ARCHIVE=true bash "$watch" --once >/dev/null 2>&1 || status=$?
[[ $status == 2 ]]

evidence_samples=$(jq -c '
    . + {archive_usage:{frames:0,max_frames:10,payload_bytes:0,max_payload_bytes:100}} |
    (. + {archive_enabled:true,archive_paused:false,archive_alert_evidence_only:true}) as $selective |
    [$selective + {archive_evidence_rules:["tcp.payload_after_observed_reset"]},
     . + {archive_enabled:true,archive_paused:false,archive_alert_evidence_only:false,archive_evidence_rules:["tcp.payload_after_observed_reset"]},
     . + {archive_enabled:true,archive_paused:true,archive_alert_evidence_only:false},
     . + {archive_enabled:true,archive_paused:false,archive_alert_evidence_only:"true"},
     . + {archive_enabled:false,archive_paused:false}, $selective,
     ($selective + {archive_evidence_rules:["bad rule"]}), ($selective + {archive_evidence_rules:["dup","dup"]}),
     ($selective + {archive_evidence_rules:[]})]
' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_REQUIRE_ARCHIVE=alert-evidence PACKRAT_HEALTH_HEARTBEAT=1 PACKRAT_FAKE_STEPS=9 PACKRAT_FAKE_SAMPLES="$evidence_samples" bash "$watch" | jq -se '
    map(.issues) == [[], ["archive_full_capture_unexpected"], ["archive_paused","archive_full_capture_unexpected"],
                     ["archive_mode_unavailable"], ["archive_disabled"], ["archive_rules_unavailable"],
                     ["archive_rules_unavailable"], ["archive_rules_unavailable"], []]
    and map(.archive_alert_evidence_only) == [true,false,false,null,null,true,true,true,true]
    and map(.archive_evidence_rules) == [["tcp.payload_after_observed_reset"],null,null,null,null,null,null,null,[]]
    and all(.[]; .archive_requirement == "alert_evidence_only")
' >/dev/null

pause_samples=$(jq -c '
    [. + {archive_enabled:true,archive_paused:true,archive_pause_reason:"frame_limit"},
     . + {archive_enabled:true,archive_paused:true,archive_pause_reason:"write_failed"},
     . + {archive_enabled:true,archive_paused:true,archive_pause_reason:"private error path"},
     . + {archive_enabled:true,archive_paused:true,archive_pause_reason:["frame_limit"],archive_alert_evidence_only:true},
     . + {archive_enabled:true,archive_paused:false,archive_pause_reason:"byte_limit"}]
' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_FAKE_STEPS=5 PACKRAT_FAKE_SAMPLES="$pause_samples" bash "$watch" | jq -se '
    map(.archive_pause_reason) == ["frame_limit","write_failed",null,null,null]
    and (tostring | contains("private error path") | not)
' >/dev/null

capacity_samples=$(jq -c '(. + {archive_enabled:true,archive_paused:false,
    archive_usage:{frames:8,max_frames:10,payload_bytes:20,max_payload_bytes:100,private:"omitted"}}) as $base |
    [$base, ($base | .archive_usage.frames = 9), ($base | .archive_usage.frames = "9"),
     ($base | .archive_usage.payload_bytes = 90), ($base | .archive_paused = true | .archive_usage.payload_bytes = 100),
     ($base | .archive_usage.payload_bytes = 100), ($base | .archive_usage.frames = 11), ($base | .archive_usage.max_frames = 0)]
' <<< "$PACKRAT_FAKE_HEALTH")
PACKRAT_REQUIRE_ARCHIVE=1 PACKRAT_HEALTH_HEARTBEAT=1 PACKRAT_FAKE_STEPS=8 PACKRAT_FAKE_SAMPLES="$capacity_samples" bash "$watch" | jq -se '
    map(.issues) == [[],["archive_near_capacity"],["archive_usage_unavailable"],["archive_near_capacity"],["archive_paused"],
                    ["archive_at_capacity"],["archive_at_capacity"],["archive_usage_unavailable"]]
    and .[2].archive_usage == null and .[7].archive_usage == null and .[1].archive_usage.frames == 9
    and all(.[]; (.archive_usage | has("private") | not))
' >/dev/null
