# Packrat detection and investigation goal

Packrat should let a defender explain why traffic was flagged, verify the finding against captured evidence, and decide what to do next. It is a passive network analyzer for live monitoring, incident triage, and reviewing traffic from authorized red-team exercises. It does not generate attacks, probe targets, or automatically contain traffic.

## What good looks like

- Every alert says what was observed, where and when it happened, which rule fired, and what is still unknown. Severity reflects potential impact; confidence reflects the strength of the evidence.
- An alert opens its triggering packets and, where available, the matching flow and protocol transaction. Packet references are scoped to their capture session. Missing frames, partial captures, and dropped packets are visible rather than treated as negative evidence.
- Operators can mark benign, needs review, or confirmed, and export a case with the evidence and rule version. Repeated sightings are grouped without losing distinct flows or understating the number of observations.
- Monitoring keeps running when the UI disconnects. The operator can distinguish new incidents, updates to existing alerts, watcher failure, and loss of capture.

## Next milestones

1. **Reliable alert evidence.** Keep the query and both replies for DNS conflicts, and retain the request/response or contributing samples for authentication and periodic traffic. Add a bounded archive lookup so older alerts can still open available evidence after the live packet buffer rolls over.
2. **Signal quality.** Classify DNS answer changes separately from wire-only differences. Describe periodic traffic as a behavioral lead until independently corroborated. Compare scan and authentication rules against labeled benign and suspicious captures before raising severity.
3. **Operator workflow.** Show rule ID, severity, confidence, evidence availability, and a suggested verification step. Add review dispositions and evidence export without including packet payloads in routine notifications.
4. **Operational reliability.** Track capture drops, alert persistence failures, stale watchers, and disk usage. Add restart and rollback checks to a supervised deployment workflow before considering any automatic rollout.

## Rule acceptance

- A new or changed rule needs a positive fixture and a representative benign negative control. Add regression fixtures for the production-like inputs that caused the change, including duplicates, truncation, or reordering where relevant.
- Critical findings require specific evidence. Timing, volume, port numbers, and other weak signals can prioritize review but must not imply attribution or confirmed compromise.
- Replay must produce deterministic results with bounded detector state. Measure alert volume, false positives, missed labeled events, capture drops, and time to triage against the same baseline before and after changes.
- Keep private captures, payloads, and credentials out of git. Use sanitized fixtures and session-scoped references in reports.

## Offline security benchmark and export contract

Baseline: Packrat 0.4.1 (`add33be`), Suricata 8.0.3, Zeek 9.0.1, and TShark 4.6.4. Each fixture had 200,000 synthetic Ethernet frames: DNS-only, or 20,000 DNS query/reply pairs and 20,000 cleartext HTTP exchanges. Runs used one logical CPU on an Intel i7-8650U with RAM-backed output. The table reports medians of five trials after one warm-up; peak RSS is for the mixed fixture.

| Output mode | DNS (s) | Mixed (s) | Peak RSS (MiB) |
|---|---:|---:|---:|
| Suricata EVE (242 protocol and decoder rules) | 2.56 | 2.70 | 124 |
| TShark selected fields | 2.78 | 3.10 | 417 |
| Packrat alerts only | 3.33 | 3.17 | 99 |
| Packrat standard NDJSON | 3.36 | 3.29 | 99 |
| Zeek JSON logs | 9.97 | 7.07 | 145 |
| TShark protocol JSON | 17.25 | 20.52 | 417 |

On a separate three-frame fixture, Packrat flagged a changed DNS answer at frame 3 and cited all three frames. It did not flag the identical-answer control. The other tools exposed both answers but did not open a matching finding in the configurations tested. This does not compare detection recall: output modes differ, Suricata did not load a threat feed, and the fixtures are synthetic. Use labeled benign and suspicious captures with pinned rulesets for detection comparisons.

The baseline analyzed all frames in the mixed capture but exported only 500 HTTP exchanges; Zeek and Suricata logged 20,000. Standard offline Packrat export must serialize HTTP/1 and cleartext HTTP/2 conversations when a TCP stream is evicted, then flush the remaining streams at end of capture. Keep the 500-stream cache bounded and preserve original frame citations. Mark the export boundary explicitly; eviction is not proof of a complete conversation, and traffic arriving after eviction may lack earlier context. Alert-only replay must not emit transactions or change alert coverage. HTTP/3 remains limited to retained connections. The acceptance workload requires 20,000 distinct HTTP exchanges, no skipped frames, and no increase in cache capacity.

The first fixed release build (`a6b7ecb`) exported all 20,000 HTTP exchanges: 19,500 at eviction and 500 at end of capture. Each exchange cited the expected request and response frames. No frames were skipped, and alert-only output matched the baseline byte for byte on the mixed capture and both DNS correctness fixtures.

## Monitoring and release loop

1. Follow the saved alert log on the lab host. Deduplicate by session and alert ID; report meaningful changes and distinguish observation, inference, and recommended verification.
2. Triage before tuning. Preserve the relevant evidence and decide whether the issue is a detector bug, a scope mismatch, or a credible finding.
3. Fix one issue at a time, add a regression test, and run the full test suite plus a locked release build with live capture enabled. Push small commits with the maintainer's sign-off.
4. Keep the active capture running while the replacement builds. Back up the current alert log and previous binary, stage the replacement, then verify the intended interface, increasing packet counts, alert saving, and a working watcher. Keep the previous binary for rollback.
5. Compare post-deployment alert volume and capture health with the baseline. Escalate credible findings for human review. Do not treat a quiet log as proof that detection is working.
