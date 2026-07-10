# Response Design and Feature Roadmap

This document records the Packrat-native plan for the next inspection and
response features. It is based on a static comparison of capabilities, not on
copied Netwatch code or UI. AI and LLM analysis are intentionally excluded.

## Current Alert Design

```text
packet -> built-in IDS / user rules -> critical incident -> red review alert
                                            |
                                            v
                              retained attacker conversation history
                                            |
                                            v
                                 operator review -> acknowledgement
```

The current implementation is passive. Critical built-in signatures and user
rules with a `Critical` alert action create an incident. The incident preserves
a bounded history of packets to or from the suspected attacker, including
traffic that subsequently rolls out of the live packet list. The operator must
open Incident History before acknowledging the alert.

## Future Auto-Containment Design

“Stop all traffic” has different meaning depending on where Packrat runs:

| Placement | What Packrat can contain |
|---|---|
| Endpoint | traffic to and from that endpoint only |
| Gateway or bridge | forwarded traffic involving the suspicious host |
| Passive mirror port | nothing directly; Packrat has no control plane there |

The future design therefore uses a pluggable enforcement backend instead of
assuming that capture authority also grants blocking authority.

```text
critical incident -> policy evaluation -> dry-run audit record
                                      -> approved enforcement backend
                                      -> temporary firewall set entry
                                      -> expiry / rollback / audit export
```

Proposed phases:

1. Monitor-only, the current default. It never changes traffic.
2. Dry-run containment: display the exact nftables rule that would be applied
   and append it to the case audit trail.
3. Manual containment: an operator explicitly applies an expiring source,
   destination, or bidirectional rule after reviewing the incident.
4. Auto-containment: opt-in per policy, supported only by an installed backend
   such as nftables on Linux.

Auto-containment must require all of the following:

- `auto_containment = false` by default.
- An explicit scope, such as `source_only` or `bidirectional`; never an
  ambiguous global outage action.
- Allowlisted management, collector, and emergency addresses that cannot be
  blocked by policy.
- A dry-run period and an audit log showing detector, packet, policy, rule,
  owner, and expiry.
- A short automatic expiry with a refresh action, plus a tested rollback path.
- A stricter trigger than the red alert, normally two independent critical
  signals or a separately marked user rule approved for automatic action.

For a gateway deployment, Packrat can eventually add the suspicious address to
an nftables set referenced by an `input`, `output`, or `forward` rule. It should
never shell out with interpolated packet fields; the backend must validate IP
addresses and use structured rule construction. Other platforms need separate
adapters and must report “unsupported” rather than silently pretending to
enforce.

## Non-AI Feature Backlog

### Priority 1: high-value inspection

- Process/PID attribution on Linux, starting with socket-table correlation and
  adding eBPF only as an optional privileged collector.
- Per-process bandwidth and connection views.
- TLS key-log (`SSLKEYLOGFILE`) ingestion for TLS 1.2/1.3 decryption where keys
  are legitimately available.
- QUIC/HTTP3 parsing and key-log-assisted 1-RTT inspection.
- JA4 and JA4Q fingerprints beside existing TLS fingerprints.
- ECH-aware metadata handling and filters that clearly mark encrypted fields as
  unavailable instead of guessing.

### Priority 2: investigation durability and policy

- Rolling flight recorder with freeze-on-critical-incident PCAP and case bundle.
- Egress baseline and drift rules: process/host to SNI, ASN, IP, and port.
- DNS and gateway RTT measurements, latency heatmaps, and health probes.
- ASN/WHOIS enrichment with cached, attributable lookup data.
- NDJSON evidence export and Prometheus metrics for a daemon mode.

### Priority 3: deployment hardening

- Linux capability dropping and an optional Landlock sandbox for the analyzer.
- A privilege-separated capture/enforcement helper with narrow IPC.
- Policy test fixtures and replay-based regression suites for every shipped
  penetration signature and containment policy.

Each item should be designed and tested in Packrat’s existing terminal-first
style. No AI/LLM mode is planned.
