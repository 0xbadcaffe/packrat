# Response Design and Feature Status

This document tracks Packrat's original, non-AI inspection and response design.
It is a capability status record, not a plan to copy another project's code or
interface. No AI or LLM analysis mode is planned.

## Response Pipeline

```text
packet -> built-in IDS / user rules -> critical incident -> red review alert
                                            |
                                            +-> EvidenceVault freeze
                                            +-> TrafficLatch policy and audit
                                            +-> retained conversation history
```

TrafficLatch is monitor-only by default. Preview records a proposed action,
manual requires approval from reviewed Incident History, and automatic mode is
an explicit startup choice. Linux enforcement uses validated IP addresses and
expiring nftables sets; protected and unsafe address classes are rejected.

Deployment placement still defines the enforcement boundary:

| Placement | What Packrat can contain |
|---|---|
| Endpoint | traffic to and from that endpoint |
| Gateway or bridge | forwarded traffic involving the suspicious address |
| Passive mirror port | nothing directly; there is no control plane |

## Implemented Capabilities

- Five operator workspaces with a view drawer and `Esc` return navigation.
- Eight terminal themes, including accessible and high-contrast choices.
- SocketScope Linux PID/UID/process attribution and per-process traffic totals.
- RouteLedger egress learning, persisted baselines, and drift detection.
- TLS ClientHello metadata, JA4, ECH awareness, and key-log correlation.
- QUIC invariant header, connection ID, packet-type, and migration inspection.
- EvidenceVault freeze-on-critical PCAP, JSON, and NDJSON artifacts.
- WirePulse passive DNS, TCP handshake, and gateway latency measurements.
- NetRegistry local prefix enrichment and operator-requested WHOIS refresh.
- Local `/health` and OpenMetrics `/metrics` telemetry endpoints.
- Expiring, audited nftables containment in preview, manual, and auto modes.
- Optional Linux Landlock filesystem-write sandbox.
- Replay regression fixtures for shipped penetration signature families.

## Remaining Engineering Work

These gaps are intentionally stated precisely; the current UI does not claim
that they are complete.

- Add an optional eBPF event collector for sockets too short-lived for `/proc`
  polling, with a narrow privilege-separated IPC contract.
- Perform authenticated TLS record decryption using legitimately supplied key
  logs; current support parses and correlates secrets only.
- Decrypt protected QUIC packets, decode HTTP/3 frames, and add JA4Q.
- Separate capture and firewall privileges into a minimal helper, then drop
  capabilities in the terminal process. Landlock currently limits filesystem
  writes but is not a privilege boundary for packet capture.
- Add a stronger automatic-containment policy gate, such as two independent
  critical signals or a rule explicitly approved for automatic response.
- Add attributable online fingerprint reputation data only as an explicit,
  cached operator action; no silent external lookups.
- Expand replay fixtures as each new detector and containment policy ships.

These remaining items require focused security design and should not be
represented as simple parser or UI additions.
