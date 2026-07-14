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
an explicit startup choice gated by either an `auto_contain` critical user rule
or two independent critical detectors for the same attacker and target. Linux
enforcement uses validated IP addresses and expiring nftables sets; protected
and unsafe address classes are rejected.

Approved containment can use the built-in nftables backend or `--latch-helper`,
which delegates firewall changes to a minimal external command over a JSON
stdin/stdout contract.

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
- TLS ClientHello metadata, JA4, ECH awareness, key-log correlation, and
  helper-backed authenticated record decode.
- QUIC invariant header, connection ID, packet-type, migration inspection, and
  helper-backed protected QUIC/HTTP3 frame summaries.
- EvidenceVault freeze-on-critical PCAP, JSON, and NDJSON artifacts.
- WirePulse passive DNS, TCP handshake, and gateway latency measurements.
- NetRegistry local prefix enrichment and operator-requested WHOIS refresh.
- Explicit reputation refresh helper for selected addresses, JA4, and RatQ; no
  silent lookups.
- Long-lived newline-delimited TLS decode helper IPC for high-rate captures.
- Long-lived newline-delimited QUIC/HTTP3 helper IPC for high-rate captures.
- Optional privilege-separated capture helper with bounded binary frame IPC;
  packet parsing and policy remain in the unprivileged TUI.
- Local `/health` and OpenMetrics `/metrics` telemetry endpoints.
- Expiring, audited nftables containment in preview, manual, and auto modes.
- Optional Linux Landlock filesystem-write sandbox.
- Replay coverage for shipped IDS signatures and VLAN penetration indicators.

## Remaining Engineering Work

These gaps are intentionally stated precisely; the current UI does not claim
that they are complete.

- Add an optional eBPF event collector for sockets too short-lived for `/proc`
  polling. Packrat can now import external socket ownership CSV rows with
  `--socket-events`; a kernel collector and helper IPC are still separate work.
- Keep replay fixtures current as each new detector and containment policy ships.

These remaining items require focused security design and should not be
represented as simple parser or UI additions.
