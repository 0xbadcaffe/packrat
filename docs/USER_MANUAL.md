# Packrat User Manual

Packrat is a terminal network analyzer for live inspection, deep packet analysis,
and penetration detection. Capture and response are separate choices: live
capture is the default, while traffic containment remains monitor-only unless an
operator explicitly enables another TrafficLatch mode.

## Start Packrat

Build and start live capture support:

```bash
cargo run --features real-capture
```

Packrat opens an interface picker. Select an interface with `j`/`k` or the arrow
keys, then press `Enter`. Capturing an interface normally requires suitable
operating-system permissions.

Use the deterministic scenario for training and UI review:

```bash
cargo run -- --simulation
```

`--simulation` is explicit. Without it, Packrat selects a real interface.

Useful startup combinations:

```bash
# Expose local health and OpenMetrics endpoints.
cargo run --features real-capture -- --telemetry-listen 127.0.0.1:9477

# Correlate TLS/QUIC sessions with an NSS-compatible key log.
cargo run --features real-capture -- --key-log /secure/session-keys.log
SSLKEYLOGFILE=/secure/session-keys.log cargo run --features real-capture

# Delegate authenticated TLS record decode to a local helper.
cargo run --features real-capture -- \
  --key-log /secure/session-keys.log \
  --tls-decrypt-helper /usr/libexec/packrat-tls-decrypt

# Delegate protected QUIC/HTTP3 decode to a local helper.
cargo run --features real-capture -- --quic-decode-helper /usr/libexec/packrat-quic-decode

# Import socket ownership events captured by an external helper.
cargo run --features real-capture -- --socket-events /secure/socket-events.csv

# Delegate raw packet capture to the minimal privileged helper.
./target/release/packrat --capture-helper /usr/libexec/packrat-capture-helper

# Delegate TrafficLatch firewall changes to a minimal helper command.
cargo run --features real-capture -- --traffic-latch manual --latch-helper /usr/libexec/packrat-latch

# Delegate explicit reputation refreshes to a local helper command.
cargo run --features real-capture -- --reputation-helper /usr/libexec/packrat-reputation

# Restrict filesystem writes with Linux Landlock.
cargo run --features real-capture -- --sandbox
```

Run `cargo run -- --help` for the complete option list.

## Navigation

The top bar contains five workspaces. Press `1` through `5` to open their home
views. Press `Tab` or `F2` to open the current workspace's view drawer, and
`Esc` to return from a detail view to its workspace home.

The navigation header shows `Workspace > Screen`. Press `Alt+Left` to return
through recently visited screens, `Ctrl+P` to open the command palette, and `,`
to open Settings as a global window without leaving the current investigation.

| Key | Workspace | Included views |
|---|---|---|
| `1` | Traffic | Packets, Flows, Hosts, Encrypted |
| `2` | Inspect | Analysis, Strings, Visualize, Workbench, Objects, Diff |
| `3` | Defense | Security, Rules, Graph |
| `4` | Actions | Scanner, Traceroute, Craft |
| `5` | Case | Notebook, Dynamic |

Expert shortcuts such as `H`, `N`, `T`, `O`, `R`, `W`, `G`, and `D` remain
available. Press `h` for the keyboard reference. Press `\` to choose among
Dark Pro, White Classic, Matrix Green, VSCode Dark, VSCode Light, Accessible
Dark, Soft Light, and High Contrast themes.

## First Investigation

1. Start capture and use Traffic > Packets.
2. Press `/`, enter an inspection filter, and press `Enter`.
3. Select a packet with `j`/`k`; press `m` to add it to the investigation
   worklist or `Enter` to add it and open Investigate immediately.
4. Open Defense > Security to review the unified Alert Center. Use `[`/`]` for
   specialist detector and sensor-health views.
5. Use Graph to correlate hosts, flows, alerts, IOCs, credentials, and objects.
6. Press `X` to write a case bundle for handoff.

## Investigation Tray

The investigation tray retains typed context across workspaces. Press `M` on a
selected packet, flow, host, alert, carved object, graph node, or note to pin it.
The Alert Center also accepts lowercase `m`. Duplicate items are focused rather
than added twice, and `d` removes the active tray item.

The right-side Context Inspector follows the active tray item. Packet items use
the complete Headers, Bytes, Flow, Strings, Encrypted, Security, and Notes tool
set. Other item types show their retained host counters, alert reason and state,
object hash and YARA results, graph risk and evidence, or note metadata. If live
source data ages out, the tray entry remains visible and is marked unavailable
instead of displaying unrelated packet context.

For packet items, Investigate keeps one active packet while you move between Summary, Headers,
Bytes, Flow, Strings, Encrypted, Security, and Notes with `[`/`]`. Use `n`/`p`
to select another tray item without returning to live capture, `w` to show
or hide the tray, `d` to remove the active item, and `l` to return to the
packet list.

Press `=` to compare the active worklist packet with the next marked packet.
The comparison overlay omits capture time and frame number, then reports
changed/added/removed decoded fields and the first differing byte. `Esc` closes
the overlay without changing the active packet.

Headers is keyboard searchable. Press `/`, enter a field such as `tcp.seq`, and
press `Enter` to finish the search. Move with `j`/`k`; press `f` to apply a
supported field as a packet-list filter. Press `Enter` on a byte-backed field
to open Bytes at its exact packet offset.

Bytes highlights the selected byte in hexadecimal and ASCII and interprets the
same offset as unsigned and signed 8-bit data, big- and little-endian 16-bit
data, big-endian 32-bit data, bits, ASCII, and a 16-byte entropy window. Use
`h`/`l` for one byte, `j`/`k` for 16 bytes, `g`/`G` for the first or last byte,
`n`/`p` for another worklist packet, and `v` to return to live packets.

From Flow, press `s` to follow the reassembled TCP stream. Press `/` to search
printable payload bytes, `n`/`N` to move through matches, and `e` to export exact
`a-to-b` and `b-to-a` binary payload files. Reassembly buffers out-of-order
segments until gaps close, trims retransmissions/overlaps, handles sequence
wraparound, and delays FIN until preceding payload is complete.

## Packet Inspection Filters

Press `/` from most views to enter a display filter. Filters update the packet
list as you type.

```text
tcp
ip.src == 192.168.10.25
tcp.port == 443
udp.dstport in [53, 5353]
frame.len > 1400
dns.qname contains "example.net"
tcp and ip.dst == 10.0.0.10
not arp
vlan.id == 20
vlan.pcp >= 5
vlan.qinq == true
vlan.outer == 100
```

`tcp.port` and `udp.port` match either direction. `vlan.id` is the inner
customer VLAN; `vlan.outer` is the provider tag in a QinQ frame.

## Deep VLAN Inspection

Open Defense > Security and select VLAN Intelligence. It reports per-VLAN
traffic and detects QinQ double tagging, DTP traffic, MAC movement between
VLANs, priority-code-point abuse, and native VLAN 1 exposure.

```text
vlan.id == 30 and ip.src == 10.30.0.5
vlan.qinq == true
vlan.outer == 200 and vlan.id == 30
vlan.pcp == 7
```

## Critical Incident Workflow

Packrat opens a red alert overlay for critical built-in penetration signatures
and user rules whose `Alert` action has `Critical` severity. Lower-severity
findings remain in Defense without interrupting the operator.

1. Read the detector, attacker, target, and evidence count.
2. Press `Enter` or `A` to open Analysis > Incident History.
3. Review retained conversation traffic and the detector summary.
4. Press `C` to acknowledge the reviewed alert.

Acknowledgement removes the active warning but preserves incident history.
EvidenceVault also freezes each critical incident once as PCAP, JSON metadata,
and NDJSON beneath the platform data directory's `packrat/evidence` folder.

## Alert Center

Defense > Security opens on the Alert Center. It combines IDS, IOC, user-rule,
credential-exposure, and VLAN findings without discarding their source data.

| Key | Action |
|---|---|
| `j` / `k` | Select a finding |
| `f` | Cycle all, critical, high, medium, and low severity filters |
| `Enter` | Mark the selected finding as under review |
| `C` | Confirm the finding |
| `z` | Mark the finding benign |
| `K` | Record that containment was completed |
| `x` | Close the finding |
| `a` | Return to Alert Center from a specialist view |
| `e` | Open the raw IDS findings view |

These dispositions are operator review state; they do not silently alter rules
or firewall policy. Critical incidents continue to use the mandatory red review
overlay and TrafficLatch policy gates described below.

### Watch and Triage modes

Open Settings > Automation to cycle these deterministic modes:

| Mode | Behavior |
|---|---|
| `Off` | Record findings for manual review |
| `Watch` | Automatically pin new high and critical findings to the investigation tray |
| `Triage` | Watch behavior plus severity-based priority and source-specific next-step recommendations |

Recommendations are fixed local policy text based on finding source and
severity. There is no AI/LLM inference, external analysis request, or firewall
action in Watch or Triage mode.

## TrafficLatch Containment

TrafficLatch is `monitor` by default and does not change firewall policy. Linux
operators may explicitly select one of these modes:

| Mode | Behavior |
|---|---|
| `monitor` | record the critical incident only |
| `preview` | record the validated action that would be attempted |
| `manual` | queue an action; press `x` in reviewed Incident History to approve |
| `auto` | request an expiring nftables block only after the automatic-response gate passes |

Start with preview and protect management addresses:

```bash
cargo run --features real-capture -- \
  --traffic-latch preview \
  --latch-seconds 300 \
  --protect-address 192.0.2.10 \
  --protect-address 2001:db8::10
```

After validating policies and nftables permissions, replace `preview` with
`manual` or `auto`. TrafficLatch rejects loopback, unspecified, multicast,
broadcast, and protected addresses. Applied entries expire automatically and
all decisions are included in case exports.

Automatic mode requires one of these gates before it applies a block:

- the matching critical user rule has `"auto_contain": true`
- Packrat has at least two independent pending critical detectors for the same
  attacker and target

If neither gate passes, the action stays pending and can still be approved
manually with `x` after incident review.

### Guard simulation and emergency stop

Press `r` in the Alert Center to evaluate all pending critical incidents as if
Guard were enabled. The simulation applies the same independent-signal gate,
address validation, protection list, expiry, and maximum-active-block policy,
but never calls nftables or a latch helper. The status line reports eligible,
pending, and rejected decisions; Settings > Defense shows the report size.

Press `!` from any screen to engage the Guard kill switch. This immediately
forces TrafficLatch back to `monitor` and rejects future automatic actions.
Already-applied nftables entries keep their configured short expiry; Packrat
does not hide that limitation by claiming they were synchronously removed.

By default, Packrat applies approved Linux blocks with nftables from the TUI
process. For stricter privilege separation, start it with `--latch-helper PATH`.
The helper receives a JSON request on stdin and returns a JSON response on
stdout:

```json
{ "address": "203.0.113.9", "expires_seconds": 300 }
```

```json
{ "ok": true, "detail": "blocked 203.0.113.9 for 300 seconds" }
```

The helper should be a small local program with only the firewall privileges it
needs. Packrat records the helper result in the incident action history.

Containment only affects traffic controlled by the host running Packrat. An
endpoint can constrain its own traffic; a gateway can constrain forwarded
traffic; a passive mirror port has no enforcement path. Use narrowly reviewed
critical rules and preview mode before production deployment.

## User Detection Rules

Rules are loaded from `~/.config/packrat/rules/`. This example creates a
critical incident for administrative-path access from an untrusted range:

```json
{
  "id": "external-admin-path",
  "name": "External administrative path access",
  "description": "Escalate untrusted requests to management paths.",
  "enabled": true,
  "auto_contain": false,
  "condition": {
    "And": [
      { "Contains": { "field": "src", "value": "198.51.100." } },
      { "Contains": { "field": "info", "value": "/admin" } }
    ]
  },
  "actions": [
    { "Alert": { "message": "Untrusted administrative access", "severity": "Critical" } },
    { "Tag": { "tag": "incident-candidate" } }
  ],
  "hits": 0
}
```

Open Rules with `R` and press `r` to reload. Conditions include `Contains`,
`Equals`, numeric `Num`, `And`, `Or`, and `Not`. Numeric fields include
`frame.len`, TCP/UDP ports, `port`, and `ip.ttl`. Test rules against a saved
PCAP or `--simulation` before enabling response actions.

## Defense Inspection

### Short-lived socket attribution

On Linux 5.8 or newer, build and install the separate eBPF collector:

```bash
./scripts/build-ebpf-socket-collector.sh
./target/release/packrat-socket-collector --check
sudo ./scripts/install-ebpf-socket-collector.sh
sudo systemctl daemon-reload
sudo systemctl enable --now packrat-socket-collector.service
```

Then add the event stream when starting Packrat:

```bash
./target/release/packrat --socket-events /run/packrat/socket-events.csv
```

The collector attaches to the TCP state, TCP accept, and UDP send/receive kernel
hooks, drops its load-time capabilities, and records PID, UID, process,
endpoint, and protocol fields. A
non-zero `eBPF lost` value means the kernel ring buffer could not reserve space;
the missing events cannot be reconstructed, so inspect system load before
relying on complete attribution. `/proc` polling continues to supplement the
event collector for established sockets.

Use `[`/`]` in Security to cycle detector and operational views:

- Stateful packet-integrity checks detect conflicting IPv4 fragments,
  bounded out-of-order IPv6 fragment reassembly, fragment floods, malformed TCP
  headers, conflicting TCP retransmissions, illegal flag combinations, and
  payload continuing after an observed reset.
- Scan correlation detects vertical, horizontal, NULL, FIN, Xmas, ICMP sweep,
  empty-UDP probe, and SYN-flood behavior over bounded time windows.
- IPv6 and Layer-2 checks validate Neighbor Discovery hop limits, track NDP
  binding changes, detect invalid or flooded Router Advertisements, excessive
  IPv6 extension chains, STP topology changes, and LLDP identity changes.
- Behavioral correlation reports periodic fixed-size C2 candidates,
  asymmetric or high-entropy outbound transfers, NXDOMAIN bursts, oversized
  DNS TXT traffic, direct public resolver use, administrative-service fan-out,
  and NTLM authentication fan-out.
- Protocol policy checks detect DHCP server changes and starvation, DNS
  transaction/question spoofing, HTTP request-framing ambiguities, and
  state-changing Modbus, DNP3, S7comm, and BACnet operations.

- SocketScope correlates Linux socket tables with PID, UID, process, command,
  and per-process packet/byte totals. For short-lived TCP and UDP sockets, run
  the optional Linux eBPF collector and start Packrat with
  `--socket-events /run/packrat/socket-events.csv`. Packrat imports appended
  rows without restarting and shows the collector's kernel-loss count in the
  SocketScope title.
- RouteLedger records process/host-to-destination routes. Press `l` to cycle
  Observe, Learn, and Detect Drift modes; press `y` to promote observations.
  Its baseline is `~/.config/packrat/route-baseline.json`.
- WirePulse passively measures DNS transaction and TCP handshake latency and
  labels the default gateway when Linux route data is available.
- NetRegistry enriches observed addresses from
  `~/.config/packrat/identity-map.csv`. Press `r` for an explicit WHOIS refresh.
  It also loads offline reputation rows from
  `~/.config/packrat/reputation-map.csv`.

The identity map uses `CIDR,ASN,organization` rows and longest-prefix matching:

```csv
# CIDR,ASN,organization
10.20.0.0/16,,Corporate laboratory
203.0.113.0/24,AS64500,Example transit
2001:db8:42::/48,AS64501,Example IPv6 edge
```

The reputation map uses `target,severity,label,source`. Targets may be an IP,
CIDR, JA4 value, or RatQ value. This is offline operator-supplied context; no
external reputation lookup runs during packet ingestion.

```csv
# target,severity,label,source
203.0.113.9,high,test sinkhole,lab blocklist
198.51.100.0/24,medium,partner watch range,change ticket 1842
ratq1_deadbeefcafe,medium,known QUIC client shape,malware lab
```

For explicit online or API-backed reputation checks, start Packrat with
`--reputation-helper PATH`. Select an address in NetRegistry and press `r`, or
select a TLS JA4 / QUIC RatQ row in Traffic > Encrypted and press `r`. The
helper receives JSON on stdin and returns JSON on stdout:

```json
{ "kind": "address", "target": "203.0.113.9" }
```

Fingerprint refreshes use the same shape with `"kind": "fingerprint"` and the
selected JA4 or RatQ value as `target`.

```json
{
  "ok": true,
  "severity": "high",
  "label": "listed by partner feed",
  "source": "partner-feed:2026-07-11"
}
```

Packrat caches the returned finding in the current case. Without
`--reputation-helper`, `r` keeps the older explicit WHOIS behavior for selected
public addresses in NetRegistry.

Socket event imports use this CSV shape:

```csv
# protocol,local_addr,local_port,remote_addr,remote_port,pid,uid,process,command
tcp,192.0.2.10,4444,198.51.100.7,443,4242,1000,curl,curl https://example.test
```

## Encrypted Traffic

Traffic > Encrypted switches between TLS and QUIC scope with `[`/`]`. TLS
ClientHello inspection includes SNI, ALPN, supported versions, cipher and
extension metadata, ECH-offered state, and JA4. QUIC scope reports invariant
header fields, version, connection IDs, packet type, address migration signals,
and a Packrat RatQ fingerprint built from visible invariant metadata. Press `r`
with `--reputation-helper` configured to refresh the selected JA4 or RatQ
reputation explicitly.

`--key-log` or `SSLKEYLOGFILE` loads TLS 1.2, TLS 1.3, and QUIC secret labels
and correlates available material by client random. `--tls-decrypt-helper PATH`
delegates authenticated TLS record decoding to a local helper. Packrat keeps one
helper process running and exchanges newline-delimited JSON request/response
pairs. Each request includes the flow id, packet number, client random, and TLS
record bytes; plaintext is retained only when the helper returns `ok: true`.

```json
{
  "flow_id": "192.0.2.10:50000-198.51.100.7:443",
  "packet_no": 42,
  "client_random": "001122...",
  "record_hex": "170303..."
}
```

The helper must write exactly one single-line JSON response for each request
and flush stdout. If the process exits or returns malformed JSON, Packrat drops
that response and starts a fresh helper process for a later record.

```json
{
  "ok": true,
  "content_type": "http",
  "plaintext_hex": "474554202f20485454502f312e31",
  "detail": "authenticated by helper"
}
```

`--quic-decode-helper PATH` delegates protected QUIC/HTTP3 decode to a local
helper. Packrat reuses one helper process and exchanges newline-delimited JSON
request/response pairs containing the connection id, packet number, and packet
bytes. Returned frame summaries are stored only when the helper returns `ok:
true`. The helper must flush one single-line response for each request.

```json
{
  "connection_id": "0102030405060708",
  "packet_no": 42,
  "packet_hex": "c000000001..."
}
```

```json
{
  "ok": true,
  "frames": [
    { "frame_type": "headers", "detail": "GET /" }
  ],
  "detail": "authenticated by helper"
}
```

## PCAP, Evidence, and Telemetry

Press `L` to import a PCAP through the normal analysis pipeline, `w` to record
capture, and `X` to export a JSON case bundle. Case exports include incidents,
evidence locations, process traffic, route drift, latency, identity enrichment,
and containment decisions.

Enable local telemetry only when needed:

```bash
cargo run --features real-capture -- --telemetry-listen 127.0.0.1:9477
curl http://127.0.0.1:9477/health
curl http://127.0.0.1:9477/metrics
```

The endpoint is unencrypted and unauthenticated, so bind it to loopback or put
it behind an appropriate local service boundary.

## Operational Notes

- Use a capture point that can see the relevant traffic; switched traffic
  requires a suitable endpoint, bridge, tap, or mirror configuration.
- Use an isolated test network for packet crafting, replay, scanning, and
  containment validation.
- Keep PCAPs, key logs, evidence, and case exports under organizational access
  and retention controls.
- A red alert is evidence requiring review, not proof by itself. Confirm packet
  context, target role, and signature or rule scope before escalating.
