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

# Import socket ownership events captured by an external helper.
cargo run --features real-capture -- --socket-events /secure/socket-events.csv

# Restrict filesystem writes with Linux Landlock.
cargo run --features real-capture -- --sandbox
```

Run `cargo run -- --help` for the complete option list.

## Navigation

The top bar contains five workspaces. Press `1` through `5` to open their home
views. Press `Tab` or `F2` to open the current workspace's view drawer, and
`Esc` to return from a detail view to its workspace home.

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
3. Select a packet with `j`/`k`; press `Enter` to load it in Workbench.
4. Open Defense > Security and use `[`/`]` to move through detector and health
   views.
5. Use Graph to correlate hosts, flows, alerts, IOCs, credentials, and objects.
6. Press `X` to write a case bundle for handoff.

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

Use `[`/`]` in Security to cycle detector and operational views:

- SocketScope correlates Linux socket tables with PID, UID, process, command,
  and per-process packet/byte totals. For very short-lived sockets, start
  Packrat with `--socket-events PATH` to import helper-generated ownership rows.
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
and a Packrat RatQ fingerprint built from visible invariant metadata.

`--key-log` or `SSLKEYLOGFILE` loads TLS 1.2, TLS 1.3, and QUIC secret labels
and correlates available material by client random. Packrat does not yet decrypt
TLS records or protected QUIC/HTTP3 payloads; the UI marks that limitation
instead of presenting encrypted bytes as decoded content.

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
