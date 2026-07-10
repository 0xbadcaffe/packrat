# Packrat User Manual

Packrat is a terminal network analyzer for live inspection, deep packet analysis,
and penetration detection. It is passive by default: it observes and records
traffic but does not modify network policy or block packets.

## Start Packrat

Build with live capture support:

```bash
cargo run --features real-capture
```

Start the release binary after building it:

```bash
cargo build --release --features real-capture
./target/release/packrat
```

Packrat opens an interface picker. Select the capture interface with `j`/`k` or
the arrow keys, then press `Enter`. Live capture access normally requires the
operating system permissions appropriate for the selected interface.

Use the deterministic built-in scenario for training, testing, and UI review:

```bash
cargo run -- --simulation
```

`--simulation` is explicit. Without it, Packrat selects a real interface.

## First Investigation

1. Start a capture and open the Packets tab with `1`.
2. Press `/`, enter an inspection filter, and press `Enter`.
3. Use `j`/`k` to select a packet. Press `Enter` to load it in Workbench.
4. Open Security with `9` for IDS, credential, VLAN, IOC, TLS, and replay views.
5. Use `G` for the Operator Graph when correlating hosts, flows, alerts, IOCs,
   credentials, and carved objects.
6. Press `X` to write a case bundle when the investigation needs to be handed off.

The `h` key opens the in-app keyboard reference. `q` exits, except while typing
in a field or interacting with a modal window.

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

`tcp.port` and `udp.port` match either source or destination port. `vlan.id` is
the inner customer VLAN; `vlan.outer` is the provider tag in a QinQ frame.

## Deep VLAN Inspection

Use the Security tab, then press `v`, to open VLAN intelligence. It presents
per-VLAN traffic and security findings. The detector currently calls out:

- QinQ double-tagging, a VLAN-hopping pattern
- DTP traffic on user-facing links
- MAC addresses crossing VLAN boundaries
- priority-code-point abuse
- native VLAN 1 exposure

Useful filters during a VLAN investigation:

```text
vlan.id == 30 and ip.src == 10.30.0.5
vlan.qinq == true
vlan.outer == 200 and vlan.id == 30
vlan.pcp == 7
```

## Critical Incident Workflow

Packrat opens a red alert overlay only for critical penetration evidence:

- Built-in critical exploit signatures, including supported critical CVE and
  protocol signatures.
- A user-defined rule with an `Alert` action at `Critical` severity.

High, medium, and low findings remain visible in the Security and Rules tabs
without interrupting the operator.

When a critical alert appears:

1. Read the detector, attacker, target, and evidence count in the red overlay.
2. Press `Enter` or `A` to open Analysis > Incident History.
3. Review the retained conversation traffic and the matching detector summary.
4. Press `C` in Incident History to acknowledge the alert.

Acknowledgement removes the active warning only. It does not delete the
incident or its retained packet history. Clearing the whole capture with `C`
from the normal packet/analysis views starts a new investigation and clears
incident history as well.

Packrat does not block traffic in this release. The alert explicitly states that
capture continues, so an operator never mistakes passive analysis for network
containment.

## User Detection Rules

Rules are JSON files loaded from `~/.config/packrat/rules/`. Create the
directory if it does not exist:

```bash
mkdir -p ~/.config/packrat/rules
```

The following rule creates a critical incident when a known administrative path
is accessed from an untrusted subnet. Save it as
`~/.config/packrat/rules/admin-path.json`, then open Rules with `R` and press
`r` to reload it.

```json
{
  "id": "external-admin-path",
  "name": "External administrative path access",
  "description": "Escalate requests from the untrusted range to management paths.",
  "enabled": true,
  "condition": {
    "And": [
      { "Contains": { "field": "src", "value": "198.51.100." } },
      { "Contains": { "field": "info", "value": "/admin" } }
    ]
  },
  "actions": [
    {
      "Alert": {
        "message": "Administrative path accessed from untrusted source",
        "severity": "Critical"
      }
    },
    { "Tag": { "tag": "incident-candidate" } },
    { "Log": { "message": "Review source and target immediately" } }
  ],
  "hits": 0
}
```

Rule conditions support `Contains`, `Equals`, numeric `Num`, plus `And`, `Or`,
and `Not`. Numeric fields include `frame.len`, `tcp.srcport`, `tcp.dstport`,
`port`, and `ip.ttl`. Rule action severities are `Info`, `Low`, `Medium`,
`High`, and `Critical`.

Start with narrow rules and test them against a saved PCAP or `--simulation`
before relying on them in production. Critical rules should be reserved for a
clear, reviewed containment threshold.

## Investigation Views

| Key | View | Typical use |
|---|---|---|
| `1` | Packets | inspect frames and load a packet into Workbench |
| `2` | Analysis | traffic summaries, anomalies, credentials, incident history |
| `6` | Flows | identify high-volume, scan, or beacon-like conversations |
| `9` | Security | IDS, credentials, ARP, DNS tunneling, TLS, VLAN, IOC findings |
| `H` | Hosts | inventory observed systems, services, tags, and OS guesses |
| `T` | TLS | inspect SNI, certificates, ciphers, and JA3/JA3S data |
| `O` | Objects | inspect carved files and YARA matches |
| `R` | Rules | review and reload local detection rules |
| `W` | Workbench | inspect protocol bytes and decoded fields |
| `G` | Graph | correlate investigation evidence and attack paths |
| `D` | Diff | compare current traffic to a saved baseline |

## PCAP and Case Handling

Press `L` to import a PCAP path into the same analysis pipeline used by live
capture. Press `w` to record the current capture to a PCAP. Press `X` to export
a JSON case bundle containing the capture summary and analysis artifacts.

Treat exported case bundles as investigation data. Store them in a controlled
case directory rather than the project root when they include production host
names, credentials, or other sensitive evidence.

## Operational Notes

- Use a capture point that can see the traffic you want to analyze; a workstation
  interface cannot see switched traffic that is not mirrored to it.
- Use an isolated test network for packet crafting, replay, and scanning.
- Keep capture files and case exports under your organization’s retention and
  access-control policy.
- A red alert is evidence requiring review, not proof by itself. Confirm the
  packet context, target role, and rule/signature scope before escalating.
