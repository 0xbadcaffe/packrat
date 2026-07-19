# 🐀 PACKRAT

```text
    ____  ___   ________ ______  ___  ______
   / __ \/   | / ____/ //_/ __ \/   |/_  __/
  / /_/ / /| |/ /   / ,< / /_/ / /| | / /
 / ____/ ___ / /___/ /| / _, _/ ___ |/ /
/_/   /_/  |_\____/_/ |_/_/ |_/_/  |_/_/
  [ CAPTURE ]---[ INSPECT ]---[ CORRELATE ]---[ DETECT ]
```

**Terminal-native deep packet inspection, deterministic penetration detection,
and evidence-driven network response.**

Packrat goes beyond packet viewing. It carries the same investigation context
from live traffic into decoded headers, reconstructed conversations, correlated
security findings, retained evidence, and controlled containment. The workflow
is keyboard-first and works on local consoles or remote shells.

Packrat has no AI or LLM analysis mode. Every finding, priority, recommendation,
and response gate comes from inspectable protocol logic, deterministic windows,
IOC/YARA matches, or operator-authored rules.

<p align="center">
  <img src="https://raw.githubusercontent.com/0xbadcaffe/packrat/master/assets/packrat-screenshot.svg" alt="Packrat terminal network analysis interface" />
</p>

## One Investigation, Not Twenty Disconnected Views

```text
LIVE TRAFFIC
    |
    +-- packet fields / bytes / VLAN stack / protocol decode
    +-- TCP streams / IPv6 fragments / TLS, DTLS and QUIC context
    +-- hosts / services / processes / carved objects
    |
CORRELATED FINDINGS
    |
    +-- IDS / ARP / authentication / DNS / TLS / IOC / YARA / rules
    +-- hit count / first evidence / last evidence / analyst disposition
    |
CASE EVIDENCE ----------------------> CONTROLLED RESPONSE
```

Packets, streams, hosts, alerts, objects, graph nodes, and notes can be pinned
to one investigation tray. Move between packet headers, bytes, flow context,
strings, encrypted-traffic metadata, and security evidence without losing the
selected artifact or stopping capture.

## What Packrat Does

| Stage | Capability |
|---|---|
| **Capture** | Real interfaces, explicit simulation, PCAP import/replay, privileged capture helper |
| **Inspect** | Header tree, byte interpretation, packet comparison, VLAN/QinQ inspection, object carving |
| **Reconstruct** | Out-of-order TCP streams, IPv4/IPv6 fragment integrity, searchable bidirectional payloads |
| **Understand encryption** | TLS/DTLS/QUIC metadata, JA3/JA3S/JA4/RatQ context, key-log and authenticated helper hooks |
| **Detect** | Stateful IDS, scans, spoofing, DHCP/DNS abuse, HTTP smuggling, industrial-policy violations, credential exposure |
| **Correlate** | Unified Alert Center, IOC/YARA/rule findings, host and service graph, explainable risk scoring |
| **Preserve** | Retained attacker traffic, notebook, project state, PCAP/JSON/NDJSON evidence, case export |
| **Respond** | Monitor, preview, approved manual, or policy-gated automatic Linux nftables containment |

## Start in Two Commands

Simulation is explicit and needs no packet-capture library:

```bash
cargo build --release
./target/release/packrat --simulation
```

Live capture is the default runtime mode and requires the `real-capture` build
feature plus libpcap or Npcap:

```bash
cargo build --release --features real-capture
sudo ./target/release/packrat
```

Packrat opens the interface selector. Use `j`/`k` and `Enter`. For a narrower
privilege boundary on Linux, grant capture capability to the dedicated helper
and keep the TUI unprivileged:

```bash
sudo setcap cap_net_raw=eip target/release/packrat-capture-helper
./target/release/packrat \
  --capture-helper ./target/release/packrat-capture-helper
```

See [BUILD.md](BUILD.md) for Linux, macOS, Windows/Npcap, cross-compilation,
eBPF socket attribution, and troubleshooting instructions.

## Operator Workflow

Packrat groups the interface into five workspaces:

| Key | Workspace | Primary views |
|---|---|---|
| `1` | **Traffic** | Packets, flows, hosts, encrypted sessions |
| `2` | **Inspect** | Investigation tray, analysis, strings, workbench, objects, diff |
| `3` | **Defense** | Alert Center, specialist detectors, rules, operator graph |
| `4` | **Actions** | Scanner, traceroute, packet craft |
| `5` | **Case** | Notebook and event history |

Core controls:

| Key | Action |
|---|---|
| `Tab` / `F2` | Open the current workspace's view drawer |
| `Esc` | Close a window or return to the workspace home |
| `Alt+Left` | Return to the previous screen |
| `Ctrl+P` / `?` | Search packets, hosts, and findings |
| `m` / `M` | Pin selected evidence or current context to the investigation tray |
| `,` | Open persistent Preferences |
| `h` | Open the scrollable keyboard reference |
| `X` | Export the current case bundle |
| `!` | Revoke active Guard blocks and force monitor mode |

## Deterministic Defense

The Alert Center correlates recurring detector output into findings instead of
flooding the operator with one row per packet. Each finding retains occurrence
count, first and last packet evidence, severity, source, recommendation, and an
analyst state and optional review recommendation: New, Reviewing, Confirmed,
Benign, Contained, or Closed.

Watch and Triage modes can pin urgent findings and add fixed, source-specific
review guidance. They never modify firewall policy. TrafficLatch containment is
separate and starts in `monitor` mode.

Automatic containment requires a critical rule explicitly marked for automatic
response or two independent critical detectors for the same attacker and
target. Blocks have short expirations, protected addresses are rejected, active
actions are bounded, and all decisions are audited. The global kill switch
attempts immediate revocation and records any failed revocation until expiry.

## Extensibility

- Local packet rules from `~/.config/packrat/rules/`
- IOC feeds and deterministic matching
- YARA scans over carved and reconstructed objects
- Hot-reloaded Lua dissectors
- TOML protocol layouts
- Privilege-separated capture, TLS/QUIC decode, reputation, and containment helpers
- Optional Linux eBPF collector for short-lived socket ownership
- OpenMetrics health and telemetry endpoint

## Build Features

| Cargo feature | Default | Purpose |
|---|---:|---|
| `real-capture` | No | Enable libpcap/Npcap capture and the capture helper |
| `ebpf-sockets` | No | Build the Linux Aya eBPF socket collector |

Useful checks:

```bash
cargo test --locked
cargo check --locked --features real-capture
cargo check --locked --features ebpf-sockets --bin packrat-socket-collector
```

## Documentation

- [User manual](docs/USER_MANUAL.md): investigations, filters, Alert Center, projects, evidence, and Guard
- [Build guide](BUILD.md): dependencies, platform builds, permissions, eBPF, and cross targets
- `packrat --help`: authoritative startup option list for the installed version

## Safety Model

Packrat observes by default. Simulation requires `--simulation`; live capture
requires an explicitly built capture feature and operating-system permission;
containment remains monitor-only unless the operator selects another mode.
Use preview mode, protected management addresses, short expirations, and a
privilege-separated helper before enabling response on production networks.

## License

MIT. See [LICENSE](LICENSE).
