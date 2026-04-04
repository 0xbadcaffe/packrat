# 🐀 packrat

> A Wireshark-style network packet analyzer TUI built with **Rust + Ratatui**.

> Crates.io package: `packrat-tui`
> Installed binary: `packrat`

<p align="center">
  <img src="https://raw.githubusercontent.com/0xbadcaffe/packrat/master/assets/packrat-screenshot.svg" alt="Packrat TUI screenshot" />
</p>

```
                     __                   __
___________    ____ |  | ______________ _/  |_
\____ \__  \ _/ ___\|  |/ /\_  __ \__  \\   __\
|  |_> > __ \\  \___|    <  |  | \// __ \|  |
|   __(____  /\___  >__|_ \ |__|  (____  /__|
|__|       \/     \/     \/            \/
```

## Install

```bash
# Demo/simulated traffic mode (no libpcap/Npcap required)
cargo install packrat-tui
packrat
```

```bash
# Real interface capture support
cargo install packrat-tui --features real-capture
packrat
```

## Features

| Tab | Contents |
|-----|----------|
| **1 Packets**   | Live packet list with protocol tree + hex dump |
| **2 Analysis**  | Protocol stats, top talkers, conversations, port summary, magic bytes, XOR, anomalies |
| **3 Strings**   | Extracted strings with entropy scoring, RE dictionary, live search |
| **4 Dynamic**   | Live syscall / signal / network trace log |
| **5 Visualize** | Protocol bars, traffic sparkline, top IPs, geo endpoints |
| **6 Topology**  | Flow graph with circular node layout and per-protocol edge colors |
| **7 Flows**     | Bidirectional flow tracker with beacon/scan/encrypted/large detection |

## Protocol Support

### Layer 2 / Encapsulation

`Ethernet II` `IEEE 802.3` `VLAN (802.1Q/QinQ)` `MPLS` `PPPoE` `VXLAN` `GRE` `WireGuard`

### Layer 3 / Network

`IPv4` `IPv6` `ARP` `ICMP` `ICMPv6` `IGMP` `GRE` `VRRP` `IPSec ESP` `IPSec AH`

### Layer 4 / Transport & Tunneling

`TCP` `UDP` `GTP v1`

### IT / Internet protocols

| Protocol | Port | Transport | Notes |
|----------|------|-----------|-------|
| **DNS** / mDNS | 53 / 5353 | UDP | Query/response, A/AAAA/MX/CNAME records |
| **DHCP** | 67/68 | UDP | Discover, Offer, Request, ACK |
| **DHCPv6** | 546/547 | UDP | Solicit, Advertise, Request, Reply |
| **NTP** | 123 | UDP | v3/v4, stratum, reference timestamps, Root Delay/Dispersion |
| **PTP (IEEE 1588)** | 319/320 | UDP | Sync, Delay_Req, Follow_Up, Announce, domainNumber, correctionField |
| **HTTP** | 80/8080 | TCP | GET/POST/PUT/DELETE, URI, Host |
| **HTTPS / TLS** | 443 | TCP | TLS 1.3, handshake type, cipher suite |
| **SSH** | 22 | TCP | Key exchange |
| **FTP** | 20/21 | TCP | USER, PASS, RETR, STOR, LIST, PASV |
| **Telnet** | 23 | TCP | IAC option negotiation |
| **SMTP** | 25/587 | TCP | Mail transfer |
| **IMAP** / IMAPS | 143/993 | TCP | Mail retrieval |
| **POP3** | 110 | TCP | Mail download |
| **SIP** / SIPS | 5060/5061 | UDP/TCP | INVITE, BYE, ACK, REGISTER, Via, Call-ID, CSeq |
| **BGP** | 179 | TCP | OPEN, UPDATE, NOTIFICATION, KEEPALIVE, AS path, NLRI |
| **LDAP** | 389 | TCP | Bind, Search, Modify, objectClass filters |
| **RADIUS** | 1812/1813 | UDP | Access-Request/Accept/Reject, Accounting |
| **QUIC** | 443 | UDP | RFC 9000, Connection ID |
| **SNMP** | 161/162 | UDP | Trap / query |
| **VXLAN** | 4789 | UDP | VNI, inner Ethernet/IP |
| **GTP** | 2152 | UDP | v1/v2, G-PDU, Create/Update PDP Context, TEID |
| **WireGuard** | 51820 | UDP | Handshake Initiation/Response, Transport Data |
| **MySQL** | 3306 | TCP | |
| **PostgreSQL** | 5432 | TCP | |
| **Redis** | 6379 | TCP | |
| **MongoDB** | 27017 | TCP | |

### OT / Industrial protocols

| Protocol | Port | Transport | Notes |
|----------|------|-----------|-------|
| **Modbus/TCP** | 502 | TCP | FC1–FC16, unit ID, register address |
| **MQTT** / MQTT-TLS | 1883 / 8883 | TCP | CONNECT, PUBLISH, SUBSCRIBE, topics |
| **OPC-UA** | 4840 | TCP | Read/Write/Browse, node IDs, session |
| **DNP3** | 20000 | TCP/UDP | Outstation addressing, function codes |
| **CoAP** / CoAP-DTLS | 5683 / 5684 | UDP | CON/NON/ACK/RST, URI paths |
| **BACnet/IP** | 47808 | UDP | BVLC, object/property lookup |
| **S7comm** | 102 | TCP | Siemens S7, DB reads/writes, PLC control |
| **EtherNet/IP** | 44818 | TCP | CIP encapsulation, RegisterSession |
| **IEC-104** | 2404 | TCP | IEC 60870-5-104 SCADA transport |
| **SOME/IP** | 30490 | UDP/TCP | Automotive service-oriented, Service/Method ID |
| **DoIP** | 13400 | TCP | Automotive diagnostics over IP, Routing Activation |

All protocols are fully dissected in the **Analysis** tree (packet → transport → application layer fields).

## Strings Tab

The Strings tab extracts printable ASCII runs from packet payloads and classifies them using a built-in dictionary suited for **protocol reverse engineering and security analysis**.

**Stats bar** shows at a glance:
- Total strings found
- Sensitive string count (passwords, keys, shell commands) — highlighted red
- Average Shannon entropy across all strings
- Most common string category

**Entropy column** (0–8 bits/byte):
- 🟢 Low entropy — predictable, human-readable, good RE targets
- 🟡 Medium entropy — mixed content
- 🔴 High entropy — likely encrypted or compressed

**String categories:**

| Category | Examples |
|----------|---------|
| `sensitive` | `password=`, `secret`, `private_key` |
| `key` | `BEGIN RSA`, `api_key=`, `ssh-rsa` |
| `shell` | `/bin/sh`, `cmd.exe`, `system(` |
| `ot-proto` | `modbus`, `bacnet`, `opc-ua`, `dnp3` |
| `ot-field` | `holding register`, `coil`, `function code` |
| `ot-sys` | `plc`, `scada`, `hmi`, `outstation` |
| `ot-vendor` | `siemens`, `schneider`, `rockwell`, `omron` |
| `mqtt` | `sensors/temperature`, `PUBLISH`, `CONNACK` |
| `http` / `http-hdr` | `GET /api`, `Authorization:`, `Cookie:` |
| `sql` | `SELECT`, `INSERT`, `DROP` |
| `jwt` | `eyJ…` base64 JWT tokens |
| `base64` | Generic base64-encoded blobs |
| `path` | `/etc/passwd`, `C:\Windows\`, `.so` |
| `domain` / `ip` | `api.example.com`, `192.168.1.1` |
| `error` | `timeout`, `refused`, `exception` |
| `version` | `firmware`, `build`, `copyright` |

Press **`/`** on the Strings tab to open live search — type to filter strings by value or category, **Enter** to keep filter, **Esc** to clear.

## Custom Dissectors

packrat supports user-defined protocol dissectors loaded from TOML files. Drop a `.toml` file in `~/.config/packrat/dissectors/` and packrat will automatically apply it to matching packets, appending a custom section to the Analysis tree.

### Dissector file format

```toml
name      = "MyProto"     # displayed in the tree
transport = "tcp"         # "tcp" or "udp"
port      = 9999          # matched against src/dst port

[[fields]]
offset  = 0               # byte offset into transport payload
length  = 2               # number of bytes to read
name    = "Magic"         # field label
display = "hex"           # "hex", "dec", or "ascii"

[[fields]]
offset  = 2
length  = 1
name    = "Command"
display = "dec"

[[fields]]
offset  = 3
length  = 16
name    = "Payload"
display = "ascii"
```

Multiple dissector files can be loaded simultaneously. Dissectors are applied after the built-in parser so they can layer on top of any protocol that uses TCP/UDP.

## Flows Tab (Tab 7)

Tracks all bidirectional TCP/UDP flows and automatically flags suspicious behavior:

| Flag | Meaning |
|------|---------|
| `[BEACON]` | Periodic inter-arrival CV < 0.15, mean interval > 0.5s — possible C2 heartbeat |
| `[LARGE]` | Flow exceeds 1 MB — bulk transfer or exfiltration candidate |
| `[ENCRYPTED]` | Payload entropy > 7.2 bits/byte — likely encrypted or compressed |
| `[SCAN]` | Source IP seen communicating with 5+ distinct destinations — port/host scan |

Sort by **b**ytes, **p**ackets, or **t**ime. Press **Enter** on a flow to jump to filtered Packets view.

## Analysis Tab — Payload Inspector (sections 7–9)

| Section | Description |
|---------|-------------|
| **Magic Bytes** | Detects ELF, PE/EXE, PNG, JPEG, ZIP, PDF, gzip, LZ4, Zstd, OGG, RIFF, bzip2, SQLite, 7-Zip, SSH key, PEM at common offsets |
| **XOR Analysis** | Brute-forces single-byte XOR (keys 1–255) and reports candidates with >70% printable result — finds obfuscated payloads |
| **Anomaly Report** | Non-standard ports, SSH/HTTP banners on unexpected ports, high-entropy cleartext, beacon flows, scan activity |

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Space` | Start / Stop capture |
| `j/k` `↑↓` | Navigate |
| `g / G` | Top / Bottom |
| `1–7` | Switch tabs |
| `/` | Filter (packet filter on most tabs; string search on Strings tab) |
| `b / p / t` | Flows tab: sort by bytes / packets / time |
| `Enter` | Flows tab: jump to filtered packet view |
| `i` | Pick interface |
| `w` | Toggle PCAP recording |
| `h` | Help |
| `C` | Clear |
| `q` | Quit |

## Filter Syntax

```
tcp                    ip.src==192.168.1.1
dns                    ip.dst==8.8.8.8
http                   tcp.port==443
```

## Platform Support

| Platform | Terminal | Status |
|----------|----------|--------|
| Linux | Any | ✅ |
| macOS | iTerm2 / kitty | ✅ |
| Windows | Windows Terminal | ✅ |
| WSL2 | Any | ✅ |

For target, architecture, and toolchain details covering x86, x64, ARM, PPC, GCC, Clang, MSVC, and QEMU-based workflows, see [BUILD.md](https://github.com/0xbadcaffe/packrat/blob/master/BUILD.md).

## License

MIT — see [LICENSE](LICENSE)
