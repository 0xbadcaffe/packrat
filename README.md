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
| **2 Analysis**  | Protocol stats, top talkers, conversations, port summary |
| **3 Strings**   | Extracted strings with entropy scoring, RE dictionary, live search |
| **4 Dynamic**   | Live syscall / signal / network trace log |
| **5 Visualize** | Protocol bars, traffic sparkline, top IPs, geo endpoints |
| **6 Topology**  | Flow graph with circular node layout and per-protocol edge colors |

## Protocol Support

### IT / Internet protocols

`TCP` `UDP` `DNS` `mDNS` `HTTP` `HTTPS` `TLS` `SSH` `SMTP` `IMAP` `POP3`
`DHCP` `NTP` `ICMP` `ICMPv6` `QUIC` `SNMP` `ARP` `MySQL` `PostgreSQL` `Redis` `MongoDB`

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

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Space` | Start / Stop capture |
| `j/k` `↑↓` | Navigate |
| `g / G` | Top / Bottom |
| `1–6` | Switch tabs |
| `/` | Filter (packet filter on most tabs; string search on Strings tab) |
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
