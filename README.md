# 🐀 packrat

> A Wireshark-style network packet analyzer, **reverse engineering**, and **security research** TUI built with **Rust + Ratatui**.

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
# Demo / simulated traffic (no libpcap required)
cargo install packrat-tui
packrat

# Real interface capture + real traceroute
cargo install packrat-tui --features real-capture
packrat
```

## Feature Overview

| Tab | Key | Description |
|-----|-----|-------------|
| **Packets**    | `1` | Live packet list, protocol detail tree, hex dump, follow-stream overlay |
| **Analysis**   | `2` | Protocol stats, top talkers, conversations, port summary, magic bytes, XOR, anomalies |
| **Strings**    | `3` | Extracted ASCII strings with entropy scoring, RE dictionary, live search |
| **Dynamic**    | `4` | Live syscall / signal / network event log |
| **Visualize**  | `5` | Protocol sparkline, traffic bars, top IPs, geo endpoints |
| **Flows**      | `6` | Bidirectional flow tracker — beacon/scan/encrypted/large detection, follow stream |
| **Craft**      | `7` | Form-based packet builder with hex preview, inject, and **flood mode** |
| **Traceroute** | `8` | Hop-by-hop path tracer (real `traceroute`/`tracert` under `--features real-capture`) |
| **Security**   | `9` | Passive IDS, credential extraction, OS fingerprinting, ARP watch, DNS tunnel detection, HTTP analytics, TLS weakness, brute-force detection, vuln patterns, PCAP replay |
| **Scanner**    | `0` | Port scanner — TCP Connect, SYN, UDP modes with service fingerprinting |

---

## Packet Crafter (Tab 7)

Build arbitrary packets from a field form, preview the raw bytes live, then inject or flood.

### Fields

| Field | Example | Notes |
|-------|---------|-------|
| Protocol | `TCP` `UDP` `ICMP` `DNS` `HTTP` `ARP` | Sets IP protocol byte and L4 parsing |
| Src IP | `192.168.1.100` | IPv4 dotted-decimal |
| Dst IP | `10.0.0.1` | IPv4 dotted-decimal |
| Src Port | `4444` | TCP/UDP only; leave blank for ICMP |
| Dst Port | `80` | TCP/UDP only |
| TTL | `64` | 1–255 |
| IP Flags | `DF` `MF` `DF+MF` `0x40` | IPv4 Don't Fragment / More Fragments |
| L4 Flags | `SYN` `ACK` `SYN+ACK` `PSH+ACK` `FIN+ACK` `RST` | **TCP** — any combination with `+` |
|          | `8:0` `echo-request` `ping` `echo-reply` `3:3` | **ICMP** — type:code or named |
|          | `0x1234` | **UDP** — hex checksum override |
|          | `0x02` or decimal `18` | Raw hex / decimal for any protocol |
| Info | `ping test` | Human-readable label (auto-generated if blank) |
| Payload | `deadbeef` `48656c6c6f` | Hex bytes appended after transport header |

### Keyboard controls

| Key | Action |
|-----|--------|
| `Tab / j / k` | Move between fields |
| `Enter / e` | Start editing focused field |
| `Esc / Enter` | Confirm edit |
| `Space / x` | Inject one packet |
| `f` | **Toggle flood mode** |
| `< / >` | Decrease / increase flood rate |
| `C` | Clear result / stop flood |
| `h` | Help |

### Flood mode

Press **`f`** to start sending packets continuously at the configured rate. Adjust with **`<`** and **`>`**:

```
1 pps → 10 pps → 100 pps → 1000 pps → 10 000 pps
```

The status bar shows the live sent count:

```
● FLOODING  1000pps  sent:4823  [f] stop  [</>] rate  [C] reset
```

### Example: SYN flood simulation

```
Protocol   TCP
Src IP     192.168.1.50
Dst IP     10.0.0.1
Dst Port   80
TTL        64
IP Flags   DF
L4 Flags   SYN
```
Press `f`, then `>` to ramp up rate. Switch to the Packets tab (key `1`) to watch packets arrive.

### Example: ICMP echo (ping) burst

```
Protocol   ICMP
Src IP     10.1.2.3
Dst IP     8.8.8.8
TTL        128
L4 Flags   echo-request
Payload    48656c6c6f
```
Press `Space` for a single ping or `f` to ping flood.

### Example: custom TCP payload

```
Protocol   TCP
Src IP     192.168.0.10
Dst IP     192.168.0.20
Src Port   5555
Dst Port   9999
L4 Flags   PSH+ACK
Payload    474554202f20485454502f312e310d0a
```

---

## Security Tab (Tab 9)

Passive real-time security analysis across 10 sub-panels. Navigate with `[` / `]` or the letter shortcuts below.

### Sub-panels

| Key | Panel | What it detects |
|-----|-------|-----------------|
| `a` | **IDS Alerts** | EternalBlue (MS17-010), BlueKeep (CVE-2019-0708), Log4Shell (CVE-2021-44228), Heartbleed, PrintNightmare, NOP sleds, directory traversal (`../`), SQL injection, XSS, LLMNR/NBNS poisoning, Pass-the-Hash, SMB null sessions |
| `c` | **Credentials** | Cleartext usernames and passwords from HTTP Basic Auth, FTP, Telnet, SMTP AUTH, LDAP bind |
| `o` | **OS Fingerprint** | Passive TTL + TCP window size matching — identifies Windows, Linux, macOS, iOS, Android, Cisco, FreeBSD |
| `w` | **ARP Watch** | IP→MAC mapping table; fires alert on any MAC change (ARP spoofing / MITM) |
| `d` | **DNS Tunnel** | Per-apex-domain scoring: query frequency + subdomain entropy + label length → flags iodine/dnscat2-style tunneling |
| `u` | **HTTP Analytics** | Method, path, response code, User-Agent for all HTTP sessions |
| `t` | **TLS Weakness** | TLS 1.0, SSL 3.0, RC4 cipher suites (0x0005/0x000a), SHA-1 OID in certificates |
| `b` | **Brute Force** | 30-second sliding window per (src, dst, port); threshold 5 attempts — covers SSH/FTP/HTTP 401/SMB |
| `v` | **Vuln Patterns** | Cleartext sensitive HTTP paths (`/admin`, `/passwd`), weak Telnet, anonymous FTP, WMI over network |
| `p` | **PCAP Replay** | Load and replay any `.pcap` file at variable speed |

### IDS alert severities

| Severity | Color | Examples |
|----------|-------|---------|
| CRITICAL | red | EternalBlue, Log4Shell, BlueKeep |
| HIGH | orange | Heartbleed, PrintNightmare, Pass-the-Hash |
| MEDIUM | yellow | SQL injection, XSS, NOP sled |
| LOW | green | LLMNR/NBNS probe, directory traversal |

### Security tab keyboard

| Key | Action |
|-----|--------|
| `[ / ]` or `Tab / Shift-Tab` | Cycle sub-panels |
| `a c o w d u t b v p` | Jump directly to a sub-panel |
| `j / k` | Scroll rows |
| `g / G` | Top / bottom |
| `C` | Clear all security data |

### PCAP Replay (sub-panel `p`)

Load a `.pcap` file and replay it at adjustable speed into the live packet stream:

```
File:    /path/to/capture.pcap     [e] to edit
Speed:   4x                        [<] slower  [>] faster
Status:  ● playing  1234/5678 pkts
[████████░░░░░░░░░░] 42%
```

| Key | Action |
|-----|--------|
| `e` | Edit file path |
| `Enter` | Load file |
| `Space` | Play / stop |
| `< / >` | Halve / double speed (0.125x → 64x) |

Speed steps: `0.125x → 0.25x → 0.5x → 1x → 2x → 4x → 8x → 16x → 32x → 64x`

---

## Port Scanner (Tab 0)

Scan a host for open ports. Three scan modes:

| Mode | Description |
|------|-------------|
| **TCP Connect** | Full TCP handshake — works as any user, cross-platform |
| **SYN** | Half-open SYN scan (simulated in demo mode; real with `--features real-capture` + root) |
| **UDP** | UDP probe with service fingerprinting |

### Fields and controls

| Field | Example |
|-------|---------|
| Target | `192.168.1.1` `scanme.nmap.org` |
| Port range | `1` – `1024` |
| Mode | Tab through: TCP Connect → SYN → UDP |

| Key | Action |
|-----|--------|
| `Tab / j / k` | Move between fields |
| `Enter / e` | Edit field |
| `m` | Cycle scan mode |
| `Space / x` | Start / stop scan |
| `Esc` | Cancel scan |
| `PgDn / PgUp` | Scroll results |
| `C` | Clear results |

### Result columns

```
Port    State     Service            Banner
22      open      SSH                OpenSSH 8.9p1 Ubuntu
80      open      HTTP               Apache/2.4.54
443     open      HTTPS
8080    filtered  HTTP-Alt
3306    closed    MySQL
```

### Example: scan a local host

```
Target     192.168.1.1
Port range 1 – 65535
Mode       TCP Connect
```
Press `Space` to start. Results populate in real time as ports are probed.

---

## Traceroute (Tab 8)

Type a hostname or IP, press `Enter` to trace:

```
Target: 8.8.8.8   [Enter] start  [Esc] clear  [j/k] scroll

Hop  IP               RTT        Hostname
  1  192.168.1.1      1.2 ms     router.local
  2  10.0.0.1         4.8 ms     -
  3  72.14.215.165    8.1 ms     -
  4  *                timeout
  5  8.8.8.8          11.3 ms    dns.google
```

Under `--features real-capture` the system `traceroute` (Linux/macOS) or `tracert` (Windows) is used. Falls back to simulation automatically if the command is unavailable.

---

## Flows Tab (Tab 6)

Tracks all bidirectional TCP/UDP flows and flags suspicious behavior automatically:

| Badge | Meaning |
|-------|---------|
| `[BEACON]` | Periodic inter-arrival CV < 0.15, mean interval > 0.5s — possible C2 heartbeat |
| `[LARGE]` | Flow exceeds 1 MB — bulk transfer or exfiltration candidate |
| `[ENCRYPTED]` | Payload entropy > 7.2 bits/byte — likely encrypted or compressed |
| `[SCAN]` | Source IP seen on 5+ distinct destinations — port/host scan |

| Key | Action |
|-----|--------|
| `b / p / t / s` | Sort by bytes / packets / time / beacon score |
| `f` | Follow Stream overlay (TCP payload, both directions) |
| `Enter` | Jump to filtered Packets view for this flow |

### Follow Stream

Shows the TCP conversation as printable ASCII, color-coded by direction (→ initiator, ← responder):

```
→ GET /secret HTTP/1.1..Host: 10.0.0.1..
← HTTP/1.1 200 OK..Content-Type: text/plain..password=hunter2
```

---

## Protocol Support

### Layer 2 / Encapsulation
`Ethernet II` `IEEE 802.3` `VLAN (802.1Q/QinQ)` `MPLS` `PPPoE` `VXLAN` `GRE` `WireGuard`

### Layer 3 / Network
`IPv4` `IPv6` `ARP` `ICMP` `ICMPv6` `IGMP` `GRE` `VRRP` `IPSec ESP` `IPSec AH`

### Layer 4
`TCP` `UDP` `GTP v1`

### Application protocols

| Protocol | Port | Notes |
|----------|------|-------|
| DNS / mDNS | 53 / 5353 | A/AAAA/MX/CNAME records |
| DHCP / DHCPv6 | 67–68 / 546–547 | Discover/Offer/Request/ACK, Solicit/Advertise |
| NTP | 123 | v3/v4, stratum, reference timestamps |
| PTP (IEEE 1588) | 319/320 | Sync, Delay_Req, Follow_Up, Announce |
| HTTP | 80/8080 | GET/POST/PUT/DELETE, URI, Host, response code |
| HTTPS/TLS | 443 | TLS 1.3, handshake, cipher suite |
| SSH | 22 | Key exchange |
| FTP | 20/21 | USER, PASS, RETR, STOR, PASV |
| Telnet | 23 | IAC option negotiation |
| SMTP | 25/587 | AUTH, MAIL FROM, RCPT TO |
| IMAP / POP3 | 143 / 110 | Mail retrieval |
| SIP | 5060/5061 | INVITE, BYE, ACK, REGISTER, Call-ID |
| BGP | 179 | OPEN, UPDATE, KEEPALIVE, AS path, NLRI |
| LDAP | 389 | Bind, Search, Modify |
| RADIUS | 1812/1813 | Access-Request/Accept/Reject, Accounting |
| QUIC | 443 | RFC 9000, Connection ID |
| SNMP | 161/162 | Trap / query |
| VXLAN | 4789 | VNI, inner Ethernet/IP |
| GTP | 2152 | v1/v2, G-PDU, TEID |
| MySQL / PostgreSQL / Redis / MongoDB | 3306/5432/6379/27017 | |
| Kafka | 9092 | Produce, Fetch, Metadata |
| AMQP / NATS | 5672 / 4222 | Messaging protocols |
| Docker / etcd | 2375 / 2379 | Container/cluster APIs |
| RTSP | 554 | Media streaming |
| RTP / STUN | 5004 / 3478 | Real-time media and NAT traversal |
| SSDP / NBNS | 1900 / 137 | Discovery and NetBIOS |
| OSPF / EIGRP / RIP | 89 / 88 / 520 | Routing protocols |
| PIM / IGMP | — | Multicast |
| TFTP / TFTP | 69 | Trivial file transfer |

### OT / Industrial protocols

| Protocol | Port | Notes |
|----------|------|-------|
| Modbus/TCP | 502 | FC1–FC16, unit ID, register address |
| MQTT | 1883/8883 | CONNECT, PUBLISH, SUBSCRIBE, topics, QoS |
| OPC-UA | 4840 | Read/Write/Browse, node IDs |
| DNP3 | 20000 | Outstation addressing, function codes |
| CoAP | 5683/5684 | CON/NON/ACK/RST, URI paths |
| BACnet/IP | 47808 | BVLC, object/property |
| S7comm | 102 | Siemens S7 PLC, DB reads/writes |
| EtherNet/IP | 44818 | CIP encapsulation, RegisterSession |
| IEC-104 | 2404 | IEC 60870-5-104 SCADA |
| SOME/IP | 30490 | Automotive service-oriented |
| DoIP | 13400 | Automotive diagnostics over IP |

---

## Dissectors

packrat supports three levels of protocol dissection — from zero-config scripting to compiled-in built-ins.

### Lua dissectors (Wireshark-compatible, hot-reload)

Drop a `.lua` file in `~/.config/packrat/plugins/` and press **`r`** to load or hot-reload without restarting.

**Supported Wireshark API:**

| Object | Description |
|--------|-------------|
| `Proto(name, desc)` | Declare a new protocol |
| `ProtoField.uint8/16/32/64(abbr, label, base)` | Typed field descriptors |
| `ProtoField.bytes/string/bool/ipv4/ether(...)` | Additional field types |
| `base.HEX`, `base.DEC`, `base.OCT`, `base.ASCII` | Display bases |
| `DissectorTable.get("tcp.port"):add(port, proto)` | Register by TCP/UDP port |
| `buf(offset, length)` → TvbRange | Slice packet payload |
| `range:uint()` `:uint8()` `:uint16()` `:uint32()` | Integer extraction |
| `range:int()` `:string()` `:bytes_hex()` `:tohex()` | String / hex extraction |
| `pinfo.src_port`, `pinfo.dst_port` | Port access |
| `pinfo.cols.protocol = "NAME"` | Override protocol column |
| `tree:add(field, range)` | Add typed field to detail tree |
| `tree:add(proto, buf(), "Label")` | Add subtree section |
| `tree:add("Label", value)` | Add plain string field |

**Minimal example — custom protocol on TCP 9999:**

```lua
local myproto = Proto("MyProto", "My Custom Protocol")

local f_magic = ProtoField.uint16("myproto.magic", "Magic", base.HEX)
local f_cmd   = ProtoField.uint8 ("myproto.cmd",   "Command", base.DEC)
local f_data  = ProtoField.bytes ("myproto.data",  "Payload")

myproto.fields = { f_magic, f_cmd, f_data }

function myproto.dissector(buf, pinfo, tree)
    if buf:len() < 3 then return end
    pinfo.cols.protocol = "MyProto"
    local subtree = tree:add(myproto, buf(0, buf:len()), "My Protocol")
    subtree:add(f_magic, buf(0, 2))
    subtree:add(f_cmd,   buf(2, 1))
    if buf:len() > 3 then
        subtree:add(f_data, buf(3, buf:len() - 3))
    end
end

DissectorTable.get("tcp.port"):add(9999, myproto)
```

**Industrial protocol example — Modbus/TCP with register parsing:**

```lua
local modbus = Proto("Modbus", "Modbus/TCP")

local f_tid  = ProtoField.uint16("modbus.tid",  "Transaction ID", base.HEX)
local f_pid  = ProtoField.uint16("modbus.pid",  "Protocol ID",    base.HEX)
local f_len  = ProtoField.uint16("modbus.len",  "Length",         base.DEC)
local f_uid  = ProtoField.uint8 ("modbus.uid",  "Unit ID",        base.DEC)
local f_fc   = ProtoField.uint8 ("modbus.fc",   "Function Code",  base.DEC)
local f_reg  = ProtoField.uint16("modbus.reg",  "Register",       base.DEC)
local f_cnt  = ProtoField.uint16("modbus.cnt",  "Count",          base.DEC)

modbus.fields = { f_tid, f_pid, f_len, f_uid, f_fc, f_reg, f_cnt }

local FC_NAMES = {
    [1]="Read Coils", [2]="Read Discrete Inputs",
    [3]="Read Holding Registers", [4]="Read Input Registers",
    [5]="Write Single Coil", [6]="Write Single Register",
    [15]="Write Multiple Coils", [16]="Write Multiple Registers",
}

function modbus.dissector(buf, pinfo, tree)
    if buf:len() < 8 then return end
    pinfo.cols.protocol = "Modbus/TCP"
    local fc = buf(7, 1):uint()
    local fc_name = FC_NAMES[fc] or ("FC " .. fc)
    local sub = tree:add(modbus, buf(0, buf:len()), "Modbus/TCP  " .. fc_name)
    sub:add(f_tid, buf(0, 2))
    sub:add(f_pid, buf(2, 2))
    sub:add(f_len, buf(4, 2))
    sub:add(f_uid, buf(6, 1))
    sub:add(f_fc,  buf(7, 1))
    if buf:len() >= 12 then
        sub:add(f_reg, buf(8,  2))
        sub:add(f_cnt, buf(10, 2))
    end
end

DissectorTable.get("tcp.port"):add(502, modbus)
```

Install plugins:

```bash
mkdir -p ~/.config/packrat/plugins
cp plugins/example_myproto.lua ~/.config/packrat/plugins/
# In packrat, press r — status bar shows: Lua: 1 files, 1 dissectors loaded
```

**Bundled examples:**

| File | Protocol | Port |
|------|----------|------|
| `plugins/example_myproto.lua` | MyProto | TCP 9999 |
| `plugins/example_modbus.lua` | Modbus/TCP | TCP 502 |
| `plugins/example_mqtt.lua` | MQTT 3.1.1 | TCP 1883/8883 |

### TOML dissectors (static field layouts, no scripting)

For fixed-format protocols without conditional logic. Drop a `.toml` file in `~/.config/packrat/dissectors/`:

```toml
name      = "MyProto"
transport = "tcp"
port      = 9999

[[fields]]
offset  = 0
length  = 2
name    = "Magic"
display = "hex"

[[fields]]
offset  = 2
length  = 1
name    = "Command"
display = "dec"

[[fields]]
offset  = 3
length  = 4
name    = "Payload Length"
display = "dec"
```

---

## Strings Tab (Tab 3)

Extracts printable ASCII runs from packet payloads and classifies them using a built-in RE/security dictionary.

**Stats bar:** total strings · sensitive count (red) · average entropy · most common category

**Entropy column:**
- Low `0–3` — human-readable, good RE target
- Medium `3–5` — mixed content
- High `5–8` — likely encrypted or compressed

**Categories:**

| Category | Examples |
|----------|---------|
| `sensitive` | `password=`, `secret`, `private_key`, `token=` |
| `key` | `BEGIN RSA`, `api_key=`, `ssh-rsa`, `Authorization: Bearer` |
| `shell` | `/bin/sh`, `cmd.exe`, `system(`, `exec(` |
| `ot-proto` | `modbus`, `bacnet`, `opc-ua`, `dnp3` |
| `http` / `http-hdr` | `GET /api`, `Cookie:`, `X-Forwarded-For:` |
| `sql` | `SELECT`, `INSERT`, `DROP TABLE`, `UNION SELECT` |
| `jwt` | `eyJ…` base64 JWT tokens |
| `path` | `/etc/passwd`, `C:\Windows\`, `../../` |
| `domain` / `ip` | `api.example.com`, `192.168.1.1` |

Press **`/`** to search, **Enter** to keep filter, **Esc** to clear.

---

## Analysis Tab (Tab 2)

| Section | Description |
|---------|-------------|
| Protocol distribution | Packet and byte counts per protocol |
| Top talkers | Busiest source IPs by byte volume |
| Conversations | Unique src→dst pairs with packet counts |
| Port summary | Top destination ports with protocol guess |
| **Magic Bytes** | Detects ELF, PE/EXE, PNG, JPEG, ZIP, PDF, gzip, OGG, SQLite, SSH key, PEM, and more |
| **XOR Analysis** | Brute-forces single-byte XOR (keys 1–255), reports candidates with >70% printable result |
| **Anomaly Report** | Non-standard ports, SSH/HTTP on unexpected ports, high-entropy cleartext, beacons, scans |

---

## PCAP Recording and Replay

**Record:**

Press **`w`** at any time to start writing a `.pcap` file (named `packrat_<timestamp>.pcap` in the current directory). Press **`w`** again to flush and close.

**Replay:**

Go to Security tab → Replay sub-panel (`9` then `p`):

1. Press `e`, type the path to a `.pcap` file, press `Enter`
2. Press `Enter` again to load
3. Press `Space` to start playback
4. Adjust speed with `<` / `>`

Replayed packets flow into the live packet list, trigger security analysis, and can be recorded to a new pcap.

---

## Keyboard Reference

### Global

| Key | Action |
|-----|--------|
| `1`–`0` | Switch tabs |
| `Space` | Start/stop capture |
| `j / k` `↑ ↓` | Navigate |
| `g / G` | Top / bottom |
| `/` | Filter (or string search on Strings tab) |
| `i` | Pick interface |
| `w` | Toggle PCAP recording |
| `r` | Hot-reload Lua plugins |
| `h` | Help overlay |
| `C` | Clear |
| `q` | Quit |

### Craft tab (7)

| Key | Action |
|-----|--------|
| `Tab / j / k` | Move field focus |
| `Enter / e` | Edit field |
| `Space / x` | Inject one packet |
| `f` | Toggle flood mode |
| `< / >` | Decrease / increase flood rate |
| `C` | Stop flood, clear result |

### Security tab (9)

| Key | Action |
|-----|--------|
| `[ / ]` | Previous / next sub-panel |
| `a c o w d u t b v p` | Jump to sub-panel |
| `j / k` | Scroll |
| `g / G` | Top / bottom |
| `C` | Clear all |

### Flows tab (6)

| Key | Action |
|-----|--------|
| `b / p / t / s` | Sort by bytes / packets / time / beacon score |
| `f` | Follow Stream overlay |
| `Enter` | Jump to Packets view for this flow |

---

## Filter Syntax

```
tcp                   # protocol name
dns
http

ip.src==192.168.1.1   # source IP
ip.dst==8.8.8.8       # destination IP
tcp.port==443         # port (src or dst)
udp.port==53
```

Filters update the packet list in real time as you type.

---

## Platform Support

| Platform | Status |
|----------|--------|
| Linux | ✅ Full support including real capture and real traceroute |
| macOS | ✅ Full support |
| Windows | ✅ Simulated mode; real capture requires Npcap |
| WSL2 | ✅ |

For cross-compilation targets (x86, ARM, PPC, GCC, Clang, MSVC, QEMU) see [BUILD.md](https://github.com/0xbadcaffe/packrat/blob/master/BUILD.md).

---

## License

MIT — see [LICENSE](LICENSE)
