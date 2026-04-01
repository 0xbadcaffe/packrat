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
| **3 Strings**   | Extracted strings with sensitive data flagging |
| **4 Dynamic**   | Live syscall / signal / network trace log |
| **5 Visualize** | Protocol bars, traffic sparkline, top IPs, geo endpoints |
| **6 Topology**  | Host relationship map with packet flow summaries |

## Build From Source

```bash
# Install Rust (one-time) — https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/0xbadcaffe/packrat.git
cd packrat
cargo run                          # dev build
cargo build --release              # optimised binary
./target/release/packrat           # macOS / Linux
.\target\release\packrat.exe       # Windows
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Space` | Start / Stop capture |
| `j/k` `↑↓` | Navigate |
| `g / G` | Top / Bottom |
| `1–6` | Switch tabs |
| `/` | Filter |
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
