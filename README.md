# 🐀 packrat

> A Wireshark-style network packet analyzer TUI, built with **Rust + Ratatui** in the style of **binsider**.

```
        .--~~,__
   :-....,-------,
        `-,,,  ,_      ;
          _,-' ,'\     ;
         (  ) .|  `-.-'
          `'   \    /(
                `~~~~~'

          packrat v0.1.0
     packet analyzer — binsider style
```

## Features

| Tab | Contents |
|-----|----------|
| **1 Packets**   | Live packet list with protocol tree + hex dump |
| **2 Analysis**  | Protocol stats, top talkers, conversations, port summary |
| **3 Strings**   | Extracted strings with sensitive data flagging |
| **4 Dynamic**   | Live syscall / signal / network trace log |
| **5 Visualize** | Protocol bars, traffic sparkline, top IPs, geo endpoints |

## Quick Start

```bash
# Install Rust (one-time) — https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

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
| `1–5` | Switch tabs |
| `/` | Filter |
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

## License

MIT — see [LICENSE](LICENSE)
