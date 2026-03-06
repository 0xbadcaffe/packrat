# 🐀 packrat — Build Instructions

## Prerequisites

### 1. Install Rust

All platforms — run this once:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env   # Linux / macOS
# Windows: restart your terminal after the installer finishes
```

Verify:
```bash
rustc --version   # should print rustc 1.75.0 or newer
cargo --version
```

---

## Simulated Mode (no libpcap needed)

This is the default. No extra dependencies — just build and run:

```bash
cd packrat
cargo run                    # dev build (fast compile, slower binary)
cargo build --release        # optimised binary
./target/release/packrat     # Linux / macOS
.\target\release\packrat.exe # Windows
```

---

## Real Capture Mode (requires libpcap / Npcap)

Enable with the `real-capture` feature flag. Requires installing the packet
capture library for your OS first.

---

### Linux

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# Fedora / RHEL / CentOS
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap

# Build packrat with real capture
cargo build --release --features real-capture

# Run — requires root for raw socket access
sudo ./target/release/packrat
```

To run without sudo, grant the binary the `cap_net_raw` capability:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/packrat
./target/release/packrat   # no sudo needed after this
```

---

### macOS

libpcap ships with macOS. You just need the Xcode Command Line Tools:

```bash
xcode-select --install   # if not already installed

# Build
cargo build --release --features real-capture

# Run — requires root
sudo ./target/release/packrat
```

To avoid sudo on macOS, add yourself to the `access_bpf` group:

```bash
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
# Log out and back in, then run without sudo
./target/release/packrat
```

---

### Windows

Windows does not have libpcap built-in. You need **Npcap**:

1. **Install Npcap** (the WinPcap-compatible packet capture driver):
   - Download from https://npcap.com/#download
   - Run the installer — tick **"Install Npcap in WinPcap API-compatible Mode"**

2. **Install the Npcap SDK** (needed to compile):
   - Download the SDK zip from https://npcap.com/#download
   - Extract it, e.g. to `C:\npcap-sdk`

3. **Set the LIB environment variable** so the Rust linker can find it:

   ```powershell
   # PowerShell — adjust path if you extracted elsewhere
   $env:LIB = "C:\npcap-sdk\Lib\x64"
   ```

   Or set it permanently in System → Advanced → Environment Variables.

4. **Build**:

   ```powershell
   cargo build --release --features real-capture
   ```

5. **Run as Administrator** (required for raw packet access):

   ```powershell
   # Right-click Windows Terminal → "Run as administrator", then:
   .\target\release\packrat.exe
   ```

---

## Selecting a Network Interface

By default packrat uses the first available interface. To pick a specific one,
set the `PACKRAT_IFACE` environment variable:

```bash
PACKRAT_IFACE=eth0 ./target/release/packrat         # Linux
PACKRAT_IFACE=en0  ./target/release/packrat         # macOS (Wi-Fi)
$env:PACKRAT_IFACE="Ethernet"; .\packrat.exe        # Windows PowerShell
```

List available interfaces:

```bash
# Linux / macOS
ip link show        # or: ifconfig

# Windows
Get-NetAdapter      # PowerShell
```

---

## Cross-Compilation

Build for multiple platforms from a single machine using
[cross](https://github.com/cross-rs/cross):

```bash
cargo install cross

# Linux x86_64 (from any host)
cross build --release --target x86_64-unknown-linux-gnu

# Windows (from Linux/macOS) — simulated mode only (no Npcap cross-compile)
cross build --release --target x86_64-pc-windows-gnu

# macOS arm64 (Apple Silicon) — requires macOS host
cargo build --release --target aarch64-apple-darwin
```

For automated multi-platform releases, see
[cargo-dist](https://opensource.axo.dev/cargo-dist/).

---

## Common Build Errors

| Error | Fix |
|-------|-----|
| `cannot find -lpcap` | Install libpcap-dev (Linux) or Npcap SDK (Windows) |
| `Permission denied (os error 13)` | Run with `sudo` or grant `cap_net_raw` |
| `No such device` | Check interface name with `ip link` / `ifconfig` |
| `VCRUNTIME140.dll not found` | Install [Visual C++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe) |
| `linker 'cc' not found` | `sudo apt install build-essential` (Linux) or `xcode-select --install` (macOS) |

---

## Running Tests

```bash
cargo test
cargo test --features real-capture   # include capture module tests
```
