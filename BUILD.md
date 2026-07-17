# Building Packrat

This guide describes the build and runtime combinations supported by the
current source tree. The authoritative CLI option list for a built binary is:

```bash
packrat --help
```

## Toolchain

Packrat requires Rust 1.85 or newer.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version
cargo --version
```

On Windows, use rustup from a Visual Studio Build Tools developer environment
and restart the terminal after installation.

## Build Modes

### Analyzer with explicit simulation

The default Cargo feature set has no libpcap dependency:

```bash
cargo build --locked --release
./target/release/packrat --simulation
```

`--simulation` is a runtime option, not a Cargo feature. Without it, Packrat
starts in capture mode and opens the real interface selector. A binary built
without `real-capture` can inspect imported data and run simulation, but cannot
open a live interface.

### Live packet capture

Build with the optional capture feature after installing the platform capture
library:

```bash
cargo build --locked --release --features real-capture
./target/release/packrat
```

The feature also builds `packrat-capture-helper`.

### Linux eBPF socket collector

The Aya loader is a separate Linux binary:

```bash
cargo build --locked --release --features ebpf-sockets \
  --bin packrat-socket-collector
```

The kernel object is built separately with Clang; see [eBPF collector](#ebpf-collector).

## Platform Dependencies

### Debian and Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libpcap-dev
cargo build --locked --release --features real-capture
```

Direct capture normally requires elevated network privileges:

```bash
sudo ./target/release/packrat
```

Prefer the dedicated helper when possible:

```bash
sudo setcap cap_net_raw=eip ./target/release/packrat-capture-helper
./target/release/packrat \
  --capture-helper ./target/release/packrat-capture-helper
```

The TUI performs parsing, detection, storage, and rendering without capture
privileges. Stopping capture terminates the helper.

Other Linux package names:

```bash
# Fedora / RHEL
sudo dnf install gcc pkgconf-pkg-config libpcap-devel

# Arch Linux
sudo pacman -S base-devel libpcap
```

### macOS

macOS includes libpcap. Install the compiler tools, then build:

```bash
xcode-select --install
cargo build --locked --release --features real-capture
sudo ./target/release/packrat
```

Capture permission is controlled by macOS BPF device policy. Systems using the
`access_bpf` group must log out and back in after membership changes.

### Windows

The analyzer and simulation build natively with the MSVC Rust target:

```powershell
cargo build --locked --release
.\target\release\packrat.exe --simulation
```

Live capture requires Npcap and the Npcap SDK:

1. Install Npcap in WinPcap API-compatible mode.
2. Install the Npcap SDK.
3. Point `LIB` at the SDK's x64 library directory.
4. Build with `real-capture` from a Visual Studio developer shell.

```powershell
$env:LIB = "C:\npcap-sdk\Lib\x64"
cargo build --locked --release --features real-capture
.\target\release\packrat.exe
```

Run the terminal with the privileges required by the selected Npcap interface.

## Supported and Checked Targets

| Target | Default build | Live capture | CI |
|---|---:|---:|---:|
| Linux x86-64 | Yes | Yes | Native, capture, eBPF loader |
| Linux i686 | Yes | Requires target libpcap | `cross check` |
| Linux ARM64 | Yes | Deployment-specific | `cross check` |
| Linux ARMv7 hard-float | Yes | Deployment-specific | `cross check` |
| Linux PowerPC64LE | Yes | Deployment-specific | `cross check` |
| macOS hosted runner | Yes | Yes | Native |
| Windows x86-64 MSVC | Yes | Manual Npcap SDK setup | Native default build |

Apple targets are compiled on Apple hosts and MSVC targets on Windows hosts.
The Linux cross matrix uses `cross`; it does not attempt to compile Apple or
MSVC targets from Ubuntu without their SDKs.

Bare-metal and `thumb*` targets are not supported. Packrat requires `std`, a
host filesystem, Tokio, and a terminal.

## Linux Cross-Compilation

Install `cross` and build a default-feature Linux binary:

```bash
cargo install cross
cross build --locked --release --target aarch64-unknown-linux-gnu
cross build --locked --release --target armv7-unknown-linux-gnueabihf
cross build --locked --release --target powerpc64le-unknown-linux-gnu
cross build --locked --release --target i686-unknown-linux-gnu
```

Cross-building `real-capture` also requires libpcap headers and libraries for
the destination architecture inside the build image. Validate live capture on
the deployment kernel and interface; a successful link does not grant capture
permission.

QEMU can run a matching Linux guest after the binary is built. It is a runtime
environment, not a Rust target.

## eBPF Collector

The optional collector observes short-lived TCP connect/accept and UDP
send/receive socket activity that `/proc` polling may miss. It requires Linux
5.8 or newer; TCP accept and UDP hooks also require BTF and the expected kernel
symbols.

Install Clang and LLVM, then build the kernel object and loader:

```bash
sudo apt-get install -y clang llvm
./scripts/build-ebpf-socket-collector.sh
./target/release/packrat-socket-collector --check
```

Install the hardened service:

```bash
sudo ./scripts/install-ebpf-socket-collector.sh
sudo systemctl daemon-reload
sudo systemctl enable --now packrat-socket-collector.service
systemctl status packrat-socket-collector.service
```

Start Packrat with the event stream:

```bash
./target/release/packrat \
  --socket-events /run/packrat/socket-events.csv
```

The service receives `CAP_BPF` and `CAP_PERFMON` for loading, drops capabilities
after attachment, enables `no_new_privs`, and reports kernel ring-buffer losses.
Run the privileged deployment test on each supported kernel:

```bash
sudo ./scripts/test-ebpf-socket-collector.sh
```

## Runtime Options

```text
-s, --simulation           run the built-in simulated traffic scenario
    --key-log PATH         load NSS/SSLKEYLOGFILE TLS and QUIC secrets
    --tls-decrypt-helper P delegate authenticated TLS record decode to helper
    --quic-decode-helper P delegate protected QUIC/HTTP3 decode to helper
    --socket-events PATH   import socket ownership CSV from an external helper
    --capture-helper PATH  delegate packet capture to a privileged helper
    --latch-helper PATH    delegate TrafficLatch blocks to a JSON helper command
    --reputation-helper P  delegate explicit reputation refreshes to a helper
    --telemetry-listen A   expose /metrics and /health (example: 127.0.0.1:9477)
    --traffic-latch MODE   monitor, preview, manual, or auto (default: monitor)
    --latch-seconds N      automatic firewall expiry (default: 900)
    --protect-address IP   never contain this address; may be repeated
    --sandbox              restrict filesystem writes with Linux Landlock
-h, --help                 show this help
```

Example:

```bash
./target/release/packrat \
  --telemetry-listen 127.0.0.1:9477 \
  --traffic-latch preview \
  --latch-seconds 300 \
  --protect-address 192.0.2.10
```

## Verification

Run the same core checks used by CI:

```bash
cargo test --locked
cargo check --locked --features real-capture
cargo check --locked --features ebpf-sockets --bin packrat-socket-collector
```

The eBPF loopback test requires root and a compatible kernel, so it is a
deployment test rather than an unprivileged unit test.

## Common Failures

| Error | Resolution |
|---|---|
| `cannot find -lpcap` | Install the platform libpcap development package or configure the Npcap SDK |
| capture permission denied | Use the capture helper, capabilities, BPF policy, or required administrator privileges |
| `No such device` | Select an interface shown by Packrat's interface selector |
| `linker cc not found` | Install Linux build tools or Xcode Command Line Tools |
| eBPF compatibility check fails | Verify kernel version, BTF, tracepoints, symbols, and service capabilities |
| `--sandbox` rejected | Landlock sandboxing is Linux-only |
