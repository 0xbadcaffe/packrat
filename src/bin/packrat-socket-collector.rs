#[cfg(all(target_os = "linux", feature = "ebpf-sockets"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    collector::run()
}

#[cfg(not(all(target_os = "linux", feature = "ebpf-sockets")))]
fn main() {
    eprintln!("packrat-socket-collector requires Linux and --features ebpf-sockets");
    std::process::exit(2);
}

#[cfg(all(target_os = "linux", feature = "ebpf-sockets"))]
#[path = "packrat-socket-collector/collector.rs"]
mod collector;
