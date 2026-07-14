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
mod collector {
    use std::convert::TryFrom;
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Write};
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    use aya::maps::{Array, RingBuf};
    use aya::programs::{FEntry, KProbe, TracePoint};
    use aya::{Btf, Ebpf};
    use packrat_tui::analysis::socket_ebpf::{compatibility_report, SocketEbpfEvent};

    struct Options {
        object: PathBuf,
        output: Option<PathBuf>,
        check_only: bool,
        stats_seconds: u64,
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let options = parse_args(std::env::args().skip(1))?;
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?
            .trim()
            .to_string();
        let tracepoint = Path::new("/sys/kernel/tracing/events/sock/inet_sock_set_state").exists()
            || Path::new("/sys/kernel/debug/tracing/events/sock/inet_sock_set_state").exists();
        let btf = Path::new("/sys/kernel/btf/vmlinux").exists();
        let report = compatibility_report(&release, tracepoint, btf);
        let kallsyms = std::fs::read_to_string("/proc/kallsyms").unwrap_or_default();
        let lifecycle_hooks = required_hooks_present(&kallsyms);
        if options.check_only {
            print_report(&release, &report, lifecycle_hooks);
            return if report.compatible && lifecycle_hooks {
                Ok(())
            } else {
                Err("kernel is not compatible".into())
            };
        }
        if !report.compatible || !lifecycle_hooks {
            let mut reasons = report.reasons.clone();
            if !lifecycle_hooks {
                reasons.push("required TCP/UDP lifecycle symbols are unavailable".into());
            }
            return Err(format!("incompatible kernel: {}", reasons.join("; ")).into());
        }

        let mut ebpf = Ebpf::load_file(&options.object)?;
        let program: &mut TracePoint = ebpf
            .program_mut("packrat_inet_sock_state")
            .ok_or("eBPF object lacks packrat_inet_sock_state")?
            .try_into()?;
        program.load()?;
        program.attach("sock", "inet_sock_set_state")?;

        let btf = Btf::from_sys_fs()?;
        attach_fentry(&mut ebpf, "packrat_udp_sendmsg", "udp_sendmsg", &btf)?;
        attach_fentry(&mut ebpf, "packrat_udp_recvmsg", "udp_recvmsg", &btf)?;
        attach_accept(&mut ebpf)?;

        let events = ebpf
            .take_map("EVENTS")
            .ok_or("eBPF object lacks EVENTS map")?;
        let lost_events = ebpf
            .take_map("LOST_EVENTS")
            .ok_or("eBPF object lacks LOST_EVENTS map")?;
        let mut ring = RingBuf::try_from(events)?;
        let lost = Array::<_, u64>::try_from(lost_events)?;
        drop_capabilities()?;

        let mut output = output_writer(options.output.as_deref())?;
        writeln!(
            output,
            "# protocol,local_addr,local_port,remote_addr,remote_port,pid,uid,process,command"
        )?;
        output.flush()?;
        let stats_interval = Duration::from_secs(options.stats_seconds.max(1));
        let mut last_stats = Instant::now();
        let mut received = 0_u64;
        let mut invalid = 0_u64;
        loop {
            let mut drained = false;
            let mut wrote = false;
            while let Some(item) = ring.next() {
                drained = true;
                match SocketEbpfEvent::decode(&item) {
                    Ok(event) if event.socket_fd.is_none() => {
                        writeln!(output, "{}", event.to_socket_scope_csv()?)?;
                        received += 1;
                        wrote = true;
                    }
                    Ok(_) | Err(_) => invalid += 1,
                }
            }
            if wrote {
                output.flush()?;
            }
            if last_stats.elapsed() >= stats_interval {
                let kernel_lost = lost.get(&0, 0).unwrap_or(0);
                writeln!(output, "# packrat-ebpf-stats received={received} kernel_lost={kernel_lost} userspace_invalid={invalid}")?;
                output.flush()?;
                last_stats = Instant::now();
            }
            if !drained {
                thread::sleep(Duration::from_millis(25));
            }
        }
    }

    fn attach_fentry(
        ebpf: &mut Ebpf,
        program_name: &str,
        function_name: &str,
        btf: &Btf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let program: &mut FEntry = ebpf
            .program_mut(program_name)
            .ok_or_else(|| format!("eBPF object lacks {program_name}"))?
            .try_into()?;
        program.load(function_name, btf)?;
        program.attach()?;
        Ok(())
    }

    fn attach_accept(ebpf: &mut Ebpf) -> Result<(), Box<dyn std::error::Error>> {
        let program: &mut KProbe = ebpf
            .program_mut("packrat_tcp_accept")
            .ok_or("eBPF object lacks packrat_tcp_accept")?
            .try_into()?;
        program.load()?;
        program.attach("inet_csk_accept", 0)?;
        Ok(())
    }

    fn output_writer(path: Option<&Path>) -> Result<Box<dyn Write>, std::io::Error> {
        match path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new().create(true).append(true).open(path)?;
                Ok(Box::new(BufWriter::new(file)))
            }
            None => Ok(Box::new(BufWriter::new(std::io::stdout()))),
        }
    }

    fn parse_args<I>(args: I) -> Result<Options, String>
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let mut object = PathBuf::from("/usr/libexec/packrat/packrat_socket.bpf.o");
        let mut output = None;
        let mut check_only = false;
        let mut stats_seconds = 5;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--object" => {
                    index += 1;
                    object = args.get(index).ok_or("--object requires a path")?.into();
                }
                "--output" => {
                    index += 1;
                    output = Some(args.get(index).ok_or("--output requires a path")?.into());
                }
                "--stats-seconds" => {
                    index += 1;
                    stats_seconds = args
                        .get(index)
                        .ok_or("--stats-seconds requires a value")?
                        .parse()
                        .map_err(|_| "invalid --stats-seconds value")?;
                }
                "--check" => check_only = true,
                "-h" | "--help" => return Err(usage().into()),
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
            index += 1;
        }
        Ok(Options {
            object,
            output,
            check_only,
            stats_seconds,
        })
    }

    fn usage() -> &'static str {
        "Usage: packrat-socket-collector [--check] [--object PATH] [--output PATH] [--stats-seconds N]"
    }

    fn print_report(
        release: &str,
        report: &packrat_tui::analysis::socket_ebpf::CompatibilityReport,
        lifecycle_hooks: bool,
    ) {
        println!("kernel={release}");
        println!("ring_buffer={}", report.ring_buffer);
        println!("socket_tracepoint={}", report.socket_tracepoint);
        println!("btf={}", report.btf);
        println!("lifecycle_hooks={lifecycle_hooks}");
        println!("compatible={}", report.compatible && lifecycle_hooks);
        for reason in &report.reasons {
            println!("reason={reason}");
        }
    }

    fn required_hooks_present(kallsyms: &str) -> bool {
        ["inet_csk_accept", "udp_sendmsg", "udp_recvmsg"]
            .iter()
            .all(|required| {
                kallsyms
                    .lines()
                    .any(|line| line.split_whitespace().nth(2) == Some(*required))
            })
    }

    fn drop_capabilities() -> Result<(), std::io::Error> {
        #[repr(C)]
        struct CapHeader {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct CapData {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        let result = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{parse_args, required_hooks_present};
        use std::path::PathBuf;

        #[test]
        fn parses_collector_options() {
            let options = parse_args([
                "--object",
                "/tmp/socket.bpf.o",
                "--output",
                "/tmp/events.csv",
                "--stats-seconds",
                "9",
                "--check",
            ])
            .unwrap();

            assert_eq!(options.object, PathBuf::from("/tmp/socket.bpf.o"));
            assert_eq!(options.output, Some(PathBuf::from("/tmp/events.csv")));
            assert_eq!(options.stats_seconds, 9);
            assert!(options.check_only);
        }

        #[test]
        fn rejects_incomplete_and_unknown_options() {
            assert!(parse_args(["--object"]).is_err());
            assert!(parse_args(["--stats-seconds", "zero"]).is_err());
            assert!(parse_args(["--unexpected"]).is_err());
        }

        #[test]
        fn requires_all_kernel_lifecycle_symbols() {
            let complete = "0 T inet_csk_accept\n0 T udp_sendmsg\n0 T udp_recvmsg\n";
            assert!(required_hooks_present(complete));
            assert!(!required_hooks_present(
                "0 T inet_csk_accept\n0 T udp_sendmsg\n"
            ));
        }
    }
}
