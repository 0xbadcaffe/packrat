use rand::Rng;

#[derive(Debug, Clone)]
pub enum EntryKind { Syscall, Signal, Network }

#[derive(Debug, Clone)]
pub struct DynEntry {
    pub ts: f64,
    pub kind: EntryKind,
    pub name: String,
    pub args: String,
    pub retval: String,
}

const SYSCALLS: &[&str] = &[
    "read","write","open","close","stat","fstat","poll","mmap","mprotect","munmap",
    "brk","ioctl","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg",
    "bind","listen","getsockname","setsockopt","fork","execve","exit","kill",
    "fcntl","flock","fsync","getcwd","chdir","rename","mkdir","unlink","lseek",
    "select","dup2","nanosleep","getpid","getuid","clone","wait4","access",
];
const SIGNALS: &[&str] = &[
    "SIGSEGV","SIGABRT","SIGFPE","SIGBUS","SIGTERM","SIGKILL","SIGUSR1","SIGCHLD","SIGPIPE",
];
const LOCAL_IPS: &[&str] = &["192.168.1.1","192.168.1.42","10.0.0.1"];
const REMOTE_IPS: &[&str] = &["8.8.8.8","1.1.1.1","142.250.80.46"];

static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

pub fn generate_entry(_tick: u32) -> DynEntry {
    let start = START.get_or_init(std::time::Instant::now);
    let ts = start.elapsed().as_secs_f64();
    let mut rng = rand::thread_rng();

    let r: u8 = rng.gen_range(0..10);
    if r == 0 {
        let sig = SIGNALS[rng.gen_range(0..SIGNALS.len())];
        DynEntry {
            ts,
            kind: EntryKind::Signal,
            name: sig.to_string(),
            args: format!("→ received by PID {}", rng.gen_range(1000..9999)),
            retval: String::new(),
        }
    } else if r == 1 {
        let src = LOCAL_IPS[rng.gen_range(0..LOCAL_IPS.len())];
        let dst = REMOTE_IPS[rng.gen_range(0..REMOTE_IPS.len())];
        let protos = ["TCP","UDP","DNS","TLS"];
        let proto = protos[rng.gen_range(0..protos.len())];
        DynEntry {
            ts,
            kind: EntryKind::Network,
            name: "NETPKT".into(),
            args: format!("{} {} → {} len={}", proto, src, dst, rng.gen_range(64..=1460)),
            retval: String::new(),
        }
    } else {
        let sc = SYSCALLS[rng.gen_range(0..SYSCALLS.len())];
        let args = gen_args(sc, &mut rng);
        let ret_neg = rng.gen_bool(0.08);
        let retval = if ret_neg {
            format!("-{}", rng.gen_range(1..=22))
        } else {
            rng.gen_range(0..=1000u32).to_string()
        };
        DynEntry {
            ts,
            kind: EntryKind::Syscall,
            name: sc.to_string(),
            args,
            retval,
        }
    }
}

fn gen_args(sc: &str, rng: &mut impl Rng) -> String {
    match sc {
        "read"    => format!("{}, 0x{:06x}, {}", rng.gen_range(0..20u8), rng.r#gen::<u32>() & 0xffffff, rng.gen_range(1..4096u16)),
        "write"   => format!("{}, 0x{:06x}, {}", rng.gen_range(0..20u8), rng.r#gen::<u32>() & 0xffffff, rng.gen_range(1..1024u16)),
        "open"    => {
            let files = ["/etc/resolv.conf","/var/log/syslog","/proc/net/tcp","/dev/urandom","/etc/passwd"];
            format!("\"{}\", O_RDONLY, 0644", files[rng.gen_range(0..files.len())])
        }
        "socket"  => {
            let fam = ["AF_INET","AF_INET6","AF_UNIX"][rng.gen_range(0..3)];
            let typ = ["SOCK_STREAM","SOCK_DGRAM"][rng.gen_range(0..2)];
            format!("{}, {}, 0", fam, typ)
        }
        "connect" => {
            let ip = REMOTE_IPS[rng.gen_range(0..REMOTE_IPS.len())];
            format!("{}, {{AF_INET, htons({}), \"{}\"}}, 16", rng.gen_range(3..20u8), rng.gen_range(1..65535u16), ip)
        }
        "sendto"  => format!("{}, 0x{:06x}, {}, 0", rng.gen_range(3..20u8), rng.r#gen::<u32>() & 0xffffff, rng.gen_range(1..4096u16)),
        "recvfrom"=> format!("{}, 0x{:06x}, {}, 0", rng.gen_range(3..20u8), rng.r#gen::<u32>() & 0xffffff, rng.gen_range(1..4096u16)),
        "mmap"    => format!("NULL, {}, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0", rng.gen_range(4096..65536u32)),
        "execve"  => {
            let bins = ["\"/bin/bash\"","\"/usr/bin/python3\"","\"/bin/sh\"","\"/usr/bin/curl\""];
            format!("{}, [...], [...]", bins[rng.gen_range(0..bins.len())])
        }
        "kill"    => format!("{}, SIG{}", rng.gen_range(1..9999u16), ["TERM","KILL","HUP","USR1"][rng.gen_range(0..4)]),
        _         => format!("{}, 0x{:06x}", rng.gen_range(0..10u8), rng.r#gen::<u32>() & 0xffffff),
    }
}
