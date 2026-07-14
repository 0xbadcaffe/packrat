//! Versioned socket-event contract shared with the optional eBPF collector.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const SOCKET_EVENT_VERSION: u16 = 1;
pub const SOCKET_EVENT_SIZE: usize = 80;
pub const MINIMUM_RINGBUF_KERNEL: KernelVersion = KernelVersion { major: 5, minor: 8 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketEventKind {
    TcpConnect = 1,
    TcpAccept = 2,
    UdpSend = 3,
    UdpReceive = 4,
}

impl TryFrom<u8> for SocketEventKind {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::TcpConnect),
            2 => Ok(Self::TcpAccept),
            3 => Ok(Self::UdpSend),
            4 => Ok(Self::UdpReceive),
            _ => Err(format!("unsupported socket event kind {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
}

impl KernelVersion {
    pub fn parse(release: &str) -> Result<Self, String> {
        let mut parts = release.split(['.', '-']);
        let major = parts
            .next()
            .ok_or("kernel release is empty")?
            .parse()
            .map_err(|_| format!("invalid kernel release: {release}"))?;
        let minor = parts
            .next()
            .ok_or_else(|| format!("kernel release lacks a minor version: {release}"))?
            .parse()
            .map_err(|_| format!("invalid kernel release: {release}"))?;
        Ok(Self { major, minor })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEbpfEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub family: u16,
    pub protocol: u8,
    pub kind: SocketEventKind,
    pub socket_fd: Option<i32>,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub process: String,
}

impl SocketEbpfEvent {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != SOCKET_EVENT_SIZE {
            return Err(format!(
                "socket event must be {SOCKET_EVENT_SIZE} bytes, got {}",
                bytes.len()
            ));
        }
        let version = read_u16(bytes, 0)?;
        if version != SOCKET_EVENT_VERSION {
            return Err(format!("unsupported socket event version {version}"));
        }
        let declared_size = read_u16(bytes, 2)? as usize;
        if declared_size != SOCKET_EVENT_SIZE {
            return Err(format!(
                "socket event declares invalid size {declared_size}"
            ));
        }
        let family = read_u16(bytes, 12)?;
        let protocol = bytes[14];
        let kind = SocketEventKind::try_from(bytes[15])?;
        let (local_addr, remote_addr, socket_fd) = match (kind, protocol) {
            (SocketEventKind::TcpConnect | SocketEventKind::TcpAccept, 6)
            | (SocketEventKind::UdpSend | SocketEventKind::UdpReceive, 17) => (
                decode_address(family, &bytes[48..64])?,
                decode_address(family, &bytes[64..80])?,
                None,
            ),
            (
                SocketEventKind::TcpAccept | SocketEventKind::UdpSend | SocketEventKind::UdpReceive,
                0,
            ) if family == 0 => {
                let fd = read_u32(bytes, 20)? as i32;
                if fd < 0 {
                    return Err(
                        "file-descriptor socket event contains a negative descriptor".into(),
                    );
                }
                (
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    Some(fd),
                )
            }
            _ => {
                return Err(format!(
                    "socket event kind {kind:?} has invalid protocol {protocol}"
                ));
            }
        };
        let comm_end = bytes[32..48]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(16);
        let process = std::str::from_utf8(&bytes[32..32 + comm_end])
            .map_err(|_| "socket event process name is not UTF-8")?
            .trim()
            .to_string();
        if process.is_empty() {
            return Err("socket event process name is empty".into());
        }
        Ok(Self {
            timestamp_ns: read_u64(bytes, 24)?,
            pid: read_u32(bytes, 4)?,
            uid: read_u32(bytes, 8)?,
            family,
            protocol,
            kind,
            socket_fd,
            local_addr,
            local_port: read_u16(bytes, 16)?,
            remote_addr,
            remote_port: read_u16(bytes, 18)?,
            process,
        })
    }

    pub fn to_socket_scope_csv(&self) -> Result<String, String> {
        let process = csv_safe(&self.process);
        let protocol = match self.protocol {
            6 => "TCP",
            17 => "UDP",
            value => return Err(format!("socket protocol {value} is unresolved")),
        };
        Ok(format!(
            "{protocol},{},{},{},{},{},{},{},{}",
            self.local_addr,
            self.local_port,
            self.remote_addr,
            self.remote_port,
            self.pid,
            self.uid,
            process,
            process,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityReport {
    pub kernel: Option<KernelVersion>,
    pub ring_buffer: bool,
    pub socket_tracepoint: bool,
    pub btf: bool,
    pub compatible: bool,
    pub reasons: Vec<String>,
}

pub fn compatibility_report(
    release: &str,
    socket_tracepoint: bool,
    btf: bool,
) -> CompatibilityReport {
    let kernel = KernelVersion::parse(release).ok();
    let ring_buffer = kernel.is_some_and(|version| version >= MINIMUM_RINGBUF_KERNEL);
    let mut reasons = Vec::new();
    if kernel.is_none() {
        reasons.push("kernel release could not be parsed".into());
    }
    if !ring_buffer {
        reasons.push("BPF ring buffers require Linux 5.8 or newer".into());
    }
    if !socket_tracepoint {
        reasons.push("sock/inet_sock_set_state tracepoint is unavailable".into());
    }
    if !btf {
        reasons.push("kernel BTF is required for TCP accept and UDP lifecycle hooks".into());
    }
    CompatibilityReport {
        kernel,
        ring_buffer,
        socket_tracepoint,
        btf,
        compatible: ring_buffer && socket_tracepoint && btf,
        reasons,
    }
}

fn decode_address(family: u16, bytes: &[u8]) -> Result<IpAddr, String> {
    match family {
        2 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        10 => Ok(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| "invalid IPv6 socket address")?,
        ))),
        _ => Err(format!("unsupported socket address family {family}")),
    }
}

fn csv_safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if matches!(character, ',' | '\n' | '\r') {
                '_'
            } else {
                character
            }
        })
        .collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("truncated u16")?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("truncated u32")?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_ne_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or("truncated u64")?
            .try_into()
            .unwrap(),
    ))
}
