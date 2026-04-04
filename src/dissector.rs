/// Custom protocol dissectors loaded from TOML files.
///
/// Drop a .toml file in ~/.config/packrat/dissectors/ to teach packrat
/// how to decode a custom or proprietary protocol by port and field layout.
///
/// Example file (my_proto.toml):
/// ```toml
/// name       = "MyProto"
/// transport  = "tcp"   # "tcp" or "udp"
/// port       = 9999
///
/// [[fields]]
/// offset  = 0
/// length  = 2
/// name    = "Magic"
/// display = "hex"   # "hex", "dec", or "ascii"
///
/// [[fields]]
/// offset  = 2
/// length  = 1
/// name    = "Command"
/// display = "dec"
/// ```
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::net::packet::{FieldColor, Packet, TreeSection, make_field};

#[derive(Debug, Deserialize, Clone)]
pub struct DissectorDef {
    pub name:      String,
    pub transport: String,
    pub port:      u16,
    #[serde(default)]
    pub fields:    Vec<FieldDef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FieldDef {
    pub offset:  usize,
    pub length:  usize,
    pub name:    String,
    #[serde(default = "default_display")]
    pub display: String,
}

fn default_display() -> String { "hex".to_string() }

/// Load all *.toml dissectors from `~/.config/packrat/dissectors/`.
/// Returns an empty Vec (not an error) if the directory does not exist.
pub fn load() -> Vec<DissectorDef> {
    let dir = match dissector_dir() {
        Some(d) => d,
        None => return Vec::new(),
    };
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("toml"))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|text| toml::from_str::<DissectorDef>(&text).ok())
        .collect()
}

fn dissector_dir() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("packrat").join("dissectors"))
}

/// Match loaded dissectors against `pkt` and append custom tree sections.
pub fn apply(dissectors: &[DissectorDef], pkt: &Packet, sections: &mut Vec<TreeSection>) {
    for def in dissectors {
        let port_matches = match def.transport.to_lowercase().as_str() {
            "tcp" | "udp" => {
                pkt.src_port.map_or(false, |p| p == def.port)
                    || pkt.dst_port.map_or(false, |p| p == def.port)
            }
            _ => false,
        };
        if !port_matches { continue; }

        let payload = transport_payload(pkt);
        let fields = def.fields.iter().map(|fd| {
            let end = fd.offset + fd.length;
            let value = if end <= payload.len() {
                format_bytes(&payload[fd.offset..end], &fd.display)
            } else {
                format!("(out of range: payload {} bytes)", payload.len())
            };
            make_field(&format!("{}:", fd.name), &value, FieldColor::Cyan)
        }).collect();

        sections.push(TreeSection {
            title: format!("{} (dissector · port {})", def.name, def.port),
            expanded: true,
            fields,
        });
    }
}

/// Skip Ethernet (14) + IP (20) + conservative transport header (8) to reach payload.
/// For a simulated/truncated packet this may return an empty slice — that is fine.
fn transport_payload(pkt: &Packet) -> &[u8] {
    let skip = 14 + 20 + 8;
    if pkt.bytes.len() > skip { &pkt.bytes[skip..] } else { &[] }
}

fn format_bytes(bytes: &[u8], display: &str) -> String {
    match display {
        "dec" => match bytes.len() {
            1 => bytes[0].to_string(),
            2 => u16::from_be_bytes([bytes[0], bytes[1]]).to_string(),
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
            _ => bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(" "),
        },
        "ascii" => String::from_utf8_lossy(bytes)
            .chars()
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '.' })
            .collect(),
        _ => bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
    }
}
