/// Core packet data model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Packet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureMetadata>,
    pub no: u64,
    pub timestamp: f64,
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub length: u16,
    pub info: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// Inner VLAN ID (C-TAG, 0x8100).  For untagged frames: None.
    pub vlan_id: Option<u16>,
    /// 802.1p Priority Code Point (3 bits, 0-7).  None when untagged.
    pub vlan_pcp: Option<u8>,
    /// Drop Eligible Indicator (1 bit).  None when untagged.
    pub vlan_dei: Option<u8>,
    /// Outer / provider VLAN ID (S-TAG, 0x88a8) for QinQ frames.
    /// Present only when the frame carries two VLAN tags (802.1ad).
    pub outer_vlan_id: Option<u16>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TimestampResolution {
    Decimal(u8),
    Binary(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaptureTimestamp {
    pub ticks: u64,
    pub resolution: TimestampResolution,
    pub offset_seconds: i64,
}

impl CaptureTimestamp {
    pub fn nanoseconds(self) -> i128 {
        let scaled = u128::from(self.ticks) * 1_000_000_000;
        let divisor = match self.resolution {
            TimestampResolution::Decimal(exponent) => 10u128.checked_pow(exponent.into()),
            TimestampResolution::Binary(exponent) => 1u128.checked_shl(exponent.into()),
        };
        let fraction = divisor.map(|value| scaled / value).unwrap_or(0);
        i128::from(self.offset_seconds) * 1_000_000_000 + fraction as i128
    }

    pub fn seconds(self) -> f64 {
        self.nanoseconds() as f64 / 1_000_000_000.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CaptureMetadata {
    pub timestamp: Option<CaptureTimestamp>,
    pub captured_length: u32,
    pub wire_length: u32,
    pub link_type: u32,
    pub interface_id: u32,
    #[serde(default)]
    pub section_id: u32,
    pub interface_name: Option<String>,
    #[serde(default)]
    pub comments: Vec<String>,
}

impl CaptureMetadata {
    pub fn truncated(&self) -> bool {
        self.captured_length < self.wire_length
    }
}

// ─── Protocol tree types ───────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TreeSection {
    pub title: String,
    pub fields: Vec<TreeField>,
    pub expanded: bool,
}

#[derive(Debug, Clone)]
pub struct TreeField {
    pub key: String,
    pub val: String,
    pub color: FieldColor,
}

#[derive(Debug, Clone)]
pub enum FieldColor {
    Default,
    Cyan,
    Green,
    Yellow,
    Red,
    Magenta,
    Orange,
}

pub fn make_field(key: &str, val: &str, color: FieldColor) -> TreeField {
    TreeField {
        key: key.to_string(),
        val: val.to_string(),
        color,
    }
}
