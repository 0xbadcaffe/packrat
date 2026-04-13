/// Core packet data model.
#[derive(Debug, Clone)]
pub struct Packet {
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
