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
    pub vlan_id: Option<u16>,
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
