//! Protocol reverse-engineering workbench.
//!
//! Provides hex/field editing of captured packet bytes and
//! custom field annotation. Integrates with the dissector system.

use crate::net::packet::Packet;

// ─── Field annotation ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FieldAnnotation {
    /// Byte offset within the packet.
    pub offset: usize,
    /// Byte length of the field.
    pub length: usize,
    /// User-supplied field name.
    pub name:   String,
    /// Interpretation hint.
    pub kind:   FieldKind,
    /// Computed display value.
    pub value:  String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    Uint,
    Sint,
    Bytes,
    String,
    IpAddr,
    MacAddr,
    Flags,
    Custom(String),
}

impl FieldKind {
    pub fn interpret(&self, bytes: &[u8]) -> String {
        match self {
            FieldKind::Uint => {
                let v: u64 = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
                format!("{v} (0x{v:0width$x})", width = bytes.len() * 2)
            }
            FieldKind::Sint => {
                let v: i64 = bytes.iter().fold(0i64, |acc, &b| (acc << 8) | b as i64);
                format!("{v}")
            }
            FieldKind::Bytes => {
                bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
            }
            FieldKind::String => {
                String::from_utf8_lossy(bytes).into_owned()
            }
            FieldKind::IpAddr if bytes.len() == 4 => {
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            }
            FieldKind::MacAddr if bytes.len() == 6 => {
                bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
            }
            FieldKind::Flags => {
                let v: u64 = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
                format!("0b{v:0width$b}", width = bytes.len() * 8)
            }
            _ => bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
        }
    }
}

// ─── Workbench state ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ProtocolWorkbench {
    /// Current packet bytes being analyzed (editable copy).
    pub bytes:       Vec<u8>,
    /// Source packet info.
    pub source_info: String,
    /// User-added field annotations.
    pub annotations: Vec<FieldAnnotation>,
    /// Currently selected byte offset.
    pub cursor:      usize,
    /// Selection start (for range annotation).
    pub sel_start:   Option<usize>,
    /// Scroll offset for hex display.
    pub scroll:      usize,
    /// Notes for this packet.
    pub notes:       String,
}

impl ProtocolWorkbench {
    pub fn load_packet(&mut self, pkt: &Packet) {
        self.bytes = pkt.bytes.clone();
        self.source_info = format!("pkt#{} {} {} {}", pkt.no, pkt.protocol, pkt.src, pkt.dst);
        self.annotations.clear();
        self.cursor = 0;
        self.sel_start = None;
        self.scroll = 0;
    }

    pub fn annotate_selection(&mut self, name: impl Into<String>, kind: FieldKind) {
        let start = self.sel_start.unwrap_or(self.cursor);
        let end   = self.cursor.max(start);
        if end >= self.bytes.len() { return; }
        let slice = &self.bytes[start..=end];
        let value = kind.interpret(slice);
        self.annotations.push(FieldAnnotation {
            offset: start,
            length: end - start + 1,
            name:   name.into(),
            kind,
            value,
        });
        self.annotations.sort_by_key(|a| a.offset);
        self.sel_start = None;
    }

    pub fn remove_annotation(&mut self, offset: usize) {
        self.annotations.retain(|a| a.offset != offset);
    }

    /// Edit a byte at the cursor.
    pub fn set_byte(&mut self, val: u8) {
        if self.cursor < self.bytes.len() {
            self.bytes[self.cursor] = val;
            // Refresh annotations that cover this byte
            for ann in &mut self.annotations {
                if self.cursor >= ann.offset && self.cursor < ann.offset + ann.length {
                    let slice = &self.bytes[ann.offset..ann.offset + ann.length];
                    ann.value = ann.kind.interpret(slice);
                }
            }
        }
    }

    pub fn cursor_up(&mut self, cols: usize) {
        self.cursor = self.cursor.saturating_sub(cols);
    }

    pub fn cursor_down(&mut self, cols: usize) {
        self.cursor = (self.cursor + cols).min(self.bytes.len().saturating_sub(1));
    }

    pub fn cursor_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn cursor_right(&mut self) {
        if self.cursor + 1 < self.bytes.len() { self.cursor += 1; }
    }

    pub fn toggle_selection(&mut self) {
        if self.sel_start.is_some() {
            self.sel_start = None;
        } else {
            self.sel_start = Some(self.cursor);
        }
    }

    /// Current byte under cursor.
    pub fn current_byte(&self) -> Option<u8> { self.bytes.get(self.cursor).copied() }

    /// Annotation at cursor, if any.
    pub fn annotation_at_cursor(&self) -> Option<&FieldAnnotation> {
        self.annotations.iter()
            .find(|a| self.cursor >= a.offset && self.cursor < a.offset + a.length)
    }

    pub fn is_empty(&self) -> bool { self.bytes.is_empty() }
    pub fn len(&self) -> usize { self.bytes.len() }
}
