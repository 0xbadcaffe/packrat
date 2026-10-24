use super::*;

// ─── Per-call shared state stored in Lua AppData ────────────────────────────

#[derive(Default, Clone)]
pub(super) struct CallState {
    pub(super) fields: Vec<FieldEntry>,
    pub(super) proto_name: String,
}

#[derive(Clone)]
pub(super) struct FieldEntry {
    pub(super) label: String,
    pub(super) value: String,
    pub(super) indent: usize,
    pub(super) base: i64, // 16=HEX, 10=DEC, 8=OCT, 0=ASCII
}

// ─── Tvb userdata (the `buf` passed to dissector) ───────────────────────────

pub(super) struct TvbUD(pub(super) Vec<u8>);

impl LuaUserData for TvbUD {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // buf:len()
        methods.add_method("len", |_, this, ()| Ok(this.0.len() as u64));

        // buf(offset, length?) → TvbRange
        methods.add_meta_method(LuaMetaMethod::Call, |lua, this, args: LuaMultiValue| {
            let mut iter = args.iter();
            let offset = lua_to_usize(iter.next());
            let len = match iter.next() {
                Some(v) => lua_to_usize(Some(v)),
                None => this.0.len().saturating_sub(offset),
            };
            let start = offset.min(this.0.len());
            let end = (offset + len).min(this.0.len());
            lua.create_userdata(TvbRangeUD(this.0[start..end].to_vec()))
        });
    }
}

// ─── TvbRange userdata (a slice of the packet) ──────────────────────────────

pub(super) struct TvbRangeUD(pub(super) Vec<u8>);

impl LuaUserData for TvbRangeUD {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok(this.0.len() as u64));

        // :uint() – big-endian unsigned integer (1-4 bytes)
        methods.add_method("uint", |_, this, ()| Ok(be_uint(&this.0)));

        // :int() – big-endian signed integer (1-4 bytes)
        methods.add_method("int", |_, this, ()| Ok(be_int(&this.0)));

        // Typed accessors
        methods.add_method("uint8", |_, this, ()| {
            Ok(this.0.first().copied().unwrap_or(0) as u64)
        });
        methods.add_method("uint16", |_, this, ()| {
            if this.0.len() >= 2 {
                Ok(u16::from_be_bytes([this.0[0], this.0[1]]) as u64)
            } else {
                Ok(this.0.first().copied().unwrap_or(0) as u64)
            }
        });
        methods.add_method("uint32", |_, this, ()| {
            if this.0.len() >= 4 {
                Ok(u32::from_be_bytes([this.0[0], this.0[1], this.0[2], this.0[3]]) as u64)
            } else {
                Ok(be_uint(&this.0))
            }
        });
        methods.add_method("uint64", |_, this, ()| Ok(be_uint(&this.0)));

        // :string() – UTF-8 / ASCII interpretation
        methods.add_method("string", |_, this, ()| {
            Ok(String::from_utf8_lossy(&this.0).into_owned())
        });

        // :bytes_hex() – colon-separated hex (e.g. "de:ad:be:ef")
        methods.add_method("bytes_hex", |_, this, ()| {
            Ok(this
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"))
        });

        // :tohex() – 0x-prefixed hex string
        methods.add_method("tohex", |_, this, ()| {
            Ok(format!(
                "0x{}",
                this.0
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ))
        });

        // :raw() – return bytes as a Lua string
        methods.add_method("raw", |lua, this, ()| lua.create_string(&this.0));
    }
}

// ─── TreeItem userdata ───────────────────────────────────────────────────────

pub(super) struct TreeItemUD {
    pub(super) indent: usize,
}

impl LuaUserData for TreeItemUD {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        // tree:add(field_or_proto_or_label, tvbrange_or_value, optional_override_label)
        // Returns a child TreeItem (for subtrees).
        methods.add_method("add", |lua, this, args: LuaMultiValue| {
            let indent = this.indent;
            let (label, value, base) = parse_add_args(args);
            if let Some(mut state) = lua.app_data_mut::<CallState>() {
                if !label.is_empty() || !value.is_empty() {
                    state.fields.push(FieldEntry {
                        label,
                        value,
                        indent,
                        base,
                    });
                }
            }
            lua.create_userdata(TreeItemUD { indent: indent + 1 })
        });

        // Compatibility no-ops
        methods.add_method("add_expert_info", |lua, this, _: LuaMultiValue| {
            lua.create_userdata(TreeItemUD {
                indent: this.indent + 1,
            })
        });
        methods.add_method("set_text", |_, _, _: String| Ok(()));
        methods.add_method("append_text", |_, _, _: String| Ok(()));
        methods.add_method("set_generated", |_, _, _: LuaMultiValue| Ok(()));
        methods.add_method("set_hidden", |_, _, _: LuaMultiValue| Ok(()));
    }
}

// ─── Argument parsing for tree:add() ────────────────────────────────────────

pub(super) fn parse_add_args(args: LuaMultiValue) -> (String, String, i64) {
    let mut iter = args.iter();
    match iter.next() {
        // ProtoField table: {_label, _base} or Proto table: {name}
        Some(LuaValue::Table(t)) => {
            let label = t
                .get::<String>("_label")
                .or_else(|_| t.get::<String>("name"))
                .unwrap_or_default();
            let base = t.get::<i64>("_base").unwrap_or(10);

            let value = match iter.next() {
                Some(LuaValue::UserData(ud)) => {
                    if let Ok(r) = ud.borrow::<TvbRangeUD>() {
                        fmt_bytes_with_base(&r.0, base)
                    } else if let Ok(b) = ud.borrow::<TvbUD>() {
                        fmt_bytes_with_base(&b.0, base)
                    } else {
                        String::new()
                    }
                }
                Some(v) => lua_val_to_string(Some(v)),
                None => String::new(),
            };

            // Optional label override (tree:add(proto, buf(), "My Protocol Header"))
            let label = match iter.next() {
                Some(LuaValue::String(s)) => lua_str_to_string(s),
                _ => label,
            };
            (label, value, base)
        }

        // Plain string label
        Some(LuaValue::String(s)) => {
            let label = lua_str_to_string(s);
            let value = match iter.next() {
                Some(LuaValue::UserData(ud)) => {
                    if let Ok(r) = ud.borrow::<TvbRangeUD>() {
                        fmt_bytes_with_base(&r.0, 16)
                    } else {
                        String::new()
                    }
                }
                Some(v) => lua_val_to_string(Some(v)),
                None => String::new(),
            };
            (label, value, 16)
        }

        _ => (String::new(), String::new(), 10),
    }
}

// ─── Byte-formatting helpers ─────────────────────────────────────────────────

pub(super) fn be_uint(b: &[u8]) -> u64 {
    match b.len() {
        0 => 0,
        1 => b[0] as u64,
        2 => u16::from_be_bytes([b[0], b[1]]) as u64,
        3 => u32::from_be_bytes([0, b[0], b[1], b[2]]) as u64,
        _ => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64,
    }
}

pub(super) fn be_int(b: &[u8]) -> i64 {
    match b.len() {
        0 => 0,
        1 => b[0] as i8 as i64,
        2 => i16::from_be_bytes([b[0], b[1]]) as i64,
        _ => i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64,
    }
}

pub(super) fn fmt_bytes_with_base(bytes: &[u8], base: i64) -> String {
    match base {
        0 => String::from_utf8_lossy(bytes).into_owned(), // ASCII
        8 => match bytes.len() {
            1 => format!("0o{:o}", bytes[0]),
            2 => format!("0o{:o}", u16::from_be_bytes([bytes[0], bytes[1]])),
            _ => bytes
                .iter()
                .map(|b| format!("{b:o}"))
                .collect::<Vec<_>>()
                .join(" "),
        },
        16 => match bytes.len() {
            0 => String::new(),
            1 => format!("0x{:02x}", bytes[0]),
            2 => format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])),
            4 => format!(
                "0x{:08x}",
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            ),
            _ => bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        },
        _ => match bytes.len() {
            // DEC
            1 => bytes[0].to_string(),
            2 => u16::from_be_bytes([bytes[0], bytes[1]]).to_string(),
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
            _ => bytes
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(" "),
        },
    }
}

/// Convert a Lua value reference to String. Accepts Option for ergonomics.
pub(super) fn lua_val_to_string(v: Option<&LuaValue>) -> String {
    match v {
        Some(LuaValue::String(s)) => String::from_utf8_lossy(&*s.as_bytes()).into_owned(),
        Some(LuaValue::Integer(n)) => n.to_string(),
        Some(LuaValue::Number(n)) => n.to_string(),
        Some(LuaValue::Boolean(b)) => b.to_string(),
        _ => String::new(),
    }
}

pub(super) fn lua_str_to_string(s: &LuaString) -> String {
    String::from_utf8_lossy(&*s.as_bytes()).into_owned()
}

pub(super) fn lua_to_usize(v: Option<&LuaValue>) -> usize {
    match v {
        Some(LuaValue::Integer(n)) => (*n).max(0) as usize,
        Some(LuaValue::Number(n)) => (*n).max(0.0) as usize,
        _ => 0,
    }
}

pub(super) fn base_to_color(base: i64) -> FieldColor {
    match base {
        0 => FieldColor::Green,   // ASCII
        8 => FieldColor::Yellow,  // OCT
        16 => FieldColor::Cyan,   // HEX
        _ => FieldColor::Default, // DEC
    }
}
