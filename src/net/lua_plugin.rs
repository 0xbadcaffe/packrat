/// Lua-based protocol dissector engine.
///
/// Drop a .lua file into `~/.config/packrat/plugins/` to teach packrat
/// a custom or proprietary protocol using a Wireshark-compatible Lua API.
///
/// The following Wireshark Lua objects are supported:
///   Proto, ProtoField, DissectorTable, base constants,
///   Tvb/TvbRange (buf), Pinfo (pinfo), TreeItem (tree).
///
/// Press `r` in the UI to hot-reload all plugins without restarting.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use mlua::prelude::*;

use crate::net::packet::{FieldColor, Packet, TreeSection, make_field};

// ─── Per-call shared state stored in Lua AppData ────────────────────────────

#[derive(Default, Clone)]
struct CallState {
    fields: Vec<FieldEntry>,
    proto_name: String,
}

#[derive(Clone)]
struct FieldEntry {
    label: String,
    value: String,
    indent: usize,
    base: i64, // 16=HEX, 10=DEC, 8=OCT, 0=ASCII
}

// ─── Tvb userdata (the `buf` passed to dissector) ───────────────────────────

struct TvbUD(Vec<u8>);

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

struct TvbRangeUD(Vec<u8>);

impl LuaUserData for TvbRangeUD {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("len", |_, this, ()| Ok(this.0.len() as u64));

        // :uint() – big-endian unsigned integer (1-4 bytes)
        methods.add_method("uint", |_, this, ()| Ok(be_uint(&this.0)));

        // :int() – big-endian signed integer (1-4 bytes)
        methods.add_method("int", |_, this, ()| Ok(be_int(&this.0)));

        // Typed accessors
        methods.add_method("uint8",  |_, this, ()| Ok(this.0.first().copied().unwrap_or(0) as u64));
        methods.add_method("uint16", |_, this, ()| {
            if this.0.len() >= 2 { Ok(u16::from_be_bytes([this.0[0], this.0[1]]) as u64) }
            else { Ok(this.0.first().copied().unwrap_or(0) as u64) }
        });
        methods.add_method("uint32", |_, this, ()| {
            if this.0.len() >= 4 {
                Ok(u32::from_be_bytes([this.0[0], this.0[1], this.0[2], this.0[3]]) as u64)
            } else { Ok(be_uint(&this.0)) }
        });
        methods.add_method("uint64", |_, this, ()| Ok(be_uint(&this.0)));

        // :string() – UTF-8 / ASCII interpretation
        methods.add_method("string", |_, this, ()| {
            Ok(String::from_utf8_lossy(&this.0).into_owned())
        });

        // :bytes_hex() – colon-separated hex (e.g. "de:ad:be:ef")
        methods.add_method("bytes_hex", |_, this, ()| {
            Ok(this.0.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
        });

        // :tohex() – 0x-prefixed hex string
        methods.add_method("tohex", |_, this, ()| {
            Ok(format!("0x{}", this.0.iter().map(|b| format!("{b:02x}")).collect::<String>()))
        });

        // :raw() – return bytes as a Lua string
        methods.add_method("raw", |lua, this, ()| {
            lua.create_string(&this.0)
        });
    }
}

// ─── TreeItem userdata ───────────────────────────────────────────────────────

struct TreeItemUD {
    indent: usize,
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
                    state.fields.push(FieldEntry { label, value, indent, base });
                }
            }
            lua.create_userdata(TreeItemUD { indent: indent + 1 })
        });

        // Wireshark compat no-ops
        methods.add_method("add_expert_info", |lua, this, _: LuaMultiValue| {
            lua.create_userdata(TreeItemUD { indent: this.indent + 1 })
        });
        methods.add_method("set_text",    |_, _, _: String| Ok(()));
        methods.add_method("append_text", |_, _, _: String| Ok(()));
        methods.add_method("set_generated", |_, _, _: LuaMultiValue| Ok(()));
        methods.add_method("set_hidden",    |_, _, _: LuaMultiValue| Ok(()));
    }
}

// ─── Argument parsing for tree:add() ────────────────────────────────────────

fn parse_add_args(args: LuaMultiValue) -> (String, String, i64) {
    let mut iter = args.iter();
    match iter.next() {
        // ProtoField table: {_label, _base} or Proto table: {name}
        Some(LuaValue::Table(t)) => {
            let label = t.get::<String>("_label")
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
                    } else { String::new() }
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

fn be_uint(b: &[u8]) -> u64 {
    match b.len() {
        0 => 0,
        1 => b[0] as u64,
        2 => u16::from_be_bytes([b[0], b[1]]) as u64,
        3 => u32::from_be_bytes([0, b[0], b[1], b[2]]) as u64,
        _ => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64,
    }
}

fn be_int(b: &[u8]) -> i64 {
    match b.len() {
        0 => 0,
        1 => b[0] as i8 as i64,
        2 => i16::from_be_bytes([b[0], b[1]]) as i64,
        _ => i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64,
    }
}

fn fmt_bytes_with_base(bytes: &[u8], base: i64) -> String {
    match base {
        0 => String::from_utf8_lossy(bytes).into_owned(), // ASCII
        8 => match bytes.len() {
            1 => format!("0o{:o}", bytes[0]),
            2 => format!("0o{:o}", u16::from_be_bytes([bytes[0], bytes[1]])),
            _ => bytes.iter().map(|b| format!("{b:o}")).collect::<Vec<_>>().join(" "),
        },
        16 => match bytes.len() {
            0 => String::new(),
            1 => format!("0x{:02x}", bytes[0]),
            2 => format!("0x{:04x}", u16::from_be_bytes([bytes[0], bytes[1]])),
            4 => format!("0x{:08x}", u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            _ => bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"),
        },
        _ => match bytes.len() { // DEC
            1 => bytes[0].to_string(),
            2 => u16::from_be_bytes([bytes[0], bytes[1]]).to_string(),
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
            _ => bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(" "),
        },
    }
}

/// Convert a Lua value reference to String. Accepts Option for ergonomics.
fn lua_val_to_string(v: Option<&LuaValue>) -> String {
    match v {
        Some(LuaValue::String(s))  => String::from_utf8_lossy(&*s.as_bytes()).into_owned(),
        Some(LuaValue::Integer(n)) => n.to_string(),
        Some(LuaValue::Number(n))  => n.to_string(),
        Some(LuaValue::Boolean(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn lua_str_to_string(s: &LuaString) -> String {
    String::from_utf8_lossy(&*s.as_bytes()).into_owned()
}

fn lua_to_usize(v: Option<&LuaValue>) -> usize {
    match v {
        Some(LuaValue::Integer(n)) => (*n).max(0) as usize,
        Some(LuaValue::Number(n))  => (*n).max(0.0) as usize,
        _ => 0,
    }
}

fn base_to_color(base: i64) -> FieldColor {
    match base {
        0  => FieldColor::Green,   // ASCII
        8  => FieldColor::Yellow,  // OCT
        16 => FieldColor::Cyan,    // HEX
        _  => FieldColor::Default, // DEC
    }
}

// ─── PluginManager ───────────────────────────────────────────────────────────

struct ProtoEntry {
    name: String,
    dissector_key: LuaRegistryKey,
}

pub struct PluginManager {
    lua: Lua,
    tcp_ports: HashMap<u16, Vec<usize>>,
    udp_ports: HashMap<u16, Vec<usize>>,
    protos: Vec<ProtoEntry>,
    pub loaded_files: Vec<String>,
    pub error_log: Vec<String>,
}

// Safety: Lua is used exclusively from the main thread (never spawned).
// mlua's Lua is !Send by default; this is safe in our single-threaded TUI loop.
unsafe impl Send for PluginManager {}

impl PluginManager {
    pub fn new() -> Self {
        let lua = Lua::new();
        let mut mgr = Self {
            lua,
            tcp_ports: HashMap::new(),
            udp_ports: HashMap::new(),
            protos: Vec::new(),
            loaded_files: Vec::new(),
            error_log: Vec::new(),
        };
        if let Err(e) = mgr.setup_globals() {
            mgr.error_log.push(format!("Lua init error: {e}"));
        }
        mgr
    }

    fn setup_globals(&self) -> LuaResult<()> {
        let lua = &self.lua;
        let g = lua.globals();

        // ── base constants ──────────────────────────────────────────────────
        let base_tbl = lua.create_table()?;
        base_tbl.set("HEX",   16i64)?;
        base_tbl.set("DEC",   10i64)?;
        base_tbl.set("OCT",    8i64)?;
        base_tbl.set("ASCII",  0i64)?;
        base_tbl.set("NONE",  10i64)?;
        g.set("base", base_tbl)?;

        // ── ProtoField ──────────────────────────────────────────────────────
        // ProtoField.uint8(abbr, label, base?) → field descriptor table
        let pf = lua.create_table()?;
        for type_name in &[
            "uint8","uint16","uint32","uint64",
            "int8","int16","int32","int64",
            "bytes","string","bool","ipv4","ipv6","ether",
            "float","double","framenum",
        ] {
            let tn = type_name.to_string();
            let f = lua.create_function(move |lua, args: LuaMultiValue| {
                let mut iter = args.iter();
                let abbr  = lua_val_to_string(iter.next());
                let label = match iter.next() {
                    Some(LuaValue::String(s)) => lua_str_to_string(s),
                    _ => abbr.clone(),
                };
                let base = match iter.next() {
                    Some(LuaValue::Integer(n)) => *n,
                    _ => 10i64,
                };
                let t = lua.create_table()?;
                t.set("_abbr",  abbr)?;
                t.set("_label", label)?;
                t.set("_type",  tn.clone())?;
                t.set("_base",  base)?;
                Ok(t)
            })?;
            pf.set(*type_name, f)?;
        }
        g.set("ProtoField", pf)?;

        // ── Proto constructor ───────────────────────────────────────────────
        let proto_fn = lua.create_function(|lua, (name, desc): (String, Option<String>)| {
            let t = lua.create_table()?;
            t.set("name",        name)?;
            t.set("description", desc.unwrap_or_default())?;
            t.set("fields",      lua.create_table()?)?;
            Ok(t)
        })?;
        g.set("Proto", proto_fn)?;

        // ── _registrations (populated by DissectorTable:add) ───────────────
        g.set("_registrations", lua.create_table()?)?;

        // ── DissectorTable ──────────────────────────────────────────────────
        // DissectorTable.get("tcp.port") → table with :add(port, proto)
        let dt_get = lua.create_function(|lua, table_name: String| {
            let dt = lua.create_table()?;
            dt.set("_tbl", table_name)?;

            let add_fn = lua.create_function(|lua, (this, port, proto): (LuaTable, u16, LuaTable)| {
                let tbl: String = this.get("_tbl")?;
                let proto_name: String = proto.get("name")?;
                let dissector: LuaFunction = proto.get("dissector")
                    .map_err(|_| LuaError::runtime(
                        "proto.dissector is not set — assign a function to proto.dissector before calling DissectorTable:add()"
                    ))?;

                let regs: LuaTable = lua.globals().get("_registrations")?;
                let entry = lua.create_table()?;
                entry.set("tbl",        tbl)?;
                entry.set("port",       port)?;
                entry.set("proto_name", proto_name)?;
                entry.set("dissector",  dissector)?;
                let n = regs.raw_len() + 1;
                regs.raw_set(n, entry)?;
                Ok(())
            })?;

            let mt  = lua.create_table()?;
            let idx = lua.create_table()?;
            idx.set("add", add_fn)?;
            mt.set("__index", idx)?;
            dt.set_metatable(Some(mt));
            Ok(dt)
        })?;
        let dt = lua.create_table()?;
        dt.set("get", dt_get)?;
        g.set("DissectorTable", dt)?;

        Ok(())
    }

    // ── Loading ─────────────────────────────────────────────────────────────

    fn load_file(&mut self, path: &PathBuf) -> LuaResult<()> {
        let src = fs::read_to_string(path)
            .map_err(|e| LuaError::runtime(e.to_string()))?;
        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();

        // Fresh _registrations for this file
        self.lua.globals().set("_registrations", self.lua.create_table()?)?;

        self.lua.load(&src).set_name(&name).exec()?;

        // Harvest registrations
        let regs: LuaTable = self.lua.globals().get("_registrations")?;
        for pair in regs.sequence_values::<LuaTable>() {
            let entry = pair?;
            let tbl:        String       = entry.get("tbl")?;
            let port:       u16          = entry.get("port")?;
            let proto_name: String       = entry.get("proto_name")?;
            let dissector:  LuaFunction  = entry.get("dissector")?;

            let key = self.lua.create_registry_value(dissector)?;
            let idx = self.protos.len();
            self.protos.push(ProtoEntry { name: proto_name, dissector_key: key });

            match tbl.as_str() {
                "tcp.port" => self.tcp_ports.entry(port).or_default().push(idx),
                "udp.port" => self.udp_ports.entry(port).or_default().push(idx),
                _ => {}
            }
        }

        self.loaded_files.push(name);
        Ok(())
    }

    /// Reload all .lua files from the plugins directory.
    pub fn reload(&mut self) {
        // Re-create the Lua VM to drop stale registry keys
        self.lua = Lua::new();
        self.tcp_ports.clear();
        self.udp_ports.clear();
        self.protos.clear();
        self.loaded_files.clear();
        self.error_log.clear();

        if let Err(e) = self.setup_globals() {
            self.error_log.push(format!("Lua init: {e}"));
            return;
        }

        let dir = match plugin_dir() { Some(d) => d, None => return };
        let paths: Vec<PathBuf> = match fs::read_dir(&dir) {
            Ok(entries) => entries
                .flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("lua"))
                .map(|e| e.path())
                .collect(),
            Err(_) => return,
        };

        for path in paths {
            if let Err(e) = self.load_file(&path) {
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?");
                self.error_log.push(format!("{name}: {e}"));
            }
        }
    }

    // ── Applying dissectors to a packet ─────────────────────────────────────

    pub fn apply(&self, pkt: &Packet, sections: &mut Vec<TreeSection>) {
        let indices = self.matching_proto_indices(pkt);
        if indices.is_empty() { return; }

        // Best-effort payload extraction (Ethernet + IP + 8-byte transport hdr)
        let skip = 14 + 20 + 8;
        let payload = if pkt.bytes.len() > skip {
            pkt.bytes[skip..].to_vec()
        } else {
            pkt.bytes.clone()
        };

        for idx in indices {
            let entry = &self.protos[idx];

            // Initialise per-call state
            self.lua.set_app_data(CallState {
                fields: Vec::new(),
                proto_name: entry.name.clone(),
            });

            let buf_ud = match self.lua.create_userdata(TvbUD(payload.clone())) {
                Ok(u) => u, Err(_) => continue,
            };

            // pinfo table
            let pinfo = match build_pinfo(&self.lua, pkt) {
                Ok(p) => p, Err(_) => continue,
            };

            // Root tree item
            let tree_ud = match self.lua.create_userdata(TreeItemUD { indent: 0 }) {
                Ok(u) => u, Err(_) => continue,
            };

            // Call dissector(buf, pinfo, tree)
            if let Ok(f) = self.lua.registry_value::<LuaFunction>(&entry.dissector_key) {
                let _: LuaResult<()> = f.call((buf_ud, pinfo, tree_ud));
            }

            // Collect results
            if let Some(state) = self.lua.app_data_ref::<CallState>() {
                if state.fields.is_empty() { continue; }
                let fields = state.fields.iter().map(|fe| {
                    let indent = "  ".repeat(fe.indent);
                    make_field(
                        &format!("{indent}{}:", fe.label),
                        &fe.value,
                        base_to_color(fe.base),
                    )
                }).collect();
                sections.push(TreeSection {
                    title: format!("{} (Lua · port {})",
                        state.proto_name,
                        pkt.dst_port.or(pkt.src_port).unwrap_or(0)),
                    expanded: true,
                    fields,
                });
            }
        }
    }

    fn matching_proto_indices(&self, pkt: &Packet) -> Vec<usize> {
        let mut out = Vec::new();
        // Determine transport from protocol name (heuristic)
        let is_tcp = is_tcp_protocol(&pkt.protocol);
        let is_udp = !is_tcp && pkt.src_port.is_some();

        for &port in [pkt.src_port, pkt.dst_port].iter().flatten() {
            if is_tcp {
                for &idx in self.tcp_ports.get(&port).into_iter().flatten() {
                    if !out.contains(&idx) { out.push(idx); }
                }
            }
            if is_udp {
                for &idx in self.udp_ports.get(&port).into_iter().flatten() {
                    if !out.contains(&idx) { out.push(idx); }
                }
            }
        }
        out
    }

    pub fn proto_count(&self)  -> usize { self.protos.len() }
    pub fn plugin_count(&self) -> usize { self.loaded_files.len() }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_pinfo(lua: &Lua, pkt: &Packet) -> LuaResult<LuaTable> {
    let pinfo = lua.create_table()?;
    pinfo.set("src_port", pkt.src_port.unwrap_or(0) as u64)?;
    pinfo.set("dst_port", pkt.dst_port.unwrap_or(0) as u64)?;
    pinfo.set("pkt_len",  pkt.length as u64)?;
    pinfo.set("number",   pkt.no)?;

    // pinfo.cols with __newindex to capture protocol name changes
    let cols = lua.create_table()?;
    cols.set("protocol", pkt.protocol.clone())?;
    let cols_mt = lua.create_table()?;
    let ni = lua.create_function(|lua, (_, key, val): (LuaTable, String, LuaValue)| {
        if key == "protocol" {
            if let Some(mut state) = lua.app_data_mut::<CallState>() {
                state.proto_name = lua_val_to_string(Some(&val));
            }
        }
        Ok(())
    })?;
    cols_mt.set("__newindex", ni)?;
    cols.set_metatable(Some(cols_mt));
    pinfo.set("cols", cols)?;
    Ok(pinfo)
}

/// Heuristic: determine if the packet's protocol uses TCP.
/// Protocols on UDP are known; everything else with ports is assumed TCP.
fn is_tcp_protocol(proto: &str) -> bool {
    !matches!(proto,
        "DNS" | "DHCP" | "DHCPv6" | "NTP" | "TFTP" | "SNMP" | "SYSLOG" |
        "SSDP" | "mDNS" | "NBNS" | "RIP" | "VXLAN" | "WireGuard" | "GTP" |
        "RADIUS" | "Kerberos-UDP" | "STUN" | "RTP" | "IGMP" | "PIM" | "PTP" |
        "SOME/IP-UDP" | "WoL" | "UDP"
    )
}

fn plugin_dir() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("packrat").join("plugins"))
}
