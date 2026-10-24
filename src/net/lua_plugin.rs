/// Lua-based protocol dissector engine.
///
/// Drop a .lua file into `~/.config/packrat/plugins/` to teach packrat
/// a custom or proprietary protocol using Packrat's Lua dissector API.
///
/// The following Lua dissector objects are supported:
///   Proto, ProtoField, DissectorTable, base constants,
///   Tvb/TvbRange (buf), Pinfo (pinfo), TreeItem (tree).
///
/// Press `r` in the UI to hot-reload all plugins without restarting.
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use mlua::prelude::*;

use crate::net::packet::{FieldColor, Packet, TreeSection, make_field};

mod userdata;
use userdata::*;

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
        base_tbl.set("HEX", 16i64)?;
        base_tbl.set("DEC", 10i64)?;
        base_tbl.set("OCT", 8i64)?;
        base_tbl.set("ASCII", 0i64)?;
        base_tbl.set("NONE", 10i64)?;
        g.set("base", base_tbl)?;

        // ── ProtoField ──────────────────────────────────────────────────────
        // ProtoField.uint8(abbr, label, base?) → field descriptor table
        let pf = lua.create_table()?;
        for type_name in &[
            "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64", "bytes",
            "string", "bool", "ipv4", "ipv6", "ether", "float", "double", "framenum",
        ] {
            let tn = type_name.to_string();
            let f = lua.create_function(move |lua, args: LuaMultiValue| {
                let mut iter = args.iter();
                let abbr = lua_val_to_string(iter.next());
                let label = match iter.next() {
                    Some(LuaValue::String(s)) => lua_str_to_string(s),
                    _ => abbr.clone(),
                };
                let base = match iter.next() {
                    Some(LuaValue::Integer(n)) => *n,
                    _ => 10i64,
                };
                let t = lua.create_table()?;
                t.set("_abbr", abbr)?;
                t.set("_label", label)?;
                t.set("_type", tn.clone())?;
                t.set("_base", base)?;
                Ok(t)
            })?;
            pf.set(*type_name, f)?;
        }
        g.set("ProtoField", pf)?;

        // ── Proto constructor ───────────────────────────────────────────────
        let proto_fn = lua.create_function(|lua, (name, desc): (String, Option<String>)| {
            let t = lua.create_table()?;
            t.set("name", name)?;
            t.set("description", desc.unwrap_or_default())?;
            t.set("fields", lua.create_table()?)?;
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
        let src = fs::read_to_string(path).map_err(|e| LuaError::runtime(e.to_string()))?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();

        // Fresh _registrations for this file
        self.lua
            .globals()
            .set("_registrations", self.lua.create_table()?)?;

        self.lua.load(&src).set_name(&name).exec()?;

        // Harvest registrations
        let regs: LuaTable = self.lua.globals().get("_registrations")?;
        for pair in regs.sequence_values::<LuaTable>() {
            let entry = pair?;
            let tbl: String = entry.get("tbl")?;
            let port: u16 = entry.get("port")?;
            let proto_name: String = entry.get("proto_name")?;
            let dissector: LuaFunction = entry.get("dissector")?;

            let key = self.lua.create_registry_value(dissector)?;
            let idx = self.protos.len();
            self.protos.push(ProtoEntry {
                name: proto_name,
                dissector_key: key,
            });

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

        let dir = match plugin_dir() {
            Some(d) => d,
            None => return,
        };
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
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                self.error_log.push(format!("{name}: {e}"));
            }
        }
    }

    // ── Applying dissectors to a packet ─────────────────────────────────────

    pub fn apply(&self, pkt: &Packet, sections: &mut Vec<TreeSection>) {
        let indices = self.matching_proto_indices(pkt);
        if indices.is_empty() {
            return;
        }

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
                Ok(u) => u,
                Err(_) => continue,
            };

            // pinfo table
            let pinfo = match build_pinfo(&self.lua, pkt) {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Root tree item
            let tree_ud = match self.lua.create_userdata(TreeItemUD { indent: 0 }) {
                Ok(u) => u,
                Err(_) => continue,
            };

            // Call dissector(buf, pinfo, tree)
            if let Ok(f) = self.lua.registry_value::<LuaFunction>(&entry.dissector_key) {
                let _: LuaResult<()> = f.call((buf_ud, pinfo, tree_ud));
            }

            // Collect results
            if let Some(state) = self.lua.app_data_ref::<CallState>() {
                if state.fields.is_empty() {
                    continue;
                }
                let fields = state
                    .fields
                    .iter()
                    .map(|fe| {
                        let indent = "  ".repeat(fe.indent);
                        make_field(
                            &format!("{indent}{}:", fe.label),
                            &fe.value,
                            base_to_color(fe.base),
                        )
                    })
                    .collect();
                sections.push(TreeSection {
                    title: format!(
                        "{} (Lua · port {})",
                        state.proto_name,
                        pkt.dst_port.or(pkt.src_port).unwrap_or(0)
                    ),
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
                    if !out.contains(&idx) {
                        out.push(idx);
                    }
                }
            }
            if is_udp {
                for &idx in self.udp_ports.get(&port).into_iter().flatten() {
                    if !out.contains(&idx) {
                        out.push(idx);
                    }
                }
            }
        }
        out
    }

    pub fn proto_count(&self) -> usize {
        self.protos.len()
    }
    pub fn plugin_count(&self) -> usize {
        self.loaded_files.len()
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_pinfo(lua: &Lua, pkt: &Packet) -> LuaResult<LuaTable> {
    let pinfo = lua.create_table()?;
    pinfo.set("src_port", pkt.src_port.unwrap_or(0) as u64)?;
    pinfo.set("dst_port", pkt.dst_port.unwrap_or(0) as u64)?;
    pinfo.set("pkt_len", pkt.length as u64)?;
    pinfo.set("number", pkt.no)?;

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
    !matches!(
        proto,
        "DNS"
            | "DHCP"
            | "DHCPv6"
            | "NTP"
            | "TFTP"
            | "SNMP"
            | "SYSLOG"
            | "SSDP"
            | "mDNS"
            | "NBNS"
            | "RIP"
            | "VXLAN"
            | "WireGuard"
            | "GTP"
            | "RADIUS"
            | "Kerberos-UDP"
            | "STUN"
            | "RTP"
            | "IGMP"
            | "PIM"
            | "PTP"
            | "SOME/IP-UDP"
            | "WoL"
            | "UDP"
    )
}

fn plugin_dir() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("packrat").join("plugins"))
}
