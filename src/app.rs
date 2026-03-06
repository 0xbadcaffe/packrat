use crate::packet::{Packet, generate_packet};
use crate::dynamic::DynEntry;

fn list_interfaces() -> Vec<String> {
    let mut ifaces = vec!["simulated".to_string()];
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        let mut sys: Vec<String> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        sys.sort();
        ifaces.extend(sys);
    }
    ifaces
}

#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Packets,
    Analysis,
    Strings,
    Dynamic,
    Visualize,
}

impl Tab {
    pub fn index(&self) -> usize {
        match self {
            Tab::Packets   => 0,
            Tab::Analysis  => 1,
            Tab::Strings   => 2,
            Tab::Dynamic   => 3,
            Tab::Visualize => 4,
        }
    }
    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Packets,
            1 => Tab::Analysis,
            2 => Tab::Strings,
            3 => Tab::Dynamic,
            4 => Tab::Visualize,
            _ => Tab::Packets,
        }
    }
}

pub struct App {
    pub active_tab: Tab,
    pub packets: Vec<Packet>,
    pub filtered: Vec<usize>, // indices into packets
    pub selected: Option<usize>, // index into filtered
    pub capturing: bool,
    pub filter_input: String,
    pub filter_mode: bool,
    pub total_bytes: u64,
    pub packet_counter: u64,
    pub rate_history: Vec<u32>, // packets per second, last 60s
    pub rate_this_sec: u32,
    pub rate_tick: u32,
    pub dyn_log: Vec<DynEntry>,
    pub dyn_scroll: usize,
    pub analysis_section: usize, // which nav item in analysis tab
    pub strings_filter: String,
    pub hex_scroll: u16,
    // Interface selection
    pub picking_iface: bool,
    pub iface_list: Vec<String>,
    pub iface_sel: usize,
    pub selected_iface: String,
}

impl App {
    pub fn new() -> Self {
        let iface_list = list_interfaces();
        Self {
            active_tab: Tab::Packets,
            packets: Vec::new(),
            filtered: Vec::new(),
            selected: None,
            capturing: false,
            filter_input: String::new(),
            filter_mode: false,
            total_bytes: 0,
            packet_counter: 0,
            rate_history: vec![0u32; 60],
            rate_this_sec: 0,
            rate_tick: 0,
            dyn_log: Vec::new(),
            dyn_scroll: 0,
            analysis_section: 0,
            strings_filter: String::new(),
            hex_scroll: 0,
            picking_iface: true,
            iface_list,
            iface_sel: 0,
            selected_iface: "simulated".to_string(),
        }
    }

    pub fn iface_down(&mut self) {
        if self.iface_sel + 1 < self.iface_list.len() {
            self.iface_sel += 1;
        }
    }

    pub fn iface_up(&mut self) {
        self.iface_sel = self.iface_sel.saturating_sub(1);
    }

    pub fn confirm_iface(&mut self) {
        self.selected_iface = self.iface_list[self.iface_sel].clone();
        self.picking_iface = false;
        self.capturing = true;
    }

    pub fn tick(&mut self) {
        self.rate_tick += 1;

        if self.capturing {
            // Generate 1-4 packets per tick (10 ticks/s)
            let burst = (rand::random::<u8>() % 4) + 1;
            for _ in 0..burst {
                let pkt = generate_packet(self.packet_counter);
                self.packet_counter += 1;
                self.total_bytes += pkt.length as u64;
                self.rate_this_sec += 1;

                if self.matches_filter(&pkt) {
                    self.filtered.push(self.packets.len());
                    // Auto-select first packet
                    if self.selected.is_none() {
                        self.selected = Some(0);
                    }
                }
                self.packets.push(pkt);

                // Cap at 2000 packets for memory
                if self.packets.len() > 2000 {
                    self.packets.remove(0);
                    self.rebuild_filtered();
                }
            }

            // Generate dynamic trace entries
            if rand::random::<u8>() % 3 == 0 {
                let entry = crate::dynamic::generate_entry(self.rate_tick);
                self.dyn_log.push(entry);
                if self.dyn_log.len() > 500 {
                    self.dyn_log.remove(0);
                }
                self.dyn_scroll = self.dyn_log.len().saturating_sub(1);
            }
        }

        // Rate counter: every 10 ticks = 1 second
        if self.rate_tick % 10 == 0 {
            self.rate_history.push(self.rate_this_sec);
            self.rate_history.remove(0);
            self.rate_this_sec = 0;
        }
    }

    pub fn toggle_capture(&mut self) {
        self.capturing = !self.capturing;
    }

    pub fn clear_packets(&mut self) {
        self.capturing = false;
        self.packets.clear();
        self.filtered.clear();
        self.selected = None;
        self.total_bytes = 0;
        self.packet_counter = 0;
    }

    pub fn apply_filter(&mut self) {
        self.rebuild_filtered();
    }

    pub fn rebuild_filtered(&mut self) {
        self.filtered = self.packets.iter().enumerate()
            .filter(|(_, p)| self.matches_filter(p))
            .map(|(i, _)| i)
            .collect();
        if let Some(sel) = self.selected {
            if sel >= self.filtered.len() {
                self.selected = if self.filtered.is_empty() {
                    None
                } else {
                    Some(self.filtered.len() - 1)
                };
            }
        }
    }

    pub fn matches_filter(&self, p: &Packet) -> bool {
        let f = self.filter_input.trim().to_lowercase();
        if f.is_empty() { return true; }
        if let Some(ip) = f.strip_prefix("ip.src==") { return p.src == ip; }
        if let Some(ip) = f.strip_prefix("ip.dst==") { return p.dst == ip; }
        if let Some(port) = f.strip_prefix("tcp.port==") {
            return p.src_port.map(|x| x.to_string()) == Some(port.to_string())
                || p.dst_port.map(|x| x.to_string()) == Some(port.to_string());
        }
        p.protocol.to_lowercase().contains(&f)
            || p.src.contains(&f)
            || p.dst.contains(&f)
            || p.info.to_lowercase().contains(&f)
    }

    pub fn toggle_filter_mode(&mut self) {
        self.filter_mode = !self.filter_mode;
    }

    pub fn selected_packet(&self) -> Option<&Packet> {
        self.selected.and_then(|i| self.filtered.get(i)).and_then(|&pi| self.packets.get(pi))
    }

    // Navigation
    pub fn move_down(&mut self) {
        match self.active_tab {
            Tab::Packets => {
                if let Some(sel) = self.selected {
                    if sel + 1 < self.filtered.len() {
                        self.selected = Some(sel + 1);
                    }
                } else if !self.filtered.is_empty() {
                    self.selected = Some(0);
                }
            }
            Tab::Analysis => {
                if self.analysis_section < 5 { self.analysis_section += 1; }
            }
            Tab::Dynamic => {
                if self.dyn_scroll + 1 < self.dyn_log.len() {
                    self.dyn_scroll += 1;
                }
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.active_tab {
            Tab::Packets => {
                if let Some(sel) = self.selected {
                    if sel > 0 { self.selected = Some(sel - 1); }
                }
            }
            Tab::Analysis => {
                if self.analysis_section > 0 { self.analysis_section -= 1; }
            }
            Tab::Dynamic => {
                self.dyn_scroll = self.dyn_scroll.saturating_sub(1);
            }
            _ => {}
        }
    }

    pub fn move_top(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            self.selected = if self.filtered.is_empty() { None } else { Some(0) };
        }
    }

    pub fn move_bottom(&mut self) {
        if matches!(self.active_tab, Tab::Packets) && !self.filtered.is_empty() {
            self.selected = Some(self.filtered.len() - 1);
        }
    }

    pub fn page_down(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            if let Some(sel) = self.selected {
                let new = (sel + 10).min(self.filtered.len().saturating_sub(1));
                self.selected = Some(new);
            }
        }
    }

    pub fn page_up(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            if let Some(sel) = self.selected {
                self.selected = Some(sel.saturating_sub(10));
            }
        }
    }

    pub fn next_tab(&mut self) {
        let next = (self.active_tab.index() + 1) % 5;
        self.active_tab = Tab::from_index(next);
    }

    pub fn current_rate(&self) -> u32 {
        *self.rate_history.last().unwrap_or(&0)
    }
}
