use std::collections::VecDeque;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;

use crate::capture::CaptureSource;
use crate::sim::capture::SimulatedCapture;
use crate::sim::dynamic::DynEntry;
use crate::export::PcapWriter;
use crate::filter::PacketFilter;
use crate::net::packet::Packet;
use crate::tabs::Tab;
use crate::topology::TopologyGraph;

const MAX_PACKETS: usize = 10_000;

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

pub struct App {
    pub active_tab: Tab,
    pub packets: VecDeque<Packet>,
    pub filtered: Vec<usize>,
    pub selected: Option<usize>,
    pub total_bytes: u64,
    pub packet_counter: u64,
    pub capturing: bool,
    capture_handle: Option<JoinHandle<()>>,
    packet_tx: Sender<Packet>,
    pub picking_iface: bool,
    pub iface_list: Vec<String>,
    pub iface_sel: usize,
    pub selected_iface: String,
    pub filter: PacketFilter,
    pub rate_history: Vec<u32>,
    pub rate_this_sec: u32,
    rate_tick: u32,
    pub dyn_log: Vec<DynEntry>,
    pub dyn_scroll: usize,
    pub analysis_section: usize,
    pub strings_filter: String,
    pub hex_scroll: u16,
    pub topology: TopologyGraph,
    pub recording: bool,
    pub pcap_path: String,
    pcap_writer: Option<PcapWriter>,
    pub show_help: bool,
}

impl App {
    pub fn new(packet_tx: Sender<Packet>) -> Self {
        let iface_list = list_interfaces();
        Self {
            active_tab: Tab::Packets,
            packets: VecDeque::new(),
            filtered: Vec::new(),
            selected: None,
            total_bytes: 0,
            packet_counter: 0,
            capturing: false,
            capture_handle: None,
            packet_tx,
            picking_iface: true,
            iface_list,
            iface_sel: 0,
            selected_iface: "simulated".to_string(),
            filter: PacketFilter::default(),
            rate_history: vec![0u32; 60],
            rate_this_sec: 0,
            rate_tick: 0,
            dyn_log: Vec::new(),
            dyn_scroll: 0,
            analysis_section: 0,
            strings_filter: String::new(),
            hex_scroll: 0,
            topology: TopologyGraph::default(),
            recording: false,
            pcap_path: String::new(),
            pcap_writer: None,
            show_help: false,
        }
    }

    pub fn iface_down(&mut self) {
        if self.iface_sel + 1 < self.iface_list.len() { self.iface_sel += 1; }
    }

    pub fn iface_up(&mut self) { self.iface_sel = self.iface_sel.saturating_sub(1); }

    pub fn confirm_iface(&mut self) {
        self.selected_iface = self.iface_list[self.iface_sel].clone();
        self.picking_iface = false;
        self.abort_capture();

        if self.selected_iface == "simulated" {
            self.capture_handle = Some(SimulatedCapture.run(self.packet_tx.clone()));
            self.capturing = true;
        } else {
            #[cfg(feature = "real-capture")]
            {
                use crate::capture::live::LiveCapture;
                let source = LiveCapture { iface: self.selected_iface.clone(), filter: None };
                self.capture_handle = Some(source.run(self.packet_tx.clone()));
                self.capturing = true;
            }
            #[cfg(not(feature = "real-capture"))]
            { self.capturing = false; }
        }
    }

    pub fn switch_interface(&mut self) {
        self.abort_capture();
        self.picking_iface = true;
        self.capturing = false;
    }

    fn abort_capture(&mut self) {
        if let Some(handle) = self.capture_handle.take() { handle.abort(); }
    }

    pub fn ingest_packet(&mut self, pkt: Packet) {
        if !self.capturing { return; }
        self.packet_counter += 1;
        self.total_bytes += pkt.length as u64;
        self.rate_this_sec += 1;
        self.topology.update(&pkt);

        if self.recording {
            if let Some(ref mut writer) = self.pcap_writer { let _ = writer.write_packet(&pkt); }
        }

        if self.filter.matches(&pkt) {
            self.filtered.push(self.packets.len());
            if self.selected.is_none() { self.selected = Some(0); }
        }

        self.packets.push_back(pkt);
        if self.packets.len() > MAX_PACKETS {
            self.packets.pop_front();
            self.rebuild_filtered();
        }
    }

    pub fn tick(&mut self) {
        self.rate_tick += 1;

        if self.capturing && self.selected_iface == "simulated" {
            if rand::random::<u8>() % 3 == 0 {
                let entry = crate::sim::dynamic::generate_entry(self.rate_tick);
                self.dyn_log.push(entry);
                if self.dyn_log.len() > 500 { self.dyn_log.remove(0); }
                // dyn_scroll is offset-from-end (0 = follow tail).
                // When user hasn't scrolled up, keep it at 0 so the tail stays visible.
            }
        }

        if self.rate_tick % 10 == 0 {
            self.rate_history.push(self.rate_this_sec);
            self.rate_history.remove(0);
            self.rate_this_sec = 0;
        }
    }

    pub fn toggle_capture(&mut self) { self.capturing = !self.capturing; }

    pub fn clear_packets(&mut self) {
        self.capturing = false;
        self.packets.clear();
        self.filtered.clear();
        self.selected = None;
        self.total_bytes = 0;
        self.packet_counter = 0;
        self.topology.clear();
    }

    pub fn toggle_recording(&mut self) {
        if self.recording {
            if let Some(ref mut w) = self.pcap_writer { let _ = w.flush(); }
            self.pcap_writer = None;
            self.recording = false;
        } else {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs();
            let path = format!("packrat_{}.pcap", ts);
            if let Ok(writer) = PcapWriter::new(std::path::Path::new(&path)) {
                self.pcap_path = path;
                self.pcap_writer = Some(writer);
                self.recording = true;
            }
        }
    }

    pub fn rebuild_filtered(&mut self) {
        self.filtered = self.packets.iter().enumerate()
            .filter(|(_, p)| self.filter.matches(p))
            .map(|(i, _)| i)
            .collect();
        if let Some(sel) = self.selected {
            if sel >= self.filtered.len() {
                self.selected = if self.filtered.is_empty() { None } else { Some(self.filtered.len() - 1) };
            }
        }
    }

    pub fn selected_packet(&self) -> Option<&Packet> {
        self.selected.and_then(|i| self.filtered.get(i)).and_then(|&pi| self.packets.get(pi))
    }

    pub fn current_rate(&self) -> u32 { *self.rate_history.last().unwrap_or(&0) }

    pub fn move_down(&mut self) {
        match self.active_tab {
            Tab::Packets  => {
                if let Some(sel) = self.selected {
                    if sel + 1 < self.filtered.len() { self.selected = Some(sel + 1); }
                } else if !self.filtered.is_empty() { self.selected = Some(0); }
            }
            Tab::Analysis => { if self.analysis_section < 5 { self.analysis_section += 1; } }
            // j = toward tail (decrease offset-from-end)
            Tab::Dynamic  => { self.dyn_scroll = self.dyn_scroll.saturating_sub(1); }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.active_tab {
            Tab::Packets  => { if let Some(sel) = self.selected { if sel > 0 { self.selected = Some(sel - 1); } } }
            Tab::Analysis => { if self.analysis_section > 0 { self.analysis_section -= 1; } }
            // k = away from tail (increase offset-from-end), clamped to log length
            Tab::Dynamic  => {
                let max = self.dyn_log.len().saturating_sub(1);
                if self.dyn_scroll < max { self.dyn_scroll += 1; }
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
        match self.active_tab {
            Tab::Packets if !self.filtered.is_empty() => {
                self.selected = Some(self.filtered.len() - 1);
            }
            Tab::Dynamic => {
                self.dyn_scroll = 0; // 0 = tail (offset-from-end model)
            }
            _ => {}
        }
    }

    pub fn page_down(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            if let Some(sel) = self.selected {
                self.selected = Some((sel + 10).min(self.filtered.len().saturating_sub(1)));
            }
        }
    }

    pub fn page_up(&mut self) {
        if matches!(self.active_tab, Tab::Packets) {
            if let Some(sel) = self.selected { self.selected = Some(sel.saturating_sub(10)); }
        }
    }

    pub fn next_tab(&mut self) {
        let next = (self.active_tab.index() + 1) % Tab::COUNT;
        self.active_tab = Tab::from_index(next);
    }
}
