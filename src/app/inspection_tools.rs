use super::*;

impl App {
    /// Open the Protocol Autopsy overlay for the currently selected packet.
    pub fn open_autopsy(&mut self) {
        let pkt = match self.selected_packet() {
            Some(p) => p.clone(),
            None => return,
        };

        let tree = self.dissect_packet(&pkt);

        // Build stream preview from reassembled data for this flow
        let stream_key = crate::analysis::stream::StreamKey::from_packet(&pkt);
        let stream_preview = if let Some(key) = stream_key {
            match self.core.streams.get(&key.id()) {
                Some(stream) => {
                    let mut lines: Vec<(bool, String)> = Vec::new();
                    // Client data
                    for chunk in stream.client_data.chunks(72) {
                        lines.push((true, printable_line(chunk)));
                    }
                    // Server data
                    for chunk in stream.server_data.chunks(72) {
                        lines.push((false, printable_line(chunk)));
                    }
                    lines
                }
                None => Vec::new(),
            }
        } else {
            Vec::new()
        };

        self.autopsy_state = Some(AutopsyState::new(tree, stream_preview));
    }

    /// Close the Protocol Autopsy overlay.
    pub fn close_autopsy(&mut self) {
        self.autopsy_state = None;
    }

    /// Reload user-configured rules through the terminal adapter.
    pub fn reload_yara_rules(&mut self) {
        self.core.yara_engine.reload();
        self.core.reset_object_scan();
    }

    pub fn yara_force_rescan(&mut self) {
        self.core.reset_object_scan();
        self.core.scan_new_objects();
    }

    pub fn yara_scan_new_objects(&mut self) {
        self.core.scan_new_objects();
    }

    pub fn carve_from_streams(&mut self) {
        self.core.carve_from_streams();
    }
}
