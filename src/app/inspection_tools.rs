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

    /// Reload YARA rules from ~/.config/packrat/yara/ and clear existing results.
    pub fn reload_yara_rules(&mut self) {
        self.yara_engine.reload();
        self.yara_engine.clear_results();
        self.yara_scan_cursor = 0;
    }

    /// Force a full re-scan of all carved objects with current rules.
    pub fn yara_force_rescan(&mut self) {
        self.yara_engine.clear_results();
        self.yara_scan_cursor = 0;
        self.yara_scan_new_objects();
    }

    /// Incrementally scan carved objects that haven't been scanned yet.
    /// Called from tick() to spread work across frames.  Scans at most 4
    /// objects per tick so the UI never blocks.
    pub fn yara_scan_new_objects(&mut self) {
        if self.yara_engine.rules.is_empty() {
            return;
        }
        let start = self.yara_scan_cursor;
        let end = (start + 4).min(self.carved_objects.len());
        if start >= end {
            return;
        }

        // Collect the minimum data needed before any mutable borrow of self.
        const SCAN_CAP: usize = 1_048_576;
        let batch: Vec<(u64, String, Vec<u8>)> = self.carved_objects[start..end]
            .iter()
            .map(|obj| {
                let cap = obj.data.len().min(SCAN_CAP);
                (obj.id, obj.kind.clone(), obj.data[..cap].to_vec())
            })
            .collect();

        for (rel_idx, (id, kind, data)) in batch.into_iter().enumerate() {
            let result =
                self.yara_engine
                    .scan_target(&data, id, "object", &format!("#{} {}", id, kind));
            if !result.matches.is_empty() {
                let rule_names = result.rule_names();
                self.carved_objects[start + rel_idx].yara_hits = rule_names;
                self.yara_engine.results.push(result);
            }
        }
        self.yara_scan_cursor = end;
    }

    /// Carve embedded files from all reassembled TCP streams.
    pub fn carve_from_streams(&mut self) {
        let streams: Vec<(String, Vec<u8>, Vec<u8>)> = self
            .core
            .streams
            .all()
            .iter()
            .map(|s| (s.key.id(), s.client_data.clone(), s.server_data.clone()))
            .collect();

        for (id, client_data, server_data) in streams {
            let source = id.clone();
            if !client_data.is_empty() {
                let new_objs = self.carver.carve(&client_data, &format!("{source}→"));
                self.carved_objects.extend(new_objs);
            }
            if !server_data.is_empty() {
                let new_objs = self.carver.carve(&server_data, &format!("{source}←"));
                self.carved_objects.extend(new_objs);
            }
        }
    }
}
