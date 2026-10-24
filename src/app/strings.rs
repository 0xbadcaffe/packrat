use super::*;

impl App {
    /// Hot-reload all Lua plugins from ~/.config/packrat/plugins/
    pub fn reload_lua_plugins(&mut self) {
        self.lua_plugins.reload();
        let n = self.lua_plugins.plugin_count();
        let p = self.lua_plugins.proto_count();
        let errs = self.lua_plugins.error_log.len();
        if errs > 0 {
            self.lua_reload_msg = Some(format!(
                "Lua: {n} files, {p} dissectors — {} error(s)",
                errs
            ));
        } else {
            self.lua_reload_msg = Some(format!("Lua: {n} files, {p} dissectors loaded"));
        }
    }

    /// Navigate the strings list (only when capture is stopped).
    pub fn strings_move_down(&mut self, list_len: usize) {
        if self.capturing || list_len == 0 {
            return;
        }
        let cur = self.strings_selected.unwrap_or(0);
        let next = (cur + 1).min(list_len.saturating_sub(1));
        self.strings_selected = Some(next);
        // strings_scroll is a scroll hint used by the draw function.
        // We advance it by 1 each time we go past the current view to
        // produce smooth scrolling (draw clamps this to selection bounds).
        if next > self.strings_scroll {
            self.strings_scroll = next;
        }
    }

    pub fn strings_move_up(&mut self) {
        if self.capturing {
            return;
        }
        let cur = self.strings_selected.unwrap_or(0);
        let prev = cur.saturating_sub(1);
        self.strings_selected = Some(prev);
        if prev < self.strings_scroll {
            self.strings_scroll = prev;
        }
    }

    pub fn strings_select(&mut self) {
        // Enter just confirms — selection is already set by j/k.
        // If nothing is selected yet, select the first item.
        if self.strings_selected.is_none() {
            self.strings_selected = Some(0);
        }
    }

    pub fn strings_deselect(&mut self) {
        self.strings_selected = None;
    }

    /// Count extracted strings (after filter) for navigation bounds.
    /// Mirrors the extraction logic in strings.rs but just counts.
    pub fn strings_list_len(&self) -> usize {
        const MIN_LEN: usize = 4;
        let mut count = 0usize;
        for pkt in self.packets.iter().take(500) {
            let mut in_run = false;
            let mut run_start = 0usize;
            for (i, &b) in pkt.bytes.iter().enumerate() {
                if b >= 32 && b < 127 {
                    if !in_run {
                        run_start = i;
                        in_run = true;
                    }
                } else if in_run {
                    in_run = false;
                    if i - run_start >= MIN_LEN {
                        count += 1;
                    }
                }
            }
            if in_run && pkt.bytes.len() - run_start >= MIN_LEN {
                count += 1;
            }
        }
        // Apply filter if active
        if self.strings_filter.is_empty() {
            count
        } else {
            // Re-extract to filter — acceptable since this only runs on keypress
            let q = self.strings_filter.to_lowercase();
            let mut filt_count = 0usize;
            for pkt in self.packets.iter().take(500) {
                let bytes = &pkt.bytes;
                let mut in_run = false;
                let mut run_start = 0usize;
                for (i, &b) in bytes.iter().enumerate() {
                    if b >= 32 && b < 127 {
                        if !in_run {
                            run_start = i;
                            in_run = true;
                        }
                    } else if in_run {
                        in_run = false;
                        if i - run_start >= MIN_LEN {
                            let val = String::from_utf8_lossy(&bytes[run_start..i]);
                            if val.to_lowercase().contains(&q) {
                                filt_count += 1;
                            }
                        }
                    }
                }
                if in_run && pkt.bytes.len() - run_start >= MIN_LEN {
                    let val = String::from_utf8_lossy(&pkt.bytes[run_start..]);
                    if val.to_lowercase().contains(&q) {
                        filt_count += 1;
                    }
                }
            }
            filt_count
        }
    }

    /// Look up a packet by its frame number (pkt.no).
    pub fn packet_by_no(&self, no: u64) -> Option<&Packet> {
        self.worklist
            .retained_packet(no)
            .or_else(|| self.packets.iter().find(|p| p.no == no))
    }

    /// Build the protocol dissection tree for `pkt`, then apply any custom
    /// dissectors loaded from ~/.config/packrat/dissectors/.
    pub fn dissect_packet(&self, pkt: &Packet) -> Vec<TreeSection> {
        let mut sections = crate::net::tree::build_tree(pkt, self.selected_iface == "simulated");
        crate::dissector::apply(&self.dissectors, pkt, &mut sections);
        self.lua_plugins.apply(pkt, &mut sections);
        sections
    }
}
