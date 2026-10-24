use super::*;

impl App {
    pub fn active_investigation_packet(&self) -> Option<&Packet> {
        self.worklist
            .active_packet_no()
            .and_then(|packet_no| self.packet_by_no(packet_no))
            .or_else(|| {
                self.worklist
                    .items
                    .is_empty()
                    .then(|| self.selected_packet())
                    .flatten()
            })
    }

    pub fn active_investigation_item(&self) -> Option<&InvestigationItem> {
        self.worklist
            .active
            .and_then(|index| self.worklist.items.get(index))
    }

    pub fn active_investigation_context(&self) -> Option<InvestigationContext> {
        let item = self.active_investigation_item()?;
        let missing = |kind, title: String| InvestigationContext {
            kind,
            title,
            details: vec![(
                "Status".into(),
                "Source data is no longer retained in this session".into(),
            )],
            available: false,
        };
        Some(match item {
            InvestigationItem::Packet(no) => self
                .packet_by_no(*no)
                .map(|packet| InvestigationContext {
                    kind: "Packet",
                    title: format!("Packet #{}", packet.no),
                    details: vec![
                        ("Protocol".into(), packet.protocol.clone()),
                        (
                            "Conversation".into(),
                            format!("{} -> {}", packet.src, packet.dst),
                        ),
                        ("Length".into(), format!("{} bytes", packet.length)),
                        ("Info".into(), packet.info.clone()),
                    ],
                    available: true,
                })
                .unwrap_or_else(|| missing("Packet", format!("Packet #{no}"))),
            InvestigationItem::Stream(id) => InvestigationContext {
                kind: "Stream",
                title: id.clone(),
                details: vec![
                    ("Context".into(), "Pinned flow or reassembled stream".into()),
                    (
                        "Action".into(),
                        "Select a packet item from this stream for byte-level inspection".into(),
                    ),
                ],
                available: true,
            },
            InvestigationItem::Host(address) => self
                .core
                .hosts
                .get(address)
                .map(|host| InvestigationContext {
                    kind: "Host",
                    title: address.clone(),
                    details: vec![
                        (
                            "Packets".into(),
                            format!("{} out / {} in", host.pkts_out, host.pkts_in),
                        ),
                        (
                            "Bytes".into(),
                            format!("{} out / {} in", host.bytes_out, host.bytes_in),
                        ),
                        ("Alerts".into(), host.alert_count.to_string()),
                        (
                            "OS".into(),
                            host.os_guess.clone().unwrap_or_else(|| "unknown".into()),
                        ),
                    ],
                    available: true,
                })
                .unwrap_or_else(|| missing("Host", address.clone())),
            InvestigationItem::Alert(id) => self
                .core
                .alert_center
                .items
                .iter()
                .find(|alert| alert.id == *id)
                .map(|alert| InvestigationContext {
                    kind: "Alert",
                    title: alert.title.clone(),
                    details: vec![
                        ("Severity".into(), alert.severity.clone()),
                        ("Priority".into(), alert.priority.to_string()),
                        ("State".into(), alert.disposition.to_string()),
                        ("Source".into(), alert.source.clone()),
                        ("Packet".into(), format!("#{}", alert.packet_no)),
                        ("Reason".into(), alert.detail.clone()),
                        (
                            "Recommendation".into(),
                            alert
                                .recommendation
                                .clone()
                                .unwrap_or_else(|| "manual review".into()),
                        ),
                    ],
                    available: true,
                })
                .unwrap_or_else(|| missing("Alert", format!("Alert #{id}"))),
            InvestigationItem::Object(id) => self
                .carved_objects
                .iter()
                .find(|object| object.id == *id)
                .map(|object| InvestigationContext {
                    kind: "Object",
                    title: object.name.clone(),
                    details: vec![
                        ("Type".into(), object.kind.clone()),
                        ("Size".into(), object.size_str()),
                        ("Source".into(), object.source.clone()),
                        ("SHA-256".into(), object.sha256.clone()),
                        (
                            "YARA".into(),
                            if object.yara_hits.is_empty() {
                                "none".into()
                            } else {
                                object.yara_hits.join(", ")
                            },
                        ),
                    ],
                    available: true,
                })
                .unwrap_or_else(|| missing("Object", format!("Object #{id}"))),
            InvestigationItem::GraphNode(key) => self
                .core
                .operator_graph
                .all_nodes()
                .find(|node| node.key == *key)
                .map(|node| InvestigationContext {
                    kind: "Graph Node",
                    title: node.label.clone(),
                    details: vec![
                        ("Key".into(), node.key.clone()),
                        ("Risk".into(), format!("{:.2}", node.score)),
                        ("Hits".into(), node.hit_count.to_string()),
                        ("Evidence".into(), node.evidence.len().to_string()),
                        ("Reason".into(), node.score_why.clone()),
                    ],
                    available: true,
                })
                .unwrap_or_else(|| missing("Graph Node", key.clone())),
            InvestigationItem::Note(id) => self
                .notebook
                .all()
                .iter()
                .find(|note| note.id == *id)
                .map(|note| InvestigationContext {
                    kind: "Note",
                    title: format!("Note #{}", note.id),
                    details: vec![
                        ("Text".into(), note.text.clone()),
                        (
                            "Tags".into(),
                            if note.tags.is_empty() {
                                "none".into()
                            } else {
                                note.tags.join(", ")
                            },
                        ),
                        (
                            "Evidence".into(),
                            note.evidence
                                .as_ref()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| "none".into()),
                        ),
                    ],
                    available: true,
                })
                .unwrap_or_else(|| missing("Note", format!("Note #{id}"))),
        })
    }

    pub fn active_investigation_stream(&self) -> Option<&ReassembledStream> {
        if let Some(InvestigationItem::Stream(id)) = self
            .worklist
            .active
            .and_then(|index| self.worklist.items.get(index))
        {
            return self.core.streams.get(id);
        }
        let packet = self.active_investigation_packet()?;
        let key = StreamKey::from_packet(packet)?;
        self.core.streams.get(&key.id())
    }

    pub fn open_active_investigation_stream_overlay(&mut self) {
        if let Some(stream) = self.active_investigation_stream() {
            let id = stream.key.id();
            self.open_reassembled_stream(id);
            return;
        }
        let Some(packet) = self.active_investigation_packet() else {
            self.set_status("No packet selected for stream follow");
            return;
        };
        let Some(key) = StreamKey::from_packet(packet) else {
            self.set_status("Active packet is not TCP-backed");
            return;
        };
        self.open_reassembled_stream(key.id());
    }

    pub(super) fn open_reassembled_stream(&mut self, id: String) {
        let Some(stream) = self.core.streams.get(&id) else {
            self.set_status("No reassembled stream is available for this packet yet");
            return;
        };

        let mut segments = Vec::new();
        for segment in &stream.segments {
            let data = if segment.from_client {
                &stream.client_data
            } else {
                &stream.server_data
            };
            let end = segment
                .offset
                .saturating_add(segment.length)
                .min(data.len());
            if segment.offset < end {
                segments.push((segment.from_client, data[segment.offset..end].to_vec()));
            }
        }
        if segments.is_empty() {
            self.set_status("Reassembled stream has no payload bytes yet");
            return;
        }
        self.stream_overlay = Some(StreamOverlayState::new(id, segments));
    }

    pub fn export_stream_overlay(&mut self) {
        let Some(overlay) = &self.stream_overlay else {
            return;
        };
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = format!("packrat_stream_{stamp}");
        let result = crate::analysis::stream::export_segments(&overlay.segments, &base);
        match result {
            Ok((left, right)) => self.set_status(format!(
                "Exported stream to {} and {}",
                left.display(),
                right.display()
            )),
            Err(error) => self.set_status(format!("Stream export failed: {error}")),
        }
    }

    pub fn open_packet_comparison(&mut self) {
        let Some(active_packet_no) = self.worklist.active_packet_no() else {
            self.set_status("Select a packet in the investigation tray to compare");
            return;
        };
        let packet_nos = self.worklist.packet_nos();
        if packet_nos.len() < 2 {
            self.set_status("Add at least two packets to the worklist for comparison");
            return;
        }
        let active_index = packet_nos
            .iter()
            .position(|no| *no == active_packet_no)
            .unwrap_or(0);
        let target_index = (active_index + 1) % packet_nos.len();
        let Some(left) = self.packet_by_no(active_packet_no) else {
            self.set_status("Active worklist packet is no longer available");
            return;
        };
        let Some(right) = packet_nos
            .get(target_index)
            .and_then(|no| self.packet_by_no(*no))
        else {
            self.set_status("Comparison worklist packet is no longer available");
            return;
        };
        self.packet_comparison = Some(packet_compare::compare(left, right));
    }

    pub fn mark_selected_packet_for_investigation(&mut self) {
        let Some(packet_no) = self.selected_packet().map(|packet| packet.no) else {
            self.set_status("No packet selected to add to worklist");
            return;
        };
        self.pin_investigation_item(InvestigationItem::Packet(packet_no));
    }

    pub fn pin_investigation_item(&mut self, item: InvestigationItem) -> bool {
        let label = item.label();
        let added = if let InvestigationItem::Packet(no) = &item {
            let Some(packet) = self.packet_by_no(*no).cloned() else {
                self.set_status(format!("Packet #{no} is no longer available to pin"));
                return false;
            };
            match self.worklist.pin_packet(&packet) {
                Ok(added) => added,
                Err(error) => {
                    self.set_status(error);
                    return false;
                }
            }
        } else {
            self.worklist.add(item)
        };
        self.project_dirty |= added;
        self.set_status(if added {
            format!("Pinned {label} to investigation tray")
        } else {
            format!("{label} is already in the investigation tray")
        });
        added
    }

    pub fn pin_selected_alert(&mut self) -> bool {
        let Some(id) = self.core.alert_center.selected_item().map(|item| item.id) else {
            self.set_status("No alert selected to pin");
            return false;
        };
        self.pin_investigation_item(InvestigationItem::Alert(id))
    }

    pub fn pin_current_context(&mut self) -> bool {
        let item = match self.active_tab {
            Tab::Packets => self
                .selected_packet()
                .map(|packet| InvestigationItem::Packet(packet.no)),
            Tab::Investigate => self
                .active_investigation_packet()
                .map(|packet| InvestigationItem::Packet(packet.no)),
            Tab::Flows => {
                let sorted = self.core.flow_tracker.sorted_flows(&self.flows_sort);
                self.flows_selected
                    .and_then(|index| sorted.get(index))
                    .map(|flow| {
                        InvestigationItem::Stream(format!(
                            "{}:{} <-> {}:{} ({})",
                            flow.key.ep1.0,
                            flow.key.ep1.1,
                            flow.key.ep2.0,
                            flow.key.ep2.1,
                            flow.key.proto,
                        ))
                    })
            }
            Tab::Hosts => {
                let hosts = if self.hosts_search.is_empty() {
                    self.core.hosts.all()
                } else {
                    self.core.hosts.search(&self.hosts_search)
                };
                hosts
                    .get(self.hosts_scroll)
                    .map(|host| InvestigationItem::Host(host.ip.clone()))
            }
            Tab::Security => self
                .core
                .alert_center
                .selected_item()
                .map(|alert| InvestigationItem::Alert(alert.id)),
            Tab::Objects if self.objects_subtab == ObjectsSubTab::Objects => self
                .carved_objects
                .get(self.objects_scroll)
                .map(|object| InvestigationItem::Object(object.id)),
            Tab::OperatorGraph => self
                .graph_ui
                .selected_node
                .and_then(|id| self.core.operator_graph.get_node(id))
                .map(|node| InvestigationItem::GraphNode(node.key.clone())),
            Tab::Notebook => {
                let notes = if self.notebook_search.is_empty() {
                    self.notebook.all().iter().collect::<Vec<_>>()
                } else {
                    self.notebook.search(&self.notebook_search)
                };
                notes
                    .get(self.notebook_scroll)
                    .map(|note| InvestigationItem::Note(note.id))
            }
            _ => None,
        };
        let Some(item) = item else {
            self.set_status("No investigation context is selected in this view");
            return false;
        };
        self.pin_investigation_item(item)
    }

    pub fn open_selected_packet_investigation(&mut self) {
        let Some(packet_no) = self.selected_packet().map(|packet| packet.no) else {
            self.set_status("No packet selected to investigate");
            return;
        };
        self.pin_investigation_item(InvestigationItem::Packet(packet_no));
        if self.worklist.retained_packet(packet_no).is_none() {
            return;
        }
        self.navigate_to(Tab::Investigate);
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn toggle_worklist(&mut self) {
        self.worklist.open = !self.worklist.open;
    }

    pub fn close_worklist(&mut self) {
        self.worklist.open = false;
    }

    pub fn worklist_next_packet(&mut self) {
        self.worklist.next();
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn worklist_prev_packet(&mut self) {
        self.worklist.prev();
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn remove_active_worklist_packet(&mut self) {
        match self.worklist.remove_active() {
            Some(item) => {
                self.project_dirty = true;
                self.set_status(format!("Removed {} from investigation tray", item.label()));
            }
            None => self.set_status("Worklist is empty"),
        }
        self.reset_header_focus();
    }

    pub fn investigation_next_view(&mut self) {
        let next = (self.investigation_view.index() + 1) % InvestigationView::COUNT;
        self.investigation_view = InvestigationView::from_index(next);
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn investigation_prev_view(&mut self) {
        let current = self.investigation_view.index();
        let prev = if current == 0 {
            InvestigationView::COUNT - 1
        } else {
            current - 1
        };
        self.investigation_view = InvestigationView::from_index(prev);
        self.investigation_scroll = 0;
        self.reset_header_focus();
    }

    pub fn investigation_scroll_down(&mut self) {
        self.investigation_scroll = self.investigation_scroll.saturating_add(1);
    }

    pub fn investigation_scroll_up(&mut self) {
        self.investigation_scroll = self.investigation_scroll.saturating_sub(1);
    }
}
