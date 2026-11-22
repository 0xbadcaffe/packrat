use super::*;
use super::alert_evidence::AlertEvidenceScope;

#[cfg(test)]
#[path = "../../tests/unit/app_alert_capacity_tests.rs"]
mod tests;

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
        self.try_view()
            .ok()
            .flatten()?
            .active_investigation_context()
    }

    pub fn active_investigation_stream(&self) -> Option<ReassembledStream> {
        self.try_view()
            .ok()
            .flatten()?
            .active_investigation_stream()
            .cloned()
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
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            self.set_status("Analysis busy; retry stream inspection");
            return;
        };
        let Some(stream) = core.streams.get(&id) else {
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
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            return false;
        };
        let Some(id) = core.alert_center.selected_item().map(|item| item.id) else {
            self.set_status("No alert selected to pin");
            return false;
        };
        self.pin_investigation_item(InvestigationItem::Alert(id))
    }

    pub fn investigate_selected_alert(&mut self) -> bool {
        self.investigate_alert(None)
    }

    pub(super) fn investigate_alert(&mut self, target: Option<&AlertSearchRef>) -> bool {
        if !self.analysis_generation_ready() {
            self.set_status("Analysis busy; retry alert investigation");
            return false;
        }
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            self.set_status("Analysis busy; retry alert investigation");
            return false;
        };
        let alert = match target {
            Some(target) => core.alert_center.items.iter().find(|alert| {
                alert.id == target.id && alert.capture_id == target.capture_id
            }),
            None => core.alert_center.selected_item(),
        };
        let Some(alert) = alert.cloned() else {
            self.set_status(if target.is_some() {
                "The searched alert is no longer available"
            } else {
                "No alert selected to investigate"
            });
            return false;
        };
        drop(core);

        let packet_refs = alert.evidence_frame_numbers();

        let alert_item = InvestigationItem::Alert(alert.id);
        self.project_dirty |= self.worklist.add(alert_item.clone());
        let scope = alert.capture_id.as_deref();
        let evidence_scope = self.alert_evidence_scope(&alert);
        let same_capture = evidence_scope == AlertEvidenceScope::CurrentCapture;
        let scope_mismatch = evidence_scope.local_mismatch();
        let mut reader = None;
        let mut archive_error = false;
        let mut resolve_frame = |app: &Self, packet_no| {
            let saved = app.saved_alert_pin(&alert, packet_no);
            let local = saved.or_else(|| {
                app.frame_may_be_local(evidence_scope, packet_no)
                    .then(|| app.packet_by_no(packet_no)).flatten()
            }).cloned();
            let from_archive = local.is_none() && same_capture;
            let packet = if from_archive {
                if reader.is_none() && !archive_error {
                    match app.packet_archive.as_ref().map(|archive| archive.reader()) {
                        Some(Ok(opened)) => reader = Some(opened),
                        Some(Err(_)) => archive_error = true,
                        None => {}
                    }
                }
                reader.as_mut().and_then(|reader| {
                    match reader.packet_for_capture(scope.unwrap_or_default(), packet_no) {
                        Ok(packet) => packet,
                        Err(_) => {
                            archive_error = true;
                            None
                        }
                    }
                })
            } else {
                local
            };
            packet.map(|packet| (packet, from_archive))
        };
        let mut trigger = packet_refs.binary_search(&alert.packet_no).ok()
            .and_then(|_| resolve_frame(self, alert.packet_no));
        if let Some((packet, _)) = &trigger {
            // Reserve bytes before processing older evidence; add the tray item in order below.
            let _ = self.worklist.retain_packet(packet);
        }

        let mut unavailable = 0;
        let mut at_capacity = 0;
        let mut archived = 0;
        let mut retained = Vec::with_capacity(packet_refs.len());
        for packet_no in packet_refs {
            let frame = if packet_no == alert.packet_no {
                trigger.take()
            } else {
                resolve_frame(self, packet_no)
            };
            let Some((packet, from_archive)) = frame else {
                unavailable += 1;
                continue;
            };
            match self.worklist.pin_packet(&packet) {
                Ok(added) => {
                    self.project_dirty |= added;
                    retained.push(packet.no);
                    archived += usize::from(from_archive);
                }
                Err(_) => {
                    unavailable += 1;
                    at_capacity += 1;
                }
            }
        }
        self.worklist.open = true;
        self.worklist.active = retained.iter().find(|&&frame| frame == alert.packet_no)
            .or_else(|| retained.first())
            .and_then(|packet_no| {
                self.worklist
                    .items
                    .iter()
                    .position(|item| *item == InvestigationItem::Packet(*packet_no))
            })
            .or_else(|| {
                self.worklist
                    .items
                    .iter()
                    .position(|item| *item == alert_item)
            });
        self.investigation_view = InvestigationView::Summary;
        self.navigate_to(Tab::Investigate);
        self.set_status(format!(
            "Alert #{}: opened {} matching packets ({} archived); {} unavailable{}{}",
            alert.id,
            retained.len(),
            archived,
            unavailable,
            if at_capacity > 0 { format!(" ({at_capacity} hit the tray limit)") } else { String::new() },
            scope_mismatch.map(|reason| if retained.is_empty() { reason } else { "saved case" })
                .or(archive_error.then_some("archive read failed"))
                .map_or_else(String::new, |reason| format!(" ({reason})"))
        ));
        true
    }

    pub fn pin_current_context(&mut self) -> bool {
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            return false;
        };
        let item = match self.active_tab {
            Tab::Packets => self
                .selected_packet()
                .map(|packet| InvestigationItem::Packet(packet.no)),
            Tab::Investigate => self
                .active_investigation_packet()
                .map(|packet| InvestigationItem::Packet(packet.no)),
            Tab::Flows => {
                let sorted = core.flow_tracker.sorted_flows(&self.flows_sort);
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
                    core.hosts.all()
                } else {
                    core.hosts.search(&self.hosts_search)
                };
                hosts
                    .get(self.hosts_scroll)
                    .map(|host| InvestigationItem::Host(host.ip.clone()))
            }
            Tab::Security => core
                .alert_center
                .selected_item()
                .map(|alert| InvestigationItem::Alert(alert.id)),
            Tab::Objects if self.objects_subtab == ObjectsSubTab::Objects => core
                .carved_objects
                .get(self.objects_scroll)
                .map(|object| InvestigationItem::Object(object.id)),
            Tab::OperatorGraph => self
                .graph_ui
                .selected_node
                .and_then(|id| core.operator_graph.get_node(id))
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
