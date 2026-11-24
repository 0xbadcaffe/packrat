use super::*;

impl App {
    pub(crate) fn offline_review(&self) -> bool {
        self.offline_review
    }

    pub(crate) fn saved_packet_capture(&self, frame: u64) -> Option<&str> {
        self.worklist.restored_packet_scopes.get(&frame).map(String::as_str)
    }

    pub(crate) fn retained_evidence_label(&self) -> String {
        use crate::storage::alert_evidence::{FrameStatus, frame_status};
        let packets = &self.worklist.retained_packets;
        let mut text = format!("  {} retained frames", packets.len());
        let (mut truncated, mut unknown, mut unreadable) = (0, 0, 0);
        for packet in packets.values() {
            match frame_status(packet) {
                FrameStatus::Truncated => truncated += 1,
                FrameStatus::LengthUnknown => unknown += 1,
                FrameStatus::Unreadable => unreadable += 1,
                _ => {}
            }
        }
        for (count, label) in [(truncated, "truncated"), (unknown, "length unknown"), (unreadable, "unreadable")] {
            if count > 0 {
                use std::fmt::Write;
                let _ = write!(text, " | {count} {label}");
            }
        }
        text
    }

    // ─── Project save / load ──────────────────────────────────────────────────

    /// Open the project manager overlay and refresh the recent list.
    pub fn open_project_manager(&mut self) {
        self.project_manager_open = true;
        self.project_manager.recent = project_store::recent_projects();
        self.project_manager.status = None;
    }

    /// Snapshot the current analysis state into a `ProjectState`.
    pub(super) fn snapshot_project(
        &self,
        name: &str,
        mode: ProjectSaveMode,
    ) -> Result<crate::model::project::ProjectState, String> {
        if !self.analysis_idle() {
            return Err("Analysis is still pending; pause capture and retry saving".into());
        }
        let core_handle = self.core.clone();
        let core = core_handle
            .try_read()?
            .ok_or("Analysis busy; retry saving")?;
        use crate::model::project::ProjectState;
        use crate::storage::case_bundle::ObjectEntry;
        let portable = mode == ProjectSaveMode::Portable;
        let mut state = ProjectState::new(name, mode);
        // Clone notebook
        state.notebook = self.notebook.clone();
        // Clone tag store
        state.tag_store = self.tag_store.clone();
        // Active filter text
        state.active_filter = self.filter.input.clone();
        // Host tags: ip → sorted vec
        for host in core.hosts.all() {
            if !host.tags.is_empty() {
                let mut tags: Vec<String> = host.tags.iter().cloned().collect();
                tags.sort();
                state.host_tags.insert(host.ip.clone(), tags);
            }
        }
        // Carved object metadata
        state.carved_objects = core.carved_objects.iter().map(ObjectEntry::from).collect();
        state.alert_items = core.alert_center.items.clone();
        state.alert_archive_report = self.saved_alert_archive_report.clone();
        state.alert_automation = core.alert_center.automation_mode;
        state.investigation_items = self
            .worklist
            .items
            .iter()
            .map(saved_investigation_item)
            .collect();
        state.active_investigation = self.worklist.active;
        state.investigation_tray_open = self.worklist.open;
        state.pinned_packets = self
            .worklist
            .packet_nos()
            .into_iter()
            .filter_map(|no| self.packet_by_no(no).cloned())
            .collect();
        for packet in &state.pinned_packets {
            let scope = self.worklist.restored_packet_scopes.get(&packet.no).map(String::as_str)
                .or_else(|| {
                    (packet.no > self.restored_project_max_frame).then(|| self.capture_id.as_deref()).flatten()
                });
            if let Some(scope) = scope {
                state.pinned_packet_scopes.insert(packet.no, scope.to_owned());
            }
        }
        state.incident_state = Some(core.incidents.snapshot());
        state.endpoint_evidence = core.endpoint_evidence.clone();
        state.guard_simulation = self.response_preview.clone();
        state.active_tab = self.active_tab.index();
        if portable {
            state.embedded_packets = self.packets.iter().cloned().collect();
        }
        Ok(state)
    }

    /// Save the current project to `path`.  Marks the workspace clean.
    pub fn save_project(&mut self, path: &str, name: &str, mode: ProjectSaveMode) {
        if let Err(error) = self.persist_project(path, name, mode, |state, path| {
            project_store::save(state, path)
        }) {
            self.set_status(error);
        }
    }

    pub(crate) fn create_project(&mut self, path: &str, name: &str, mode: ProjectSaveMode) {
        match self.persist_project(path, name, mode, project_store::create) {
            Ok(()) => self.project_manager_open = false,
            Err(error) => self.project_manager.status = Some(error),
        }
    }

    fn persist_project(
        &mut self,
        path: &str,
        name: &str,
        mode: ProjectSaveMode,
        write: impl FnOnce(&crate::model::project::ProjectState, &std::path::Path) -> anyhow::Result<()>,
    ) -> Result<(), String> {
        let state = self.snapshot_project(name, mode.clone())?;
        let p = std::path::Path::new(path);
        write(&state, p).map_err(|error| format!("Save failed: {error}"))?;
        if !self.offline_review {
            let _ = project_store::add_to_recent(name, p, state.metadata.description.as_deref(), mode);
        }
        self.current_project_name = Some(name.to_string());
        self.current_project_path = Some(path.to_string());
        self.project_dirty = false;
        self.set_status(format!("Project saved: {name}"));
        Ok(())
    }

    /// Load a project from `path`, restoring notebook, tags, filter, host tags.
    pub fn load_project(&mut self, path: &str) {
        if let Err(error) = self.open_project(std::path::Path::new(path)) {
            self.project_manager.status = Some(format!("Load failed: {error}"));
        }
    }

    pub fn open_project(&mut self, path: &std::path::Path) -> Result<(), String> {
        let state = project_store::load(path).map_err(|error| format!("{error:#}"))?;
        let name = state.metadata.name.clone();
        let mode = state.metadata.save_mode.clone();
        let description = state.metadata.description.clone();
        self.apply_project_state(state)?;
        if !self.offline_review {
            let _ = project_store::add_to_recent(&name, path, description.as_deref(), mode);
        }
        self.current_project_name = Some(name.clone());
        self.current_project_path = Some(path.to_string_lossy().into_owned());
        self.project_dirty = false;
        self.project_manager_open = false;
        self.set_status(format!("Project loaded: {name}"));
        Ok(())
    }

    pub(super) fn apply_project_state(
        &mut self,
        mut state: crate::model::project::ProjectState,
    ) -> Result<(), String> {
        // Validate before replacing the active investigation.
        let tray = restore_investigation_tray(&state)?;
        state.validate_archive_evidence()?;
        let incidents = state
            .incident_state
            .take()
            .map(IncidentStore::from_snapshot)
            .transpose()?;
        crate::analysis::impact::validate_endpoint_evidence(&state.endpoint_evidence)?;
        let bytes = state
            .embedded_packets
            .iter()
            .try_fold(0usize, |total, packet| {
                total.checked_add(packet.bytes.len().saturating_add(512))
            })
            .ok_or("Saved packet budget overflow")?;
        if state.embedded_packets.len() > 100_000 || bytes > 256 * 1024 * 1024 {
            return Err("Saved packet history exceeds analysis budget".into());
        }
        let derive_saved_context = self.offline_review && state.embedded_packets.is_empty()
            && state.pcap_refs.is_empty() && state.pinned_packets.first().is_some_and(|first| {
                let Some(scope) = state.pinned_packet_scopes.get(&first.no) else { return false; };
                state.pinned_packets.iter().all(|packet| state.pinned_packet_scopes.get(&packet.no) == Some(scope))
                    && state.alert_items.iter().any(|alert| alert.capture_id.as_ref() == Some(scope))
            });
        self.try_clear_packets()?;
        self.restored_project_max_frame = state
            .pinned_packets
            .iter()
            .chain(&state.embedded_packets)
            .map(|packet| packet.no)
            .max()
            .unwrap_or(0);
        if self.capture_id.is_some() {
            // Never let a newly accepted frame reuse a historical evidence number.
            self.capture_frame_high_water = state
                .alert_items
                .iter()
                .flat_map(|alert| {
                    [alert.packet_no, alert.first_packet, alert.last_packet]
                        .into_iter()
                        .chain(alert.packet_refs.iter().copied())
                })
                .chain(tray.packet_nos())
                .chain(state.embedded_packets.iter().map(|packet| packet.no))
                .max()
                .unwrap_or(0)
                .max(self.restored_project_max_frame);
        }
        if self.background_analysis_enabled() {
            self.enqueue_offline_packets(state.embedded_packets, true)?;
        } else {
            self.restoring_project = true;
            for packet in state.embedded_packets {
                self.inject_packet(packet);
            }
            self.restoring_project = false;
        }
        // Saved evidence is historical even when the project contains no frames.
        self.live_response_eligible = false;
        self.live_response_incidents.clear();
        self.alert_overlay_open = incidents
            .as_ref()
            .is_some_and(|store| store.active().is_some());
        let mut evidence = if derive_saved_context { std::mem::take(&mut state.pinned_packets) } else { Vec::new() };
        evidence.sort_unstable_by_key(|packet| packet.no);
        self.configure_core(move |core| {
            for packet in &evidence {
                if crate::storage::alert_evidence::frame_status(packet) != crate::storage::alert_evidence::FrameStatus::Unreadable {
                    core.observe_saved_evidence(packet);
                }
            }
            if let Some(incidents) = incidents {
                core.incidents = incidents;
            }
            core.endpoint_evidence = state.endpoint_evidence;
            for (ip, tags) in state.host_tags {
                core.hosts.seed_tags(&ip, tags);
            }
            core.alert_center
                .restore(state.alert_items, state.alert_automation);
        });
        self.notebook = state.notebook;
        self.tag_store = state.tag_store;
        self.filter.input = state.active_filter;
        self.rebuild_filtered();
        self.worklist = tray;
        self.saved_alert_archive_report = state.alert_archive_report;
        self.response_preview = state.guard_simulation;
        if state.active_tab < Tab::COUNT {
            self.active_tab = Tab::from_index(state.active_tab);
        }
        Ok(())
    }

    /// Quick-save the current project if one is open; otherwise open Save As dialog.
    pub fn quick_save_project(&mut self) {
        if let (Some(path), Some(name)) = (
            self.current_project_path.clone(),
            self.current_project_name.clone(),
        ) {
            self.save_project(&path, &name, ProjectSaveMode::Lightweight);
        } else {
            // No active project — open manager on New tab
            self.open_project_manager();
            self.project_manager.tab = crate::ui::project_manager::PmTab::New;
        }
    }

    /// Export a full case bundle JSON to a timestamped file and set a status message.
    pub fn export_case_bundle(&mut self) {
        match crate::analysis::case_export::export_auto(self) {
            Ok(path) => self.set_status(format!("Case bundle written: {path}")),
            Err(e) => self.set_status(format!("Export failed: {e}")),
        }
    }
}
