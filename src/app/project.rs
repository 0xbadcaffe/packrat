use super::*;

impl App {
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
    ) -> crate::model::project::ProjectState {
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
        for host in self.hosts.all() {
            if !host.tags.is_empty() {
                let mut tags: Vec<String> = host.tags.iter().cloned().collect();
                tags.sort();
                state.host_tags.insert(host.ip.clone(), tags);
            }
        }
        // Carved object metadata
        state.carved_objects = self.carved_objects.iter().map(ObjectEntry::from).collect();
        state.alert_items = self.alert_center.items.clone();
        state.alert_automation = self.alert_center.automation_mode;
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
        state.incident_state = Some(self.incidents.snapshot());
        state.endpoint_evidence = self.endpoint_evidence.clone();
        state.guard_simulation = self.response_preview.clone();
        state.active_tab = self.active_tab.index();
        if portable {
            state.embedded_packets = self.packets.iter().cloned().collect();
        }
        state
    }

    /// Save the current project to `path`.  Marks the workspace clean.
    pub fn save_project(&mut self, path: &str, name: &str, mode: ProjectSaveMode) {
        let state = self.snapshot_project(name, mode.clone());
        let p = std::path::Path::new(path);
        match project_store::save(&state, p) {
            Ok(()) => {
                let _ = project_store::add_to_recent(
                    name,
                    p,
                    state.metadata.description.as_deref(),
                    mode,
                );
                self.current_project_name = Some(name.to_string());
                self.current_project_path = Some(path.to_string());
                self.project_dirty = false;
                self.set_status(format!("Project saved: {name}"));
            }
            Err(e) => {
                self.set_status(format!("Save failed: {e}"));
            }
        }
    }

    /// Load a project from `path`, restoring notebook, tags, filter, host tags.
    pub fn load_project(&mut self, path: &str) {
        match project_store::load(std::path::Path::new(path)) {
            Ok(state) => {
                let name = state.metadata.name.clone();
                let mode = state.metadata.save_mode.clone();
                let description = state.metadata.description.clone();
                if let Err(error) = self.apply_project_state(state) {
                    self.project_manager.status = Some(format!("Load failed: {error}"));
                    return;
                }
                // Update project tracking state
                let _ = project_store::add_to_recent(
                    &name,
                    std::path::Path::new(path),
                    description.as_deref(),
                    mode,
                );
                self.current_project_name = Some(name.clone());
                self.current_project_path = Some(path.to_string());
                self.project_dirty = false;
                self.project_manager_open = false;
                self.set_status(format!("Project loaded: {name}"));
            }
            Err(e) => {
                self.project_manager.status = Some(format!("Load failed: {e}"));
            }
        }
    }

    pub(super) fn apply_project_state(
        &mut self,
        mut state: crate::model::project::ProjectState,
    ) -> Result<(), String> {
        // Validate before replacing the active investigation.
        let tray = restore_investigation_tray(&state)?;
        let incidents = state
            .incident_state
            .take()
            .map(IncidentStore::from_snapshot)
            .transpose()?;
        if state.endpoint_evidence.len() > 10_000
            || serde_json::to_vec(&state.endpoint_evidence)
                .map_err(|error| error.to_string())?
                .len()
                > 8 * 1024 * 1024
        {
            return Err("Saved endpoint evidence exceeds limits".into());
        }
        self.clear_packets();
        self.restoring_project = true;
        for packet in state.embedded_packets {
            self.inject_packet(packet);
        }
        self.restoring_project = false;
        // Saved evidence is historical even when the project contains no frames.
        self.live_response_eligible = false;
        self.live_response_incidents.clear();
        if let Some(incidents) = incidents {
            self.incidents = incidents;
        }
        self.endpoint_evidence = state.endpoint_evidence;
        self.notebook = state.notebook;
        self.tag_store = state.tag_store;
        self.filter.input = state.active_filter;
        self.rebuild_filtered();
        for (ip, tags) in state.host_tags {
            self.hosts.seed_tags(&ip, tags);
        }
        self.alert_center
            .restore(state.alert_items, state.alert_automation);
        self.worklist = tray;
        self.response_preview = state.guard_simulation;
        if state.active_tab < Tab::COUNT {
            self.active_tab = Tab::from_index(state.active_tab);
        }
        self.alert_overlay_open = self.incidents.active().is_some();
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
