use super::*;

impl App {
    pub(super) fn open_industry_incident(
        &mut self,
        packet: &Packet,
        signature: &str,
        detail: &str,
    ) {
        let id = self.incidents.open_or_update(
            IncidentSource::IndustrySignature,
            signature,
            detail,
            EvidenceSeverity::Critical,
            packet,
            self.packets.iter().cloned(),
        );
        if !self.restoring_project {
            self.freeze_incident_evidence(id);
            if self.processing_live_packet {
                self.live_response_incidents.insert(id);
            }
            self.evaluate_traffic_latch(id, false);
        }
        self.alert_overlay_open = true;
        self.set_status(format!("Critical incident #{id}: {signature}"));
    }

    pub(super) fn open_user_rule_incident(
        &mut self,
        packet: &Packet,
        rule_id: &str,
        rule_name: &str,
        message: &str,
        auto_contain: bool,
    ) {
        let id = self.incidents.open_or_update(
            IncidentSource::UserRule,
            rule_id,
            format!("{rule_name}: {message}"),
            EvidenceSeverity::Critical,
            packet,
            self.packets.iter().cloned(),
        );
        if !self.restoring_project {
            self.freeze_incident_evidence(id);
            if self.processing_live_packet {
                self.live_response_incidents.insert(id);
            }
            self.evaluate_traffic_latch(id, auto_contain);
        }
        self.alert_overlay_open = true;
        self.set_status(format!("Critical incident #{id}: {rule_name}"));
    }

    pub(super) fn freeze_incident_evidence(&mut self, incident_id: u64) {
        let incident = self
            .incidents
            .incidents
            .iter()
            .find(|incident| incident.id == incident_id)
            .cloned();
        let Some(incident) = incident else {
            return;
        };
        if let Err(error) = self
            .evidence_vault
            .freeze_with_endpoint_evidence(&incident, &self.endpoint_evidence)
        {
            self.set_status(format!(
                "Incident #{incident_id} retained in memory; evidence export failed: {error}"
            ));
        }
    }

    pub(super) fn evaluate_traffic_latch(&mut self, incident_id: u64, auto_contain_rule: bool) {
        let incident = self
            .incidents
            .incidents
            .iter()
            .find(|incident| incident.id == incident_id)
            .cloned();
        if let Some(incident) = incident {
            if !self.live_response_eligible || !self.live_response_incidents.contains(&incident_id)
            {
                self.traffic_latch.observe_offline_incident(&incident);
                return;
            }
            let automatic_allowed =
                auto_contain_rule || self.has_independent_critical_signals(&incident);
            if let Some(path) = self.latch_helper_path.as_ref() {
                let backend = CommandLatch::new(path);
                self.traffic_latch.on_incident_with_auto_gate(
                    &incident,
                    &backend,
                    automatic_allowed,
                );
            } else {
                self.traffic_latch.on_incident_with_auto_gate(
                    &incident,
                    &NftablesLatch,
                    automatic_allowed,
                );
            }
        }
    }

    pub(super) fn has_independent_critical_signals(
        &self,
        incident: &crate::analysis::incident::Incident,
    ) -> bool {
        let mut detectors = std::collections::BTreeSet::new();
        for candidate in self.incidents.incidents.iter().filter(|candidate| {
            candidate.attacker == incident.attacker
                && candidate.target == incident.target
                && candidate.severity == EvidenceSeverity::Critical
                && candidate.status == crate::analysis::incident::IncidentStatus::PendingReview
        }) {
            detectors.insert((candidate.source, candidate.detector.clone()));
        }
        detectors.len() >= 2
    }

    pub fn approve_active_latch(&mut self) {
        let Some(incident_id) = self.incidents.active().map(|incident| incident.id) else {
            self.set_status("No active incident has a pending TrafficLatch action");
            return;
        };
        if !self.live_response_eligible || !self.live_response_incidents.contains(&incident_id) {
            self.set_status("Containment disabled for offline, synthetic, or mixed evidence; start a clean live session");
            return;
        }
        let result = if let Some(path) = self.latch_helper_path.as_ref() {
            let backend = CommandLatch::new(path);
            self.traffic_latch.approve(incident_id, &backend)
        } else {
            self.traffic_latch.approve(incident_id, &NftablesLatch)
        };
        match result {
            Ok(action) => {
                let detail = action.detail.clone();
                self.set_status(format!("TrafficLatch: {detail}"));
            }
            Err(error) => self.set_status(format!("TrafficLatch error: {error}")),
        }
    }

    pub fn simulate_guard_response(&mut self) {
        let incidents = self.incidents.incidents.clone();
        self.response_preview = incidents
            .iter()
            .filter(|incident| {
                incident.status == crate::analysis::incident::IncidentStatus::PendingReview
            })
            .map(|incident| {
                let allowed = self.has_independent_critical_signals(incident);
                self.traffic_latch.simulate_incident(incident, allowed)
            })
            .collect();
        let eligible = self
            .response_preview
            .iter()
            .filter(|action| {
                action.status == crate::analysis::traffic_latch::LatchStatus::Previewed
            })
            .count();
        self.set_status(format!(
            "Guard simulation: {eligible} eligible, {} require review or were rejected",
            self.response_preview.len().saturating_sub(eligible),
        ));
    }

    pub fn engage_guard_kill_switch(&mut self) {
        let (revoked, failed) = if let Some(path) = self.latch_helper_path.as_ref() {
            self.traffic_latch
                .engage_kill_switch(&CommandLatch::new(path))
        } else {
            self.traffic_latch.engage_kill_switch(&NftablesLatch)
        };
        self.set_status(format!(
            "Guard stopped: monitor mode, {revoked} active blocks revoked, {failed} revocations failed",
        ));
    }

    pub fn clear_guard_kill_switch(&mut self) {
        self.traffic_latch.clear_kill_switch();
        self.set_status("Guard kill switch reset; containment remains in monitor mode");
    }

    /// Open the retained incident packet history and record that it was reviewed.
    pub fn open_active_incident_analysis(&mut self) -> bool {
        if !self.incidents.mark_active_reviewed() {
            return false;
        }
        self.active_tab = Tab::Analysis;
        self.analysis_section = INCIDENT_ANALYSIS_SECTION;
        self.alert_overlay_open = false;
        self.set_status("Incident reviewed. Press C in Incident History to acknowledge the alert.");
        true
    }

    /// Acknowledgement hides the active alert but preserves its history.
    pub fn acknowledge_active_incident(&mut self) -> Result<(), &'static str> {
        self.incidents.acknowledge_active()?;
        self.alert_overlay_open = self.incidents.active().is_some();
        self.set_status("Incident acknowledged; retained packet history remains available.");
        Ok(())
    }
}
