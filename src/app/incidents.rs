use super::*;

impl App {
    #[cfg(test)]
    pub(super) fn open_industry_incident(
        &mut self,
        packet: &Packet,
        signature: &str,
        detail: &str,
    ) {
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();
        let id = core.incidents.open_or_update(
            IncidentSource::IndustrySignature,
            signature,
            detail,
            EvidenceSeverity::Critical,
            packet,
            self.packets.iter().cloned(),
        );
        drop(core);
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

    #[cfg(test)]
    pub(super) fn open_user_rule_incident(
        &mut self,
        packet: &Packet,
        rule_id: &str,
        rule_name: &str,
        message: &str,
        auto_contain: bool,
    ) {
        let core_handle = self.core.clone();
        let mut core = core_handle.edit();
        let id = core.incidents.open_or_update(
            IncidentSource::UserRule,
            rule_id,
            format!("{rule_name}: {message}"),
            EvidenceSeverity::Critical,
            packet,
            self.packets.iter().cloned(),
        );
        drop(core);
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

    #[cfg(test)]
    pub(super) fn freeze_incident_evidence(&mut self, incident_id: u64) {
        let core_handle = self.core.clone();
        let core = core_handle.edit();
        let incident = core
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
            .freeze_with_endpoint_evidence(&incident, &core.endpoint_evidence)
        {
            self.set_status(format!(
                "Incident #{incident_id} retained in memory; evidence export failed: {error}"
            ));
        }
    }

    #[cfg(test)]
    pub(super) fn evaluate_traffic_latch(&mut self, incident_id: u64, auto_contain_rule: bool) {
        let core_handle = self.core.clone();
        let core = core_handle.edit();
        let incident = core
            .incidents
            .incidents
            .iter()
            .find(|incident| incident.id == incident_id)
            .cloned();
        drop(core);
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
        self.query_core(|core| {
            let mut detectors = std::collections::BTreeSet::new();
            for candidate in core.incidents.incidents.iter().filter(|candidate| {
                candidate.attacker == incident.attacker
                    && candidate.target == incident.target
                    && candidate.severity == EvidenceSeverity::Critical
                    && candidate.status == crate::analysis::incident::IncidentStatus::PendingReview
            }) {
                detectors.insert((candidate.source, candidate.detector.clone()));
            }
            detectors.len() >= 2
        })
        .unwrap_or(false)
    }

    pub fn approve_active_latch(&mut self) {
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            self.set_status("Analysis busy; retry containment review");
            return;
        };
        let Some(incident_id) = core.incidents.active().map(|incident| incident.id) else {
            self.set_status("No active incident has a pending TrafficLatch action");
            return;
        };
        drop(core);
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
        let core_handle = self.core.clone();
        let Ok(Some(core)) = core_handle.try_read() else {
            return;
        };
        let incidents = core.incidents.incidents.clone();
        drop(core);
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
        let Some(Some(id)) = self.query_core(|core| core.incidents.active().map(|i| i.id)) else {
            return false;
        };
        self.configure_core(move |core| {
            if let Some(incident) = core.incidents.incidents.iter_mut().find(|i| i.id == id) {
                incident.reviewed = true;
            }
        });
        self.active_tab = Tab::Analysis;
        self.analysis_section = INCIDENT_ANALYSIS_SECTION;
        self.alert_overlay_open = false;
        self.set_status("Incident reviewed. Press C in Incident History to acknowledge the alert.");
        true
    }

    /// Acknowledgement hides the active alert but preserves its history.
    pub fn acknowledge_active_incident(&mut self) -> Result<(), &'static str> {
        let Some(Some((id, reviewed, other_pending))) = self.query_core(|core| {
            core.incidents.active().map(|i| {
                (
                    i.id,
                    i.reviewed,
                    core.incidents.incidents.iter().any(|other| {
                        other.id != i.id
                            && other.status
                                == crate::analysis::incident::IncidentStatus::PendingReview
                    }),
                )
            })
        }) else {
            return Err("no active incident or analysis busy");
        };
        if !reviewed {
            return Err("review the incident analysis before acknowledging it");
        }
        self.update_core(
            "Incident acknowledged; retained packet history remains available.",
            move |core| {
                if core.incidents.active().is_none_or(|i| i.id != id) {
                    return Err("Incident changed; review the current alert".into());
                }
                core.incidents.acknowledge_active().map_err(str::to_string)
            },
        );
        self.alert_overlay_open = other_pending;
        self.set_status("Incident acknowledged; retained packet history remains available.");
        Ok(())
    }
}
