use super::*;
use crate::analysis::alert_center::AlertItem;
use crate::analysis::impact::EndpointEvidence;
use crate::analysis::incident::Incident;
use crate::engine::PacketAnalysis;

#[derive(Default)]
pub(super) struct AnalysisContext {
    incidents: Vec<Incident>,
    endpoints: Vec<EndpointEvidence>,
    independent: std::collections::HashSet<u64>,
    alerts: Vec<AlertItem>,
    auto_pin: bool,
}

impl App {
    pub(super) fn analysis_context(&self, analysis: &PacketAnalysis) -> Option<AnalysisContext> {
        if analysis.incidents.is_empty() && analysis.alert_pins.is_empty() {
            return Some(AnalysisContext::default());
        }
        self.query_core(|core| {
            let incidents: Vec<_> = analysis
                .incidents
                .iter()
                .filter_map(|notice| {
                    core.incidents
                        .incidents
                        .iter()
                        .find(|incident| incident.id == notice.id)
                        .cloned()
                })
                .collect();
            let independent = incidents
                .iter()
                .filter(|incident| {
                    core.incidents
                        .incidents
                        .iter()
                        .filter(|candidate| {
                            candidate.attacker == incident.attacker
                                && candidate.target == incident.target
                                && candidate.status
                                    == crate::analysis::incident::IncidentStatus::PendingReview
                                && candidate.severity == EvidenceSeverity::Critical
                        })
                        .map(|candidate| (candidate.source, candidate.detector.as_str()))
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        >= 2
                })
                .map(|incident| incident.id)
                .collect();
            let mut alerts: Vec<_> = analysis.alert_pins.iter().filter_map(|id| {
                core.alert_center.items.iter().find(|item| item.id == *id).cloned()
            }).collect();
            alerts.sort_by_key(|alert| std::cmp::Reverse(alert.priority));
            AnalysisContext {
                auto_pin: core.alert_center.automation_mode != AutomationMode::Off,
                endpoints: if incidents.is_empty() { Vec::new() } else { core.endpoint_evidence.clone() },
                incidents,
                independent,
                alerts,
            }
        })
    }

    pub(super) fn handle_packet_analysis(
        &mut self,
        analysis: PacketAnalysis,
        context: AnalysisContext,
        live: bool,
        restoring: bool,
        evidence: &[Packet],
    ) {
        if restoring {
            return;
        }
        self.processing_live_packet = live && self.live_response_eligible;
        for notice in analysis.incidents {
            if !restoring {
                if let Some(incident) = context
                    .incidents
                    .iter()
                    .find(|incident| incident.id == notice.id)
                {
                    if let Err(error) = self
                        .evidence_vault
                        .freeze_with_endpoint_evidence(incident, &context.endpoints)
                    {
                        self.set_status(format!(
                            "Incident #{} retained in memory; evidence export failed: {error}",
                            notice.id
                        ));
                    }
                    if self.processing_live_packet {
                        self.live_response_incidents.insert(notice.id);
                    }
                    if !self.live_response_eligible
                        || !self.live_response_incidents.contains(&notice.id)
                    {
                        self.traffic_latch.observe_offline_incident(incident);
                    } else {
                        let allowed =
                            notice.auto_contain_rule || context.independent.contains(&notice.id);
                        if let Some(path) = &self.latch_helper_path {
                            self.traffic_latch.on_incident_with_auto_gate(
                                incident,
                                &CommandLatch::new(path),
                                allowed,
                            );
                        } else {
                            self.traffic_latch.on_incident_with_auto_gate(
                                incident,
                                &NftablesLatch,
                                allowed,
                            );
                        }
                    }
                }
            }
            self.alert_overlay_open = true;
            self.set_status(format!(
                "Critical incident #{}: {}",
                notice.id, notice.label
            ));
        }
        let previous_active = self.worklist.active;
        for alert in &context.alerts {
            self.archive_alert_packets(alert, evidence);
            if context.auto_pin && alert.is_priority_evidence() {
                let current = evidence.binary_search_by_key(&alert.packet_no, |packet| packet.no)
                    .ok().map(|index| &evidence[index]);
                self.retain_automatic_alert_evidence(alert, current);
            }
        }
        self.worklist.active = previous_active;
    }

    fn retain_automatic_alert_evidence(&mut self, alert: &AlertItem, current: Option<&Packet>) {
        let scope = self.alert_evidence_scope(alert);
        if scope.local_mismatch().is_some() {
            return;
        }
        self.project_dirty |= self.worklist.add(InvestigationItem::Alert(alert.id));
        let mut frames = alert.evidence_frame_numbers();
        frames.retain(|&frame| {
            self.frame_may_be_local(scope, frame) && self.worklist.retained_packet(frame).is_none()
        });
        if frames.is_empty() {
            return;
        }
        let trigger = current.filter(|packet| packet.no == alert.packet_no)
            .or_else(|| {
                frames.binary_search(&alert.packet_no).ok()?;
                self.packets.iter().find(|packet| packet.no == alert.packet_no)
            });
        if let Some(packet) = trigger && let Ok(index) = frames.binary_search(&packet.no) {
            self.project_dirty |= self.worklist.pin_packet(packet).unwrap_or(false);
            frames.remove(index);
        }
        let mut remaining = frames.len();
        for packet in &self.packets {
            if remaining == 0 {
                break;
            }
            if frames.binary_search(&packet.no).is_ok()
                && self.worklist.pin_packet(packet).unwrap_or(false)
            {
                self.project_dirty = true;
                remaining -= 1;
            }
        }
    }
}
