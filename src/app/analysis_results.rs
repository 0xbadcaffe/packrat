use super::*;
use crate::analysis::impact::EndpointEvidence;
use crate::analysis::incident::Incident;
use crate::engine::PacketAnalysis;

pub(super) struct AnalysisContext {
    incidents: Vec<Incident>,
    endpoints: Vec<EndpointEvidence>,
    independent: std::collections::HashSet<u64>,
}

impl App {
    pub(super) fn analysis_context(&self, analysis: &PacketAnalysis) -> Option<AnalysisContext> {
        if analysis.incidents.is_empty() {
            return Some(AnalysisContext {
                incidents: Vec::new(),
                endpoints: Vec::new(),
                independent: Default::default(),
            });
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
            AnalysisContext {
                incidents,
                endpoints: core.endpoint_evidence.clone(),
                independent,
            }
        })
    }

    pub(super) fn handle_packet_analysis(
        &mut self,
        analysis: PacketAnalysis,
        context: AnalysisContext,
        live: bool,
        restoring: bool,
    ) {
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
        for id in analysis.alert_pins {
            self.worklist.add(InvestigationItem::Alert(id));
        }
    }
}
