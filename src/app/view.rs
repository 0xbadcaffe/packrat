use super::*;
use crate::analysis::alert_center::AlertDisposition;

pub struct AppView<'a> {
    app: &'a App,
    pub core: CoreReadGuard<'a>,
}

impl std::ops::Deref for AppView<'_> {
    type Target = App;
    fn deref(&self) -> &Self::Target {
        self.app
    }
}

impl App {
    pub fn review_selected_alert(&mut self, disposition: AlertDisposition) {
        let target = self.query_core(|core| core.alert_center.selected_item()
            .map(|alert| (alert.id, alert.capture_id.clone())));
        match target {
            Some(Some((id, capture_id))) => {
                let reviewed_unix_ms = crate::storage::alert_jsonl::unix_now_ms();
                self.update_core(&format!("Alert #{id} marked {disposition}"), move |core| {
                    if core.alert_center.set_disposition_at(id, capture_id.as_deref(), disposition, reviewed_unix_ms) {
                        Ok(())
                    } else {
                        Err(format!("Alert #{id} is no longer available; review state not changed"))
                    }
                });
            }
            Some(None) => self.set_status("No alert selected to review"),
            None => self.set_status("Analysis is busy; retry alert review"),
        }
    }

    pub fn configure_core(&mut self, apply: impl FnOnce(&mut AnalysisCore) + Send + 'static) {
        self.update_core("", move |core| {
            apply(core);
            Ok(())
        });
    }

    pub fn query_core<T>(&self, query: impl FnOnce(&AnalysisCore) -> T) -> Option<T> {
        if !self.analysis_generation_ready() {
            return None;
        }
        self.core.try_read().ok().flatten().map(|core| query(&core))
    }

    pub fn try_view(&self) -> Result<Option<AppView<'_>>, String> {
        if !self.analysis_generation_ready() {
            return Ok(None);
        }
        Ok(self
            .core
            .try_read()?
            .map(|core| AppView { app: self, core }))
    }

    pub fn replace_core(&mut self, mut core: AnalysisCore) {
        self.analysis_worker.take();
        self.pending_analysis.clear();
        self.pending_analysis_bytes = 0;
        self.pending_analysis_events.clear();
        self.packet_effects.clear();
        self.reset_inspection();
        core.alert_center.capture_id = self.capture_id.as_deref().map(str::to_owned);
        self.core = ReadCore::new(core);
    }
}

impl AppView<'_> {
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
            InvestigationItem::Stream(id) if self.core.streams.get(id).is_some() => InvestigationContext {
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
            InvestigationItem::Stream(id) => missing("Stream", id.clone()),
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
            InvestigationItem::Alert(id) => InvestigationContext {
                kind: "Alert",
                title: format!("Alert #{id}"),
                details: vec![("Status".into(), "Legacy pin has no unique capture identity".into())],
                available: false,
            },
            InvestigationItem::AlertRef { id, capture_id } => unique_alert(self.core.alert_center
                .items.iter().filter(|alert| alert.id == *id && alert.capture_id == *capture_id))
                .map(|alert| {
                    let (trigger_frame, trigger_flow) = self.alert_trigger_context(alert);
                    let (evidence, payload) = self.alert_evidence_context(alert);
                    InvestigationContext {
                        kind: "Alert",
                        title: alert.title.clone(),
                        details: vec![
                            ("Severity".into(), alert.severity.clone()),
                            ("Priority".into(), alert.priority.to_string()),
                            ("State".into(), alert.disposition.to_string()),
                            ("First recorded review".into(), alert.first_reviewed_unix_ms
                                .and_then(|timestamp| i64::try_from(timestamp).ok())
                                .and_then(chrono::DateTime::from_timestamp_millis)
                                .map_or_else(|| "Not recorded".into(), |time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())),
                            ("Source".into(), alert.source.clone()),
                            (
                                "Rule".into(),
                                alert.provenance.as_ref().map(|rule| rule.rule_label())
                                    .unwrap_or_else(|| "Not recorded".into()),
                            ),
                            (
                                "Evidence confidence".into(),
                                alert.provenance.as_ref().map(|rule| rule.confidence.to_string())
                                    .unwrap_or_else(|| "Not recorded".into()),
                            ),
                            ("Trigger frame".into(), trigger_frame),
                            ("Trigger flow".into(), trigger_flow),
                            (
                                "Capture ID".into(),
                                alert.capture_id.as_deref().unwrap_or("Unscoped").into(),
                            ),
                            ("Packet evidence".into(), evidence),
                            ("Cited payload".into(), payload.unwrap_or_else(|| "No verified TCP/UDP payload lengths".into())),
                            ("Reason".into(), alert.detail.clone()),
                            (
                                "Recommendation".into(),
                                alert
                                    .provenance
                                    .as_ref()
                                    .map(|rule| rule.verification_hint.clone())
                                    .or_else(|| alert.recommendation.clone())
                                    .unwrap_or_else(|| "manual review".into()),
                            ),
                        ],
                        available: true,
                    }
                })
                .unwrap_or_else(|| missing("Alert", format!("Alert #{id}"))),
            InvestigationItem::Object(id) => self
                .core
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
        self.core.streams.get(&key.id()).filter(|stream| self.investigation_stream_has_evidence(stream))
    }
}
