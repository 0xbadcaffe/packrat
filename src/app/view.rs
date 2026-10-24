use super::*;

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

    pub fn replace_core(&mut self, core: AnalysisCore) {
        self.analysis_worker.take();
        self.pending_analysis.clear();
        self.pending_analysis_bytes = 0;
        self.pending_analysis_events.clear();
        self.packet_effects.clear();
        self.reset_inspection();
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
        self.core.streams.get(&key.id())
    }
}
