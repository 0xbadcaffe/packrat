use super::*;

impl OperatorGraphEngine {
    /// Called per-packet to create/update host flow relationships.
    pub fn on_packet(
        &mut self,
        src: &str,
        dst: &str,
        proto: &str,
        _sport: Option<u16>,
        dport: Option<u16>,
        ts: Timestamp,
        bytes: u64,
        pkt_no: u64,
    ) {
        if src.is_empty() || dst.is_empty() || src == "0.0.0.0" || dst == "0.0.0.0" {
            return;
        }

        let src_id = self.ensure_node(
            format!("Host:{src}"),
            src.to_string(),
            ts,
            GraphNodeData::Host(HostNodeData {
                ips: vec![src.to_string()],
                ..Default::default()
            }),
        );
        let dst_id = self.ensure_node(
            format!("Host:{dst}"),
            dst.to_string(),
            ts,
            GraphNodeData::Host(HostNodeData {
                ips: vec![dst.to_string()],
                ..Default::default()
            }),
        );

        let pkt_ev = GraphEvidenceRef::Packet(PacketRef(pkt_no));
        self.add_node_evidence(src_id, pkt_ev.clone());
        self.add_node_evidence(dst_id, pkt_ev.clone());

        let eid = self.ensure_edge(
            src_id,
            dst_id,
            GraphEdgeKind::CommunicatesWith,
            ts,
            1.0,
            bytes,
        );
        if let Some(e) = self.edges.get_mut(&eid) {
            e.meta.protocol = Some(proto.to_string());
            e.meta.port = dport;
        }
        self.add_edge_evidence(eid, pkt_ev);

        // Service node for destination port
        if let Some(port) = dport {
            let svc_key = format!("Service:{dst}:{port}/{proto}");
            let svc_label = format!("{dst}:{port}/{proto}");
            let svc_id = self.ensure_node(
                svc_key,
                svc_label,
                ts,
                GraphNodeData::Service(ServiceNodeData {
                    protocol: proto.to_string(),
                    port,
                    host_ip: dst.to_string(),
                    role: known_service_role(port, proto),
                }),
            );
            self.ensure_edge(dst_id, svc_id, GraphEdgeKind::BelongsToHost, ts, 1.0, 0);
            self.ensure_edge(src_id, svc_id, GraphEdgeKind::UsesService, ts, 1.0, bytes);
        }

        self.total_events += 1;
    }

    // ─── Higher-level ingestion ───────────────────────────────────────────────

    pub fn on_credential(
        &mut self,
        username: Option<&str>,
        scheme: &str,
        cleartext: bool,
        src_ip: &str,
        dst_ip: &str,
        ts: Timestamp,
        pkt_no: u64,
    ) {
        if src_ip.is_empty() {
            return;
        }
        let uname = username.unwrap_or("unknown");
        let key = format!("Cred:{scheme}:{uname}:{dst_ip}");
        let label = format!("{scheme}://{uname}@{dst_ip}");
        let cred_id = self.ensure_node(
            key,
            label,
            ts,
            GraphNodeData::Credential(CredentialNodeData {
                cred_type: scheme.to_string(),
                username: username.map(str::to_string),
                pw_preview: "***".into(),
                scheme: scheme.to_string(),
                cleartext,
                confidence: if cleartext { 0.95 } else { 0.7 },
            }),
        );

        let src_id = self.ensure_node(
            format!("Host:{src_ip}"),
            src_ip.to_string(),
            ts,
            GraphNodeData::Host(HostNodeData {
                ips: vec![src_ip.to_string()],
                ..Default::default()
            }),
        );
        let dst_id = self.ensure_node(
            format!("Host:{dst_ip}"),
            dst_ip.to_string(),
            ts,
            GraphNodeData::Host(HostNodeData {
                ips: vec![dst_ip.to_string()],
                ..Default::default()
            }),
        );
        self.ensure_edge(
            src_id,
            cred_id,
            GraphEdgeKind::AuthenticatedWith,
            ts,
            0.9,
            0,
        );
        self.ensure_edge(
            cred_id,
            dst_id,
            GraphEdgeKind::AuthenticatedWith,
            ts,
            0.9,
            0,
        );
        self.add_node_evidence(cred_id, GraphEvidenceRef::Packet(PacketRef(pkt_no)));

        // High-risk tag for cleartext
        if cleartext {
            self.tag_node(cred_id, "cleartext-credential");
        }
    }

    pub fn on_tls_session(
        &mut self,
        flow_id: &str,
        sni: Option<&str>,
        fingerprint: &str,
        ts: Timestamp,
    ) {
        if fingerprint.is_empty() {
            return;
        }
        // Certificate node
        let cert_key = format!("Cert:{fingerprint}");
        let cert_label = sni
            .map(|s| format!("cert:{s}"))
            .unwrap_or_else(|| format!("cert:{}", &fingerprint[..8.min(fingerprint.len())]));
        let cert_id = self.ensure_node(
            cert_key,
            cert_label,
            ts,
            GraphNodeData::Certificate(CertificateNodeData {
                fingerprint: fingerprint.to_string(),
                subject: sni.unwrap_or("unknown").to_string(),
                ..Default::default()
            }),
        );

        // SNI identity node
        if let Some(name) = sni {
            let ident_key = format!("Identity:tls-sni:{name}");
            let ident_id = self.ensure_node(
                ident_key,
                name.to_string(),
                ts,
                GraphNodeData::Identity(IdentityNodeData {
                    name: name.to_string(),
                    kind: "tls-sni".into(),
                    resolved_ip: None,
                }),
            );
            self.ensure_edge(cert_id, ident_id, GraphEdgeKind::ResolvesTo, ts, 0.9, 0);
        }

        // Link flow nodes to certificate
        let flow_key = format!("Flow:{flow_id}");
        if let Some(&flow_node_id) = self.key_index.get(&flow_key) {
            self.ensure_edge(
                flow_node_id,
                cert_id,
                GraphEdgeKind::PresentsCertificate,
                ts,
                1.0,
                0,
            );
        }
    }

    pub fn on_ids_alert(
        &mut self,
        signature: &str,
        severity: &str,
        src_ip: &str,
        dst_ip: &str,
        pkt_no: u64,
        ts: Timestamp,
    ) {
        let key = format!("Alert:{signature}:{pkt_no}");
        let label = format!("[{severity}] {signature}");
        let alert_id = self.ensure_node(
            key,
            label,
            ts,
            GraphNodeData::Alert(AlertNodeData {
                signature: signature.to_string(),
                severity: severity.to_string(),
                detail: format!("{src_ip} → {dst_ip}"),
                pkt_no,
            }),
        );
        self.add_node_evidence(alert_id, GraphEvidenceRef::Alert(pkt_no));

        for ip in [src_ip, dst_ip].iter().filter(|ip| !ip.is_empty()) {
            let host_id = self.ensure_node(
                format!("Host:{ip}"),
                ip.to_string(),
                ts,
                GraphNodeData::Host(HostNodeData {
                    ips: vec![ip.to_string()],
                    ..Default::default()
                }),
            );
            self.ensure_edge(host_id, alert_id, GraphEdgeKind::TriggersAlert, ts, 0.95, 0);
            self.tag_node(host_id, format!("alert:{}", severity.to_lowercase()));
        }
    }

    pub fn on_ioc_hit(
        &mut self,
        value: &str,
        kind: &str,
        context: &str,
        pkt_no: u64,
        ts: Timestamp,
        src_ip: &str,
    ) {
        let key = format!("IOC:{kind}:{value}");
        let label = format!("[{kind}] {value}");
        let ioc_id = self.ensure_node(
            key,
            label,
            ts,
            GraphNodeData::IOC(IocNodeData {
                ioc_kind: kind.to_string(),
                value: value.to_string(),
                description: context.to_string(),
                source: "ioc-engine".into(),
            }),
        );
        self.add_node_evidence(ioc_id, GraphEvidenceRef::IocHit(pkt_no));
        self.tag_node(ioc_id, "ioc-match");

        if !src_ip.is_empty() {
            let host_id = self.ensure_node(
                format!("Host:{src_ip}"),
                src_ip.to_string(),
                ts,
                GraphNodeData::Host(HostNodeData {
                    ips: vec![src_ip.to_string()],
                    ..Default::default()
                }),
            );
            self.ensure_edge(host_id, ioc_id, GraphEdgeKind::MatchesIoc, ts, 0.95, 0);
            self.tag_node(host_id, "ioc-associated");
        }
    }

    pub fn on_rule_hit(
        &mut self,
        rule_id: &str,
        rule_name: &str,
        action: &str,
        pkt_no: u64,
        ts: Timestamp,
    ) {
        let key = format!("RuleHit:{rule_id}:{pkt_no}");
        let label = format!("Rule: {rule_name}");
        let hit_id = self.ensure_node(
            key,
            label,
            ts,
            GraphNodeData::RuleHit(RuleHitNodeData {
                rule_id: rule_id.to_string(),
                rule_name: rule_name.to_string(),
                pkt_no,
                action: action.to_string(),
            }),
        );
        self.add_node_evidence(hit_id, GraphEvidenceRef::RuleHit(pkt_no));
    }

    pub fn on_carved_object(
        &mut self,
        obj_id: u64,
        mime: &str,
        sha256: &str,
        source: &str,
        size: usize,
        ts: Timestamp,
    ) {
        let key = format!(
            "File:{}",
            if sha256.is_empty() {
                format!("id:{obj_id}")
            } else {
                sha256.to_string()
            }
        );
        let label = format!("{} ({})", mime, human_size(size));
        let file_id = self.ensure_node(
            key,
            label,
            ts,
            GraphNodeData::FileObject(FileObjectNodeData {
                filename: format!("object_{obj_id}"),
                mime: mime.to_string(),
                sha256: sha256.to_string(),
                size,
                source: source.to_string(),
                yara_hits: Vec::new(),
            }),
        );
        self.add_node_evidence(
            file_id,
            GraphEvidenceRef::Object(crate::model::evidence::ObjectRef(obj_id)),
        );
        self.tag_node(file_id, "carved");

        // Link to source flow if we can identify it
        let flow_key = format!("Flow:{source}");
        if let Some(&flow_id) = self.key_index.get(&flow_key) {
            self.ensure_edge(file_id, flow_id, GraphEdgeKind::ExtractedFrom, ts, 0.85, 0);
        }
    }

    // ─── Lazy intelligence ────────────────────────────────────────────────────
}
