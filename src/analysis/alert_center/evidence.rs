use super::{
    AUTOMATIC_EVIDENCE_PRIORITY, AlertCenter, AlertDisposition, AlertFlow, AlertItem, AlertTransport,
    AutomationMode, retain_packet_ref,
};

impl AlertFlow {
    pub(crate) fn from_captured_header(wire: &crate::analysis::packet_fields::CapturedTransportHeader) -> Option<Self> {
        let transport = match wire.protocol {
            6 => AlertTransport::Tcp,
            17 => AlertTransport::Udp,
            _ => return None,
        };
        (wire.source.port() != 0 && wire.destination.port() != 0 && wire.source != wire.destination)
            .then_some(Self { transport, source: wire.source, destination: wire.destination })
    }
}

impl AlertCenter {
    pub(crate) fn attach_ids_evidence(
        &mut self, signature: &str, opening_frame: u64, probe_frame: u64, evidence_frame: u64,
    ) {
        let Some(item) = self.items.iter_mut().find(|item| {
            item.capture_id == self.capture_id && item.source == "IDS" && item.title == signature
                && item.first_packet == opening_frame && item.packet_refs.contains(&probe_frame)
        }) else { return };
        if !retain_packet_ref(item, evidence_frame) { return; }
        if item.queue_evidence(self.automation_mode != AutomationMode::Off, self.archive_evidence_rules.as_deref())
            && !self.pending_pins.contains(&item.id)
        {
            self.pending_pins.push(item.id);
        }
        self.pending_exports.push(item.clone());
    }

    pub fn set_disposition(&mut self, id: u64, capture_id: Option<&str>, disposition: AlertDisposition) -> bool {
        self.set_disposition_at(id, capture_id, disposition, None)
    }

    pub(crate) fn set_disposition_at(
        &mut self, id: u64, capture_id: Option<&str>, disposition: AlertDisposition, reviewed_unix_ms: Option<u64>,
    ) -> bool {
        let Some(item) = self.items.iter_mut().find(|item| {
            item.id == id && item.capture_id.as_deref() == capture_id
        }) else {
            return false;
        };
        if item.disposition != disposition {
            item.disposition = disposition;
            item.reviewed_priority = disposition.is_resolved().then_some(item.priority);
            if disposition != AlertDisposition::New && item.first_reviewed_unix_ms.is_none() {
                item.first_reviewed_unix_ms = reviewed_unix_ms.filter(|&timestamp| timestamp != 0);
            }
            self.pending_exports.push(item.clone());
        }
        true
    }
}

impl AlertDisposition {
    pub(super) fn is_resolved(self) -> bool {
        matches!(self, Self::Benign | Self::Contained | Self::Closed)
    }
}

impl AlertItem {
    pub(super) fn reopen_for_escalation(&mut self, priority: u8, evidence_changed: bool) {
        if !self.disposition.is_resolved() { return; }
        let reviewed = *self.reviewed_priority.get_or_insert(self.priority);
        if evidence_changed && priority >= AUTOMATIC_EVIDENCE_PRIORITY && priority > reviewed {
            self.disposition = AlertDisposition::New;
            self.reviewed_priority = None;
        }
    }

    pub(crate) fn is_priority_evidence(&self) -> bool {
        self.priority >= AUTOMATIC_EVIDENCE_PRIORITY
    }

    pub(super) fn queue_evidence(&self, auto_pin: bool, archive_rules: Option<&[String]>) -> bool {
        (self.is_priority_evidence() && (auto_pin || archive_rules.is_some()))
            || archive_rules
                .zip(self.provenance.as_ref())
                .is_some_and(|(rules, rule)| rules.contains(&rule.rule_id))
    }

    pub(crate) fn evidence_frame_numbers(&self) -> Vec<u64> {
        let mut frames = Vec::with_capacity(self.packet_refs.len() + 3);
        frames.extend([self.first_packet, self.packet_no, self.last_packet]);
        frames.extend(self.packet_refs.iter().copied());
        frames.retain(|&number| number > 0);
        frames.sort_unstable();
        frames.dedup();
        frames
    }
}
