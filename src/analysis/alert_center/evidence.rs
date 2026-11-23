use super::{AUTOMATIC_EVIDENCE_PRIORITY, AlertDisposition, AlertItem};

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
