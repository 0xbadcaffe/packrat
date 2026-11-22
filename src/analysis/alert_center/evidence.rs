use super::{AUTOMATIC_EVIDENCE_PRIORITY, AlertItem};

impl AlertItem {
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
