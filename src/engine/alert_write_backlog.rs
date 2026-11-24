use std::collections::BTreeMap;

use crate::analysis::alert_center::AlertItem;

const MAX_SNAPSHOTS: usize = 1_024;
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct AlertWriteBacklog {
    snapshots: BTreeMap<(u64, Option<String>), (usize, AlertItem)>,
    bytes: usize,
    pub(crate) dropped: u64,
}

impl AlertWriteBacklog {
    pub(crate) fn extend(&mut self, alerts: Vec<AlertItem>) {
        for alert in alerts {
            let bytes = allocation_cost(&alert);
            if bytes > MAX_BYTES {
                self.dropped = self.dropped.saturating_add(1);
                continue;
            }
            let key = (alert.id, alert.capture_id.clone());
            if let Some((previous, _)) = self.snapshots.insert(key, (bytes, alert)) {
                self.bytes -= previous;
            }
            self.bytes += bytes;
            while self.bytes > MAX_BYTES || self.snapshots.len() > MAX_SNAPSHOTS {
                let Some((_, (removed, _))) = self.snapshots.pop_first() else { break };
                self.bytes -= removed;
                self.dropped = self.dropped.saturating_add(1);
            }
        }
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &AlertItem> {
        self.snapshots.values().map(|(_, alert)| alert)
    }

    pub(crate) fn clear(&mut self) {
        self.snapshots.clear();
        self.bytes = 0;
    }
}

fn allocation_cost(alert: &AlertItem) -> usize {
    let base = std::mem::size_of::<((u64, Option<String>), (usize, AlertItem))>();
    let lengths = [
        alert.source.capacity(), alert.severity.capacity(), alert.title.capacity(),
        alert.detail.capacity(), alert.correlation_key.capacity(),
        alert.packet_refs.capacity().saturating_mul(std::mem::size_of::<u64>()),
        alert.recommendation.as_ref().map_or(0, String::capacity),
        alert.capture_id.as_ref().map_or(0, |id| id.capacity().saturating_add(id.len())),
        alert.provenance.as_ref().map_or(0, |rule| {
            rule.rule_id.capacity().saturating_add(rule.verification_hint.capacity())
        }),
    ];
    lengths.into_iter().fold(base, usize::saturating_add)
}

#[cfg(test)]
#[path = "../../tests/unit/alert_write_backlog_tests.rs"]
mod tests;
