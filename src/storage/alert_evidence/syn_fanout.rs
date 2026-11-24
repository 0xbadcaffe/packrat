use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{FlowCounts, FlowKey};

#[derive(Serialize)]
pub(super) struct CitedSynFanout {
    source_hosts: usize,
    destination_hosts: usize,
    destination_ports: usize,
    capture_paths: usize,
}

pub(super) fn summarize(flows: &BTreeMap<FlowKey, FlowCounts>) -> Option<CitedSynFanout> {
    let mut sources = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (flow, counts) in flows {
        if counts.initial_syn_frames == 0 {
            continue;
        }
        sources.insert(flow.source.ip());
        destinations.insert(flow.destination.ip());
        ports.insert(flow.destination.port());
        paths.insert((flow.section_id, flow.interface_id, &flow.vlan_stack));
    }
    (!sources.is_empty()).then_some(CitedSynFanout {
        source_hosts: sources.len(),
        destination_hosts: destinations.len(),
        destination_ports: ports.len(),
        capture_paths: paths.len(),
    })
}
