use super::*;

pub(super) fn has_conflicting_tcp_overlap(
    slices: &[FragmentSlice],
    segment: &TcpSegment<'_>,
) -> bool {
    let new_start = segment.sequence;
    let new_end = new_start.saturating_add(segment.payload.len() as u32);
    slices.iter().any(|existing| {
        let existing_end = existing.start.saturating_add(existing.data.len() as u32);
        let overlap_start = new_start.max(existing.start);
        let overlap_end = new_end.min(existing_end);
        if overlap_start >= overlap_end {
            return false;
        }
        let new_offset = (overlap_start - new_start) as usize;
        let existing_offset = (overlap_start - existing.start) as usize;
        let overlap_len = (overlap_end - overlap_start) as usize;
        segment.payload[new_offset..new_offset + overlap_len]
            != existing.data[existing_offset..existing_offset + overlap_len]
    })
}

pub(super) fn evict_oldest_scan_source(states: &mut HashMap<ScanSourceKey, SourceScanState>) {
    if states.len() < MAX_SCAN_STATES {
        return;
    }
    if let Some(oldest) = states
        .iter()
        .min_by(|left, right| {
            left.1.last_seen.total_cmp(&right.1.last_seen).then(left.0.cmp(right.0))
        })
        .map(|(key, _)| key.clone())
    {
        states.remove(&oldest);
    }
}

pub(super) fn evict_oldest_syn_target(states: &mut HashMap<SynTargetKey, SynFloodState>) {
    if states.len() < MAX_SCAN_STATES {
        return;
    }
    if let Some(oldest) = states
        .iter()
        .min_by(|left, right| {
            left.1.last_seen.total_cmp(&right.1.last_seen).then(left.0.cmp(right.0))
        })
        .map(|(key, _)| key.clone())
    {
        states.remove(&oldest);
    }
}

pub(super) fn evict_oldest_beacon(states: &mut HashMap<BehaviorFlowKey, BeaconState>) {
    if states.len() < MAX_SCAN_STATES {
        return;
    }
    if let Some(oldest) = states
        .iter()
        .min_by(|left, right| {
            left.1.last_seen.total_cmp(&right.1.last_seen).then(left.0.cmp(right.0))
        })
        .map(|(key, _)| key.clone())
    {
        states.remove(&oldest);
    }
}

pub(super) fn evict_oldest_exfil(states: &mut HashMap<ExfilKey, ExfilState>) {
    if states.len() < MAX_SCAN_STATES {
        return;
    }
    if let Some(oldest) = states
        .iter()
        .min_by(|left, right| left.1.last_seen.total_cmp(&right.1.last_seen))
        .map(|(key, _)| key.clone())
    {
        states.remove(&oldest);
    }
}

pub(super) fn beacon_pattern(samples: &[BeaconSample]) -> bool {
    if samples.len() < BEACON_MIN_SAMPLES {
        return false;
    }
    let duration = samples[samples.len() - 1].timestamp - samples[0].timestamp;
    let count = (samples.len() - 1) as f64;
    let interval_mean = duration / count;
    if duration < 30.0 || interval_mean < 1.0 {
        return false;
    }
    let interval_variance = samples
        .windows(2)
        .map(|pair| (pair[1].timestamp - pair[0].timestamp - interval_mean).powi(2))
        .sum::<f64>()
        / count;
    let interval_cv = interval_variance.sqrt() / interval_mean;

    let size_mean = samples.iter().map(|sample| f64::from(sample.size)).sum::<f64>()
        / samples.len() as f64;
    let size_variance = samples
        .iter()
        .map(|sample| (f64::from(sample.size) - size_mean).powi(2))
        .sum::<f64>()
        / samples.len() as f64;
    let size_cv = if size_mean > 0.0 {
        size_variance.sqrt() / size_mean
    } else {
        1.0
    };
    interval_cv <= 0.15 && size_cv <= 0.10
}

pub(super) fn is_internal_address(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unicast_link_local() || ip.segments()[0] & 0xfe00 == 0xfc00
        }
        Err(_) => false,
    }
}

pub(super) fn record_timed_target(
    state: &mut TimedTargetState,
    timestamp: f64,
    target: &str,
    window: f64,
) {
    state
        .targets
        .retain(|(seen, _)| timestamp < *seen || timestamp - *seen <= window);
    if state.targets.is_empty() {
        state.alerted = false;
    }
    state.targets.push((timestamp, target.to_string()));
    if state.targets.len() > 256 {
        state.targets.remove(0);
    }
}

pub(super) fn unique_timed_targets(state: &TimedTargetState) -> usize {
    state
        .targets
        .iter()
        .map(|(_, target)| target.as_str())
        .collect::<HashSet<_>>()
        .len()
}
