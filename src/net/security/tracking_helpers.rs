use super::*;
use std::{collections::VecDeque, ops::Range};

pub(super) struct TcpOverlap {
    pub(super) previous_frame: u64,
    pub(super) compared_bytes: usize,
    pub(super) difference_sequence: u32,
}

pub(super) fn conflicting_tcp_overlap(
    slices: &VecDeque<FragmentSlice>,
    payload_sequence: u32,
    payload: &[u8],
) -> Option<TcpOverlap> {
    slices.iter().find_map(|existing| {
        let (range, saved) = overlapping_tcp_bytes(existing, payload_sequence, payload.len())?;
        let compared_bytes = range.len();
        let new_offset = range.start;
        let difference = payload[range].iter()
            .zip(saved)
            .position(|(new, old)| new != old)?;
        Some(TcpOverlap {
            previous_frame: existing.packet_no,
            compared_bytes,
            difference_sequence: payload_sequence.wrapping_add((new_offset + difference) as u32),
        })
    })
}

fn overlapping_tcp_bytes(
    existing: &FragmentSlice,
    payload_sequence: u32,
    payload_len: usize,
) -> Option<(Range<usize>, &[u8])> {
    // Align the retained slice to the incoming sequence, including wrap through zero.
    let start = i64::from(existing.start.wrapping_sub(payload_sequence) as i32);
    let overlap_start = start.max(0);
    let overlap_end = (start + existing.data.len() as i64).min(payload_len as i64);
    if overlap_end <= overlap_start {
        return None;
    }
    let old_offset = (overlap_start - start) as usize;
    let count = (overlap_end - overlap_start) as usize;
    Some((overlap_start as usize..overlap_end as usize, &existing.data[old_offset..old_offset + count]))
}

pub(super) fn tcp_payload_already_seen(
    slices: &VecDeque<FragmentSlice>,
    payload_sequence: u32,
    payload: &[u8],
) -> bool {
    let mut matching = Vec::new();
    for existing in slices {
        if let Some((range, saved)) = overlapping_tcp_bytes(existing, payload_sequence, payload.len())
            && payload[range.clone()] == *saved
        {
            if range.len() == payload.len() {
                return true;
            }
            matching.push(range);
        }
    }
    matching.sort_unstable_by_key(|range| range.start);
    let mut covered = 0;
    for range in matching {
        if range.start > covered {
            break;
        }
        covered = covered.max(range.end);
        if covered == payload.len() {
            return true;
        }
    }
    false
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

pub(super) struct PeriodicTrafficEvidence {
    pub(super) duration: f64,
    pub(super) interval_mean: f64,
    pub(super) interval_min: f64,
    pub(super) interval_max: f64,
    pub(super) size_min: u32,
    pub(super) size_max: u32,
}

pub(super) fn beacon_pattern(samples: &[BeaconSample]) -> Option<PeriodicTrafficEvidence> {
    if samples.len() < BEACON_MIN_SAMPLES {
        return None;
    }
    let duration = samples[samples.len() - 1].timestamp - samples[0].timestamp;
    let count = (samples.len() - 1) as f64;
    let interval_mean = duration / count;
    if duration < 30.0 || interval_mean < 1.0 {
        return None;
    }
    let mut interval_min = f64::INFINITY;
    let mut interval_max = 0.0_f64;
    let interval_variance = samples
        .windows(2)
        .map(|pair| {
            let gap = pair[1].timestamp - pair[0].timestamp;
            interval_min = interval_min.min(gap);
            interval_max = interval_max.max(gap);
            (gap - interval_mean).powi(2)
        })
        .sum::<f64>()
        / count;
    let interval_cv = interval_variance.sqrt() / interval_mean;

    let mut size_min = u32::MAX;
    let mut size_max = 0;
    let size_mean = samples.iter().map(|sample| {
        size_min = size_min.min(sample.size);
        size_max = size_max.max(sample.size);
        f64::from(sample.size)
    }).sum::<f64>() / samples.len() as f64;
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
    (interval_cv <= 0.15 && size_cv <= 0.10).then_some(PeriodicTrafficEvidence {
        duration, interval_mean, interval_min, interval_max, size_min, size_max,
    })
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
