use super::*;

// ─── Assembler ────────────────────────────────────────────────────────────────

const MAX_STREAMS: usize = 500;
const MAX_SEGMENT_METADATA: usize = 8192;

#[derive(Debug, Default)]
pub struct StreamAssembler {
    streams: HashMap<String, ReassembledStream>,
    revision: u64,
    evicted_streams: u64,
}

impl StreamAssembler {
    pub fn ingest(&mut self, pkt: &Packet) {
        self.ingest_inner(pkt, false);
    }

    pub(crate) fn ingest_observing_tls(&mut self, pkt: &Packet) -> Option<((u16, u16), Vec<u64>)> {
        self.ingest_inner(pkt, true)
    }

    fn ingest_inner(&mut self, pkt: &Packet, observe_tls: bool) -> Option<((u16, u16), Vec<u64>)> {
        let key = StreamKey::from_packet(pkt)?;
        let raw = &pkt.bytes;
        let view = tcp_view(pkt)?;
        let tcp_header = raw.get(view.header..view.payload)?;
        let id = key.id();

        // Evict oldest stream if at cap
        if !self.streams.contains_key(&id) && self.streams.len() >= MAX_STREAMS {
            if let Some(oldest_id) = self
                .streams
                .iter()
                .min_by(|a, b| a.1.last_seen.total_cmp(&b.1.last_seen))
                .map(|(k, _)| k.clone())
            {
                self.streams.remove(&oldest_id);
                self.evicted_streams += 1;
            }
        }

        self.revision = self.revision.wrapping_add(1);
        let stream = self
            .streams
            .entry(id)
            .or_insert_with(|| ReassembledStream::new(key.clone(), pkt.timestamp));
        stream.revision = self.revision;
        stream.last_seen = pkt.timestamp.max(stream.last_seen);
        stream.truncated |= view.truncated;

        // Determine direction: is pkt.src the A-side?
        let sport = pkt.src_port.unwrap_or(0);
        let ep_a_ip_port = format!("{}:{}", pkt.src, sport);
        let from_client = ep_a_ip_port == stream.key.ep_a;

        // Read TCP flags and sequence number from raw bytes
        let tcp_flags = tcp_header[13];
        let is_syn = tcp_flags & 0x02 != 0;
        let is_fin = tcp_flags & 0x01 != 0;
        let is_rst = tcp_flags & 0x04 != 0;

        let tcp_seq: u32 =
            u32::from_be_bytes([tcp_header[4], tcp_header[5], tcp_header[6], tcp_header[7]]);

        // Extract payload using the correctly computed offset
        let payload = &raw[view.payload..view.end];

        let initial_syn = if from_client {
            &mut stream.client_initial_syn
        } else {
            &mut stream.server_initial_syn
        };
        if is_syn {
            let data_exists = if from_client {
                !stream.client_data.is_empty()
            } else {
                !stream.server_data.is_empty()
            };
            if initial_syn.is_some_and(|initial| initial != tcp_seq)
                || (initial_syn.is_none() && data_exists)
            {
                stream.epoch_ambiguous = true;
            }
            initial_syn.get_or_insert(tcp_seq);
        }
        if stream.epoch_ambiguous || stream.reset {
            return None;
        }

        if is_rst {
            stream.closed = true;
            stream.reset = true;
            return None;
        }
        if (from_client && stream.client_finished) || (!from_client && stream.server_finished) {
            return None;
        }

        // ── Sequence-number–aware assembly ─────────────────────────────────
        // We track the next expected sequence number per direction to:
        //   a) detect and skip retransmitted bytes
        //   b) retain gaps until missing segments arrive
        //   c) consume FIN only after all preceding payload bytes

        let (data, next_seq_slot) = if from_client {
            (&mut stream.client_data, &mut stream.client_next_seq)
        } else {
            (&mut stream.server_data, &mut stream.server_next_seq)
        };

        let pending = if from_client {
            &mut stream.client_pending
        } else {
            &mut stream.server_pending
        };
        let payload_sequence = tcp_seq.wrapping_add(u32::from(is_syn));
        if next_seq_slot.is_none() {
            stream.midstream |= !is_syn;
            *next_seq_slot = Some(payload_sequence);
        }

        if from_client {
            stream.client_pkts += 1;
        } else {
            stream.server_pkts += 1;
        }

        if is_syn && payload.is_empty() {
            if is_fin {
                *next_seq_slot = next_seq_slot.map(|sequence| sequence.wrapping_add(1));
                stream.closed = true;
                if from_client {
                    stream.client_finished = true;
                    stream.client_fin_packet = Some(pkt.no);
                } else {
                    stream.server_finished = true;
                    stream.server_fin_packet = Some(pkt.no);
                }
            }
            return None;
        }
        if payload.is_empty() && !is_fin {
            return None;
        }

        let segment = PendingTcpSegment {
            sequence: payload_sequence,
            payload: payload.to_vec(),
            fin: is_fin,
            timestamp: pkt.timestamp,
            packet_no: pkt.no,
        };
        if sequence_delta(segment.sequence, next_seq_slot.unwrap_or(segment.sequence)) > 0 {
            if !buffer_pending(pending, segment) {
                stream.dropped_segments += 1;
            }
            return None;
        }

        let direction = usize::from(from_client);
        let checked = &mut stream.tls_prefix_checked[direction];
        let track_tls_prefix = observe_tls && !*checked && data.first().is_none_or(|&kind| kind == 0x16);
        let track_dns = observe_tls && stream.dns_offsets[direction].is_some()
            && (sport == 53 || pkt.dst_port == Some(53));
        // An uppercase prefix can be cleartext HTTP; avoid scanning encrypted HTTPS overlaps.
        let track_http = !stream.http_overlap_conflict
            && (matches!(sport, 80 | 443 | 8080) || matches!(pkt.dst_port, Some(80 | 443 | 8080)))
            && data.first().or_else(|| payload.first()).is_some_and(u8::is_ascii_uppercase);
        let check_limit = if track_dns || track_http { usize::MAX } else if track_tls_prefix { MAX_TLS_RECORD_BYTES } else { 0 };
        let progress = consume_contiguous(data, next_seq_slot, pending, segment, check_limit);
        *checked |= progress.prefix_conflict;
        stream.http_overlap_conflict |= track_http && progress.prefix_conflict;
        if track_dns && progress.prefix_conflict {
            stream.dns_offsets[direction] = None;
        }
        stream.truncated |= progress.discarded_bytes > 0;
        let added_bytes = !progress.segments.is_empty();
        for emitted in progress.segments {
            if stream.segments.len() >= MAX_SEGMENT_METADATA {
                stream.provenance_truncated = true;
                continue;
            }
            stream.segments.push(StreamSegment {
                from_client,
                offset: emitted.offset,
                length: emitted.length,
                timestamp: emitted.timestamp,
                packet_no: emitted.packet_no,
            });
        }
        if progress.fin_consumed {
            stream.closed = true;
            if from_client {
                stream.client_finished = true;
                stream.client_fin_packet = progress.fin_packet_no;
            } else {
                stream.server_finished = true;
                stream.server_fin_packet = progress.fin_packet_no;
            }
        }
        if observe_tls && added_bytes {
            observe_segmented_tls(stream, from_client, pkt.no)
        } else {
            None
        }
    }

    pub fn get(&self, id: &str) -> Option<&ReassembledStream> {
        self.streams.get(id)
    }

    pub(crate) fn observe_tcp_dns(&mut self, pkt: &Packet) -> DnsTcpObservation {
        if pkt.src_port != Some(53) && pkt.dst_port != Some(53) {
            return DnsTcpObservation::Unanchored;
        }
        let Some((source, destination)) = tcp_port_pair(pkt) else {
            return DnsTcpObservation::Unanchored;
        };
        if (source != 53 && destination != 53)
            || (pkt.src_port, pkt.dst_port) != (Some(source), Some(destination))
        {
            return DnsTcpObservation::Unanchored;
        }
        let Some(stream) = StreamKey::from_packet(pkt).and_then(|key| self.streams.get_mut(&key.id())) else {
            return DnsTcpObservation::Unanchored;
        };
        let from_a = format!("{}:{source}", pkt.src) == stream.key.ep_a;
        dns::observe(stream, from_a, source, destination)
    }

    pub(crate) fn http_auth_candidate(&mut self, pkt: &Packet) -> Option<(String, bool, usize, u32)> {
        let source @ (80 | 443 | 8080) = pkt.src_port? else { return None };
        let destination = pkt.dst_port?;
        let (_, payload) = tcp_payload_with_ack(pkt, (source, destination))?;
        if payload.is_empty() {
            return None;
        }
        let id = StreamKey::from_packet(pkt)?.id();
        let stream = self.streams.get_mut(&id)?;
        let from_a = format!("{}:{source}", pkt.src) == stream.key.ep_a;
        let (syn, data) = if from_a {
            (stream.client_initial_syn, &stream.client_data)
        } else {
            (stream.server_initial_syn, &stream.server_data)
        };
        let initial = syn?.wrapping_add(1);
        let previous = std::mem::replace(&mut stream.http_auth_examined[usize::from(from_a)], data.len());
        if stream.midstream || stream.reset || stream.has_gaps() || stream.provenance_truncated || stream.http_overlap_conflict
            || data.len() <= previous || !data.starts_with(b"HTTP/1.")
            || !data[previous.saturating_sub(3)..].windows(4).any(|bytes| bytes == b"\r\n\r\n")
            || !data[previous.saturating_sub(16_384)..].windows(12)
                .any(|bytes| matches!(bytes, b"HTTP/1.1 401" | b"HTTP/1.0 401"))
        {
            return None;
        }
        Some((id, from_a, previous, initial))
    }

    pub(crate) fn observe_modbus(
        &mut self, pkt: &Packet,
    ) -> crate::analysis::industrial_policy::ModbusObservation {
        use crate::analysis::industrial_policy::{ModbusObservation::*, modbus_message};
        if pkt.dst_port != Some(502) {
            return Unanchored;
        }
        let Some((source_port, destination_port)) = tcp_port_pair(pkt) else {
            return Unanchored;
        };
        if destination_port != 502 || source_port == 502 || pkt.src_port != Some(source_port) {
            return Unanchored;
        }
        let Some(stream) = StreamKey::from_packet(pkt).and_then(|key| self.streams.get_mut(&key.id())) else {
            return Unanchored;
        };
        let from_a = format!("{}:{source_port}", pkt.src) == stream.key.ep_a;
        let (syn, data) = if from_a {
            (stream.client_initial_syn, &stream.client_data)
        } else {
            (stream.server_initial_syn, &stream.server_data)
        };
        if syn.is_none() || stream.midstream {
            return Unanchored;
        }
        if stream.epoch_ambiguous || stream.reset || stream.truncated
            || stream.dropped_segments > 0 || stream.provenance_truncated
        {
            return Anchored(None);
        }
        let mut result = None;
        while let Some(start) = stream.modbus_offset {
            let Some(remaining) = data.get(start..) else { break; };
            match modbus_message(remaining) {
                Ok(Some((length, finding))) => {
                    let end = start + length;
                    stream.modbus_offset = Some(end);
                    if let Some(finding) = finding.filter(|_| result.is_none()) {
                        let frames = stream.packet_numbers(from_a, start, end);
                        if !frames.is_empty() {
                            result = Some((finding, frames));
                        }
                    }
                }
                Ok(None) => break,
                Err(()) => stream.modbus_offset = None,
            }
        }
        Anchored(result)
    }

    pub fn all(&self) -> Vec<&ReassembledStream> {
        let mut v: Vec<_> = self.streams.values().collect();
        v.sort_by(|a, b| b.last_seen.total_cmp(&a.last_seen));
        v
    }

    pub fn len(&self) -> usize {
        self.streams.len()
    }
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub fn evicted_streams(&self) -> u64 {
        self.evicted_streams
    }

    pub fn clear(&mut self) {
        self.streams.clear();
        self.evicted_streams = 0;
    }
}

fn observe_segmented_tls(
    stream: &mut ReassembledStream, from_a: bool, frame: u64,
) -> Option<((u16, u16), Vec<u64>)> {
    if stream.midstream || stream.truncated || stream.dropped_segments > 0 || stream.provenance_truncated {
        return None;
    }
    let checked = &mut stream.tls_prefix_checked[usize::from(from_a)];
    if *checked {
        return None;
    }
    let data = if from_a {
        stream.client_initial_syn?;
        &stream.client_data
    } else {
        stream.server_initial_syn?;
        &stream.server_data
    };
    if data.first() != Some(&0x16) {
        *checked = true;
        return None;
    }
    let length = 5 + usize::from(u16::from_be_bytes(data.get(3..5)?.try_into().ok()?));
    if length > MAX_TLS_RECORD_BYTES {
        *checked = true;
        return None;
    }
    let record = data.get(..length)?;
    *checked = true;
    let selection = crate::analysis::encrypted_insight::parse_anchored_server_hello(record)?;
    let frames = stream.packet_numbers(from_a, 0, length);
    (2..=crate::analysis::alert_center::MAX_ALERT_PACKET_REFS).contains(&frames.len()).then_some(())?;
    frames.contains(&frame).then_some((selection, frames))
}
