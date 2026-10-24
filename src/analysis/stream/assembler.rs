use super::*;

// ─── Assembler ────────────────────────────────────────────────────────────────

const MAX_STREAMS: usize = 500;
const MAX_SEGMENT_METADATA: usize = 8192;

#[derive(Debug, Default)]
pub struct StreamAssembler {
    streams: HashMap<String, ReassembledStream>,
}

impl StreamAssembler {
    pub fn ingest(&mut self, pkt: &Packet) {
        let key = match StreamKey::from_packet(pkt) {
            Some(k) => k,
            None => return,
        };
        let raw = &pkt.bytes;
        let Some(view) = tcp_view(pkt) else {
            return;
        };
        let Some(tcp_header) = raw.get(view.header..view.payload) else {
            return;
        };
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
            }
        }

        let stream = self
            .streams
            .entry(id)
            .or_insert_with(|| ReassembledStream::new(key.clone(), pkt.timestamp));
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
            return;
        }

        if is_rst {
            stream.closed = true;
            stream.reset = true;
            return;
        }
        if (from_client && stream.client_finished) || (!from_client && stream.server_finished) {
            return;
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
            return;
        }
        if payload.is_empty() && !is_fin {
            return;
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
            return;
        }

        let progress = consume_contiguous(data, next_seq_slot, pending, segment);
        stream.truncated |= progress.discarded_bytes > 0;
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
    }

    pub fn get(&self, id: &str) -> Option<&ReassembledStream> {
        self.streams.get(id)
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

    pub fn clear(&mut self) {
        self.streams.clear();
    }
}
