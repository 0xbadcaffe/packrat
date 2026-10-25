use super::*;

#[derive(Default)]
pub(super) struct Connection {
    pub streams: BTreeMap<u64, BTreeMap<Http3Sender, HalfStream>>,
    pub limited: bool,
    pub revision: u64,
}

pub(super) struct Frame {
    pub event: Http3EventKind,
    pub length: u64,
    pub packets: Vec<u64>,
}

#[derive(Default)]
pub(super) struct HalfStream {
    pub frames: BTreeMap<u64, Frame>,
    pub final_size: Option<u64>,
    pub final_packets: Vec<u64>,
    pub reset_code: Option<u64>,
    pub ambiguous: bool,
    pub limited: bool,
}

impl HalfStream {
    pub fn ingest(&mut self, event: Http3EventKind, packet_no: u64) -> Result<bool, String> {
        let (offset, length) = if let Some(range) = event.range() {
            range
        } else {
            match &event {
                Http3EventKind::Finished { final_size }
                | Http3EventKind::Reset { final_size, .. } => {
                    self.ambiguous |= self.final_size.is_some_and(|prior| prior != *final_size)
                        || self
                            .frames
                            .iter()
                            .any(|(offset, frame)| offset + frame.length > *final_size);
                    let new = self.final_size.is_none();
                    self.final_size.get_or_insert(*final_size);
                    if let Http3EventKind::Reset { error_code, .. } = &event {
                        self.ambiguous |= self.reset_code.is_some_and(|prior| prior != *error_code);
                        self.reset_code = Some(*error_code);
                    }
                    retain_packet(&mut self.final_packets, packet_no, &mut self.limited);
                    return Ok(new);
                }
                _ => return Err("HTTP/3 event has no retained range".into()),
            }
        };
        if self.final_size.is_some_and(|size| offset + length > size) {
            self.ambiguous = true;
        }
        if let Some(prior) = self.frames.get_mut(&offset) {
            if prior.event != event {
                self.ambiguous = true;
            }
            retain_packet(&mut prior.packets, packet_no, &mut self.limited);
            return Ok(false);
        }
        if self.frames.len() >= 1024 {
            self.limited = true;
            return Err("HTTP/3 frames per stream direction exceeded".into());
        }
        if self
            .frames
            .range(..offset)
            .next_back()
            .is_some_and(|(start, frame)| *start + frame.length > offset)
            || self
                .frames
                .range(offset..)
                .next()
                .is_some_and(|(start, _)| *start < offset + length)
        {
            self.ambiguous = true;
            return Ok(false);
        }
        self.frames.insert(
            offset,
            Frame {
                event,
                length,
                packets: vec![packet_no],
            },
        );
        Ok(true)
    }
}

fn retain_packet(packets: &mut Vec<u64>, number: u64, limited: &mut bool) {
    if packets.contains(&number) {
        return;
    }
    if packets.len() < 32 {
        packets.push(number);
    } else {
        *limited = true;
    }
}
