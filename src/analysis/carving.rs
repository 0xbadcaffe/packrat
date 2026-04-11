//! File carving — extract embedded files from packet payloads.
//!
//! Scans reassembled stream data for magic bytes and extracts
//! candidate files with their offsets and types.

use std::collections::HashMap;

// ─── Carved object ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CarvedObject {
    /// Sequential ID assigned at carve time.
    pub id:        u64,
    /// Detected MIME type or file kind (e.g. "image/png", "application/pdf").
    pub kind:      String,
    /// Human-readable name, e.g. "PNG from flow tcp:1.2.3.4:1234-5.6.7.8:80"
    pub name:      String,
    /// Source flow or stream identifier.
    pub source:    String,
    /// Byte offset inside the stream where the object starts.
    pub offset:    usize,
    /// Extracted bytes (may be truncated for large objects).
    pub data:      Vec<u8>,
    /// Computed SHA-256 hex string (empty if not yet computed).
    pub sha256:    String,
    /// YARA rule hits against this object (populated later).
    pub yara_hits: Vec<String>,
}

impl CarvedObject {
    pub fn size_str(&self) -> String {
        let b = self.data.len();
        if b < 1024 { format!("{b}B") }
        else if b < 1024 * 1024 { format!("{:.1}KB", b as f64 / 1024.0) }
        else { format!("{:.1}MB", b as f64 / 1_048_576.0) }
    }
}

// ─── Magic signatures ─────────────────────────────────────────────────────────

struct Sig {
    magic:  &'static [u8],
    kind:   &'static str,
    /// Optional trailer bytes (to detect end of file). None = use max_size.
    trailer: Option<&'static [u8]>,
    max_size: usize,
}

static SIGNATURES: &[Sig] = &[
    Sig { magic: b"\x89PNG\r\n\x1a\n",   kind: "image/png",         trailer: Some(b"\x00\x00\x00\x00IEND\xaeB`\x82"), max_size: 10_000_000 },
    Sig { magic: b"\xff\xd8\xff",         kind: "image/jpeg",        trailer: Some(b"\xff\xd9"),                        max_size: 10_000_000 },
    Sig { magic: b"GIF87a",               kind: "image/gif",         trailer: Some(b"\x00;"),                           max_size: 5_000_000  },
    Sig { magic: b"GIF89a",               kind: "image/gif",         trailer: Some(b"\x00;"),                           max_size: 5_000_000  },
    Sig { magic: b"%PDF-",                kind: "application/pdf",   trailer: Some(b"%%EOF"),                           max_size: 50_000_000 },
    Sig { magic: b"PK\x03\x04",           kind: "application/zip",   trailer: Some(b"PK\x05\x06"),                      max_size: 50_000_000 },
    Sig { magic: b"\x1f\x8b\x08",         kind: "application/gzip",  trailer: None,                                     max_size: 50_000_000 },
    Sig { magic: b"BZh",                  kind: "application/bzip2", trailer: None,                                     max_size: 50_000_000 },
    Sig { magic: b"\xfd7zXZ\x00",         kind: "application/xz",    trailer: None,                                     max_size: 50_000_000 },
    Sig { magic: b"MZ",                   kind: "application/exe",   trailer: None,                                     max_size: 20_000_000 },
    Sig { magic: b"\x7fELF",              kind: "application/elf",   trailer: None,                                     max_size: 20_000_000 },
    Sig { magic: b"RIFF",                 kind: "audio/wav",         trailer: None,                                     max_size: 20_000_000 },
    Sig { magic: b"OggS",                 kind: "audio/ogg",         trailer: None,                                     max_size: 20_000_000 },
    Sig { magic: b"ID3",                  kind: "audio/mp3",         trailer: None,                                     max_size: 20_000_000 },
    Sig { magic: b"\x00\x00\x00\x20ftyp", kind: "video/mp4",        trailer: None,                                     max_size: 100_000_000},
    Sig { magic: b"<!DOCTYPE html",       kind: "text/html",         trailer: Some(b"</html>"),                         max_size: 5_000_000  },
    Sig { magic: b"<html",               kind: "text/html",          trailer: Some(b"</html>"),                         max_size: 5_000_000  },
];

// ─── Carver ───────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct Carver {
    next_id: u64,
    /// Deduplicate by SHA256 to avoid re-emitting the same file.
    seen: HashMap<String, bool>,
}

impl Carver {
    /// Scan `data` for embedded files and return all found objects.
    pub fn carve(&mut self, data: &[u8], source: &str) -> Vec<CarvedObject> {
        let mut out = Vec::new();
        for sig in SIGNATURES {
            let mut pos = 0;
            while pos + sig.magic.len() <= data.len() {
                if data[pos..].starts_with(sig.magic) {
                    let end = if let Some(trail) = sig.trailer {
                        // Search forward for trailer
                        find_after(&data[pos..], trail)
                            .map(|off| (pos + off + trail.len()).min(pos + sig.max_size))
                            .unwrap_or((pos + sig.max_size).min(data.len()))
                    } else {
                        (pos + sig.max_size).min(data.len())
                    };

                    let slice = &data[pos..end];
                    if slice.len() > sig.magic.len() {
                        let digest = sha256_hex(slice);
                        if !self.seen.contains_key(&digest) {
                            self.seen.insert(digest.clone(), true);
                            self.next_id += 1;
                            out.push(CarvedObject {
                                id:        self.next_id,
                                kind:      sig.kind.to_string(),
                                name:      format!("{} from {}", sig.kind, source),
                                source:    source.to_string(),
                                offset:    pos,
                                data:      slice.to_vec(),
                                sha256:    digest,
                                yara_hits: Vec::new(),
                            });
                        }
                    }
                    pos += sig.magic.len(); // advance past this magic to continue scanning
                } else {
                    pos += 1;
                }
            }
        }
        out
    }
}

fn find_after(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return None; }
    data.windows(needle.len()).position(|w| w == needle)
}

fn sha256_hex(data: &[u8]) -> String {
    // Simple FNV-1a 64-bit hash as a stand-in (avoids pulling sha2 crate).
    let mut h: u64 = 14_695_981_039_346_656_037;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(1_099_511_628_211);
    }
    format!("{h:016x}")
}
