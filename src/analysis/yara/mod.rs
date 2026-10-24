//! YARA-compatible rule engine — pure Rust, no external C library.
//!
//! Parses a practical subset of YARA 4.x syntax and scans byte buffers.
//!
//! Supported rule syntax:
//!   strings:
//!     $a = "literal"              (optional `nocase` modifier)
//!     $b = { DE AD ?? BE EF }     (hex with `??` wildcards)
//!   condition:
//!     any of them  |  all of them  |  $name  |  true

use std::path::PathBuf;

// ─── Pattern kinds ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum StringKind {
    Literal(Vec<u8>),
    Hex(Vec<HexByte>),
}

#[derive(Debug, Clone, Copy)]
enum HexByte {
    Exact(u8),
    Wild,
}

#[derive(Debug, Clone)]
struct YaraString {
    pub name: String, // "$a"
    kind: StringKind,
    nocase: bool,
}

impl YaraString {
    fn find_all(&self, data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        match &self.kind {
            StringKind::Literal(p) => {
                if self.nocase {
                    find_literal_nocase(data, p)
                } else {
                    find_literal(data, p)
                }
            }
            StringKind::Hex(p) => find_hex(data, p),
        }
    }
}

// ─── Condition ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Condition {
    AnyOfThem,
    AllOfThem,
    Ref(String), // "$name"
    True,
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    strings: Vec<YaraString>,
    pub condition: Condition,
}

impl YaraRule {
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        // Collect all pattern hits
        let hits: Vec<(usize, Vec<YaraMatch>)> = self
            .strings
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let ms = s
                    .find_all(data)
                    .into_iter()
                    .map(|(off, bytes)| YaraMatch {
                        rule_name: self.name.clone(),
                        pattern_name: s.name.clone(),
                        offset: off,
                        matched_bytes: bytes[..bytes.len().min(32)].to_vec(),
                    })
                    .collect();
                (i, ms)
            })
            .collect();

        let fires = match &self.condition {
            Condition::True => true,
            Condition::AnyOfThem => hits.iter().any(|(_, ms)| !ms.is_empty()),
            Condition::AllOfThem => {
                !self.strings.is_empty() && hits.iter().all(|(_, ms)| !ms.is_empty())
            }
            Condition::Ref(name) => hits.iter().any(|(i, ms)| {
                self.strings
                    .get(*i)
                    .map(|s| &s.name == name)
                    .unwrap_or(false)
                    && !ms.is_empty()
            }),
        };

        if fires {
            hits.into_iter().flat_map(|(_, ms)| ms).collect()
        } else {
            Vec::new()
        }
    }
}

// ─── Match result ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub pattern_name: String,
    pub offset: usize,
    pub matched_bytes: Vec<u8>, // first 32 bytes
}

impl YaraMatch {
    pub fn hex_preview(&self) -> String {
        self.matched_bytes
            .iter()
            .take(16)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ─── Per-target scan result ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target_id: u64,
    pub target_kind: String, // "object" | "packet"
    pub target_label: String,
    pub matches: Vec<YaraMatch>,
}

impl ScanResult {
    /// Deduplicated rule names that fired.
    pub fn rule_names(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.matches
            .iter()
            .filter(|m| seen.insert(m.rule_name.clone()))
            .map(|m| m.rule_name.clone())
            .collect()
    }
}

// ─── Engine ───────────────────────────────────────────────────────────────────

/// Maximum bytes scanned per object (avoid long scans for huge objects).
const MAX_SCAN_BYTES: usize = 1_048_576; // 1 MB

#[derive(Debug, Default)]
pub struct YaraEngine {
    pub rules: Vec<YaraRule>,
    pub results: Vec<ScanResult>,
    pub load_errors: Vec<String>,
    pub rule_dir: PathBuf,
}

impl YaraEngine {
    /// Create engine and attempt to load rules from `~/.config/packrat/yara/`.
    pub fn new() -> Self {
        let rule_dir = dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("packrat")
            .join("yara");
        let mut engine = Self {
            rule_dir,
            ..Default::default()
        };
        engine.reload();
        engine
    }

    /// Reload all `.yar` / `.yara` files from `rule_dir`.
    pub fn reload(&mut self) {
        self.rules.clear();
        self.load_errors.clear();

        if !self.rule_dir.exists() {
            return;
        }

        let entries = match std::fs::read_dir(&self.rule_dir) {
            Ok(e) => e,
            Err(e) => {
                self.load_errors.push(format!("read dir: {e}"));
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yar" && ext != "yara" {
                continue;
            }

            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let (rules, errs) = parse_rules(&text);
                    self.rules.extend(rules);
                    for e in errs {
                        self.load_errors.push(format!(
                            "{}: {e}",
                            path.file_name().and_then(|n| n.to_str()).unwrap_or("?")
                        ));
                    }
                }
                Err(e) => self.load_errors.push(format!("{}: {e}", path.display())),
            }
        }
    }

    /// Scan raw bytes against all rules. Returns all matches.
    pub fn scan_raw(&self, data: &[u8]) -> Vec<YaraMatch> {
        let scan_data = if data.len() > MAX_SCAN_BYTES {
            &data[..MAX_SCAN_BYTES]
        } else {
            data
        };
        self.rules.iter().flat_map(|r| r.scan(scan_data)).collect()
    }

    /// Scan bytes and wrap result with target metadata.
    pub fn scan_target(&self, data: &[u8], id: u64, kind: &str, label: &str) -> ScanResult {
        ScanResult {
            target_id: id,
            target_kind: kind.to_string(),
            target_label: label.to_string(),
            matches: self.scan_raw(data),
        }
    }

    pub fn clear_results(&mut self) {
        self.results.clear();
    }
    pub fn rule_dir_str(&self) -> String {
        self.rule_dir.display().to_string()
    }
    pub fn total_matches(&self) -> usize {
        self.results.iter().map(|r| r.matches.len()).sum()
    }
}

// ─── Scanner helpers ──────────────────────────────────────────────────────────

fn find_literal(data: &[u8], pattern: &[u8]) -> Vec<(usize, Vec<u8>)> {
    if pattern.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + pattern.len() <= data.len() {
        if data[pos..].starts_with(pattern) {
            out.push((pos, pattern.to_vec()));
            pos += pattern.len();
        } else {
            pos += 1;
        }
    }
    out
}

fn find_literal_nocase(data: &[u8], pattern: &[u8]) -> Vec<(usize, Vec<u8>)> {
    if pattern.is_empty() {
        return vec![];
    }
    let lower: Vec<u8> = pattern.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + pattern.len() <= data.len() {
        let win: Vec<u8> = data[pos..pos + pattern.len()]
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect();
        if win == lower {
            out.push((pos, data[pos..pos + pattern.len()].to_vec()));
            pos += pattern.len();
        } else {
            pos += 1;
        }
    }
    out
}

fn find_hex(data: &[u8], pattern: &[HexByte]) -> Vec<(usize, Vec<u8>)> {
    if pattern.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + pattern.len() <= data.len() {
        let ok = pattern.iter().enumerate().all(|(i, hb)| match hb {
            HexByte::Wild => true,
            HexByte::Exact(b) => data[pos + i] == *b,
        });
        if ok {
            out.push((pos, data[pos..pos + pattern.len()].to_vec()));
            pos += pattern.len();
        } else {
            pos += 1;
        }
    }
    out
}

mod parser;
pub use parser::parse_rules;

