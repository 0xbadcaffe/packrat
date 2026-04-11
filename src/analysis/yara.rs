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
enum HexByte { Exact(u8), Wild }

#[derive(Debug, Clone)]
struct YaraString {
    pub name:   String,   // "$a"
    kind:       StringKind,
    nocase:     bool,
}

impl YaraString {
    fn find_all(&self, data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        match &self.kind {
            StringKind::Literal(p) => if self.nocase { find_literal_nocase(data, p) } else { find_literal(data, p) },
            StringKind::Hex(p)     => find_hex(data, p),
        }
    }
}

// ─── Condition ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Condition {
    AnyOfThem,
    AllOfThem,
    Ref(String),   // "$name"
    True,
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name:        String,
    pub description: String,
    pub tags:        Vec<String>,
    strings:         Vec<YaraString>,
    pub condition:   Condition,
}

impl YaraRule {
    pub fn string_count(&self) -> usize { self.strings.len() }

    fn scan(&self, data: &[u8]) -> Vec<YaraMatch> {
        // Collect all pattern hits
        let hits: Vec<(usize, Vec<YaraMatch>)> = self.strings.iter().enumerate().map(|(i, s)| {
            let ms = s.find_all(data).into_iter().map(|(off, bytes)| YaraMatch {
                rule_name:    self.name.clone(),
                pattern_name: s.name.clone(),
                offset:       off,
                matched_bytes: bytes[..bytes.len().min(32)].to_vec(),
            }).collect();
            (i, ms)
        }).collect();

        let fires = match &self.condition {
            Condition::True       => true,
            Condition::AnyOfThem => hits.iter().any(|(_, ms)| !ms.is_empty()),
            Condition::AllOfThem => !self.strings.is_empty() && hits.iter().all(|(_, ms)| !ms.is_empty()),
            Condition::Ref(name) => hits.iter().any(|(i, ms)| {
                self.strings.get(*i).map(|s| &s.name == name).unwrap_or(false) && !ms.is_empty()
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
    pub rule_name:    String,
    pub pattern_name: String,
    pub offset:       usize,
    pub matched_bytes: Vec<u8>,   // first 32 bytes
}

impl YaraMatch {
    pub fn hex_preview(&self) -> String {
        self.matched_bytes.iter().take(16)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ─── Per-target scan result ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub target_id:    u64,
    pub target_kind:  String,   // "object" | "packet"
    pub target_label: String,
    pub matches:      Vec<YaraMatch>,
}

impl ScanResult {
    /// Deduplicated rule names that fired.
    pub fn rule_names(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.matches.iter()
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
    pub rules:       Vec<YaraRule>,
    pub results:     Vec<ScanResult>,
    pub load_errors: Vec<String>,
    pub rule_dir:    PathBuf,
}

impl YaraEngine {
    /// Create engine and attempt to load rules from `~/.config/packrat/yara/`.
    pub fn new() -> Self {
        let rule_dir = dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("packrat")
            .join("yara");
        let mut engine = Self { rule_dir, ..Default::default() };
        engine.reload();
        engine
    }

    /// Reload all `.yar` / `.yara` files from `rule_dir`.
    pub fn reload(&mut self) {
        self.rules.clear();
        self.load_errors.clear();

        if !self.rule_dir.exists() { return; }

        let entries = match std::fs::read_dir(&self.rule_dir) {
            Ok(e) => e,
            Err(e) => { self.load_errors.push(format!("read dir: {e}")); return; }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yar" && ext != "yara" { continue; }

            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let (rules, errs) = parse_rules(&text);
                    self.rules.extend(rules);
                    for e in errs {
                        self.load_errors.push(format!("{}: {e}", path.file_name()
                            .and_then(|n| n.to_str()).unwrap_or("?")));
                    }
                }
                Err(e) => self.load_errors.push(format!("{}: {e}", path.display())),
            }
        }
    }

    /// Scan raw bytes against all rules. Returns all matches.
    pub fn scan_raw(&self, data: &[u8]) -> Vec<YaraMatch> {
        let scan_data = if data.len() > MAX_SCAN_BYTES { &data[..MAX_SCAN_BYTES] } else { data };
        self.rules.iter().flat_map(|r| r.scan(scan_data)).collect()
    }

    /// Scan bytes and wrap result with target metadata.
    pub fn scan_target(&self, data: &[u8], id: u64, kind: &str, label: &str) -> ScanResult {
        ScanResult {
            target_id:    id,
            target_kind:  kind.to_string(),
            target_label: label.to_string(),
            matches:      self.scan_raw(data),
        }
    }

    pub fn clear_results(&mut self) { self.results.clear(); }
    pub fn rule_dir_str(&self)  -> String { self.rule_dir.display().to_string() }
    pub fn total_matches(&self) -> usize  { self.results.iter().map(|r| r.matches.len()).sum() }
}

// ─── Scanner helpers ──────────────────────────────────────────────────────────

fn find_literal(data: &[u8], pattern: &[u8]) -> Vec<(usize, Vec<u8>)> {
    if pattern.is_empty() { return vec![]; }
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
    if pattern.is_empty() { return vec![]; }
    let lower: Vec<u8> = pattern.iter().map(|b| b.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + pattern.len() <= data.len() {
        let win: Vec<u8> = data[pos..pos + pattern.len()].iter()
            .map(|b| b.to_ascii_lowercase()).collect();
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
    if pattern.is_empty() { return vec![]; }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + pattern.len() <= data.len() {
        let ok = pattern.iter().enumerate().all(|(i, hb)| match hb {
            HexByte::Wild    => true,
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

// ─── Parser ───────────────────────────────────────────────────────────────────

pub fn parse_rules(text: &str) -> (Vec<YaraRule>, Vec<String>) {
    let clean = strip_comments(text);
    let mut rules  = Vec::new();
    let mut errors = Vec::new();

    let mut s: &str = &clean;

    loop {
        let Some(pos) = find_rule_keyword(s) else { break };
        s = &s[pos + 4..];
        s = s.trim_start();

        // Rule name
        let name_end = s.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(s.len());
        let name = s[..name_end].to_string();
        if name.is_empty() { errors.push("empty rule name".into()); continue; }
        s = &s[name_end..];
        s = s.trim_start();

        // Optional tags: `: tag1 tag2`
        let mut tags = Vec::new();
        if s.starts_with(':') {
            s = &s[1..];
            s = s.trim_start();
            while !s.is_empty() && !s.starts_with('{') {
                let end = s.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(s.len());
                if end > 0 { tags.push(s[..end].to_string()); }
                s = s[end..].trim_start();
            }
        }

        // Opening brace
        let Some(bpos) = s.find('{') else {
            errors.push(format!("rule {name}: missing '{{'")); break;
        };
        s = &s[bpos + 1..];

        // Matching closing brace
        let mut depth = 1usize;
        let mut end_pos = s.len();
        for (i, c) in s.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 { end_pos = i; break; }
                }
                _ => {}
            }
        }
        let body = s[..end_pos].to_string();
        s = &s[end_pos + 1..];

        match parse_rule_body(&name, &tags, &body) {
            Ok(rule) => rules.push(rule),
            Err(e)   => errors.push(format!("rule {name}: {e}")),
        }
    }

    (rules, errors)
}

fn find_rule_keyword(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 4 <= b.len() {
        if &b[i..i + 4] == b"rule" {
            let before_ok = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            let after_ok  = i + 4 >= b.len() || !(b[i + 4].is_ascii_alphanumeric() || b[i + 4] == b'_');
            if before_ok && after_ok { return Some(i); }
        }
        i += 1;
    }
    None
}

fn parse_rule_body(name: &str, tags: &[String], body: &str) -> Result<YaraRule, String> {
    let mut description = String::new();
    let mut strings     = Vec::new();
    let mut condition   = Condition::True;

    // State machine over lines — split into sections by "meta:" / "strings:" / "condition:"
    let mut section = "";
    let mut buf     = String::new();

    for line in body.lines() {
        let t = line.trim();
        match t {
            "meta:"      => { flush_section(section, &buf, &mut description, &mut strings, &mut condition)?; buf.clear(); section = "meta"; }
            "strings:"   => { flush_section(section, &buf, &mut description, &mut strings, &mut condition)?; buf.clear(); section = "strings"; }
            "condition:" => { flush_section(section, &buf, &mut description, &mut strings, &mut condition)?; buf.clear(); section = "condition"; }
            ""           => {}
            _            => { buf.push_str(t); buf.push('\n'); }
        }
    }
    if !buf.is_empty() { flush_section(section, &buf, &mut description, &mut strings, &mut condition)?; }

    Ok(YaraRule { name: name.to_string(), description, tags: tags.to_vec(), strings, condition })
}

fn flush_section(
    section: &str, buf: &str,
    description: &mut String,
    strings: &mut Vec<YaraString>,
    condition: &mut Condition,
) -> Result<(), String> {
    match section {
        "meta" => {
            for line in buf.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("description") {
                    let v = rest.trim().trim_start_matches('=').trim().trim_matches('"');
                    *description = v.to_string();
                }
            }
        }
        "strings" => {
            for line in buf.lines() {
                let t = line.trim();
                if t.is_empty() { continue; }
                strings.push(parse_string_def(t)?);
            }
        }
        "condition" => {
            *condition = parse_condition(buf.trim());
        }
        _ => {}
    }
    Ok(())
}

fn parse_string_def(line: &str) -> Result<YaraString, String> {
    // $name = "literal" [nocase]
    // $name = { HH ?? HH } [nocase]
    let mut parts = line.splitn(2, '=');
    let name = parts.next().unwrap_or("").trim().to_string();
    let rhs  = parts.next().ok_or_else(|| format!("missing = in: {line}"))?.trim();

    if !name.starts_with('$') {
        return Err(format!("string name must start with $: {name}"));
    }

    let nocase = rhs.contains("nocase");

    let kind = if rhs.starts_with('"') {
        // Literal string
        let inner = &rhs[1..];
        let end = inner.find('"').ok_or_else(|| format!("unterminated string: {line}"))?;
        StringKind::Literal(unescape_str(&inner[..end]))
    } else if rhs.starts_with('{') {
        // Hex pattern
        let end = rhs.find('}').ok_or_else(|| format!("unterminated hex: {line}"))?;
        let hex_str = &rhs[1..end];
        let mut pat = Vec::new();
        for tok in hex_str.split_whitespace() {
            // Skip alternation/grouping tokens
            if tok == "|" || tok == "(" || tok == ")" { continue; }
            if tok == "??" || tok == "?" {
                pat.push(HexByte::Wild);
            } else if tok.len() == 2 {
                let b = u8::from_str_radix(tok, 16)
                    .map_err(|_| format!("bad hex byte '{tok}' in: {line}"))?;
                pat.push(HexByte::Exact(b));
            } else if tok.len() == 1 && tok.chars().next().map(|c| c.is_ascii_hexdigit()).unwrap_or(false) {
                // Nibble-masked like "?D" — simplify to wildcard
                pat.push(HexByte::Wild);
            }
            // Skip anything else (comments, etc.)
        }
        StringKind::Hex(pat)
    } else if rhs.starts_with('/') {
        // Regex — extract literal content between slashes and use as literal
        // (limited support: works for simple fixed patterns)
        let end = rhs[1..].rfind('/').map(|i| i + 1).unwrap_or(rhs.len());
        let literal = &rhs[1..end];
        // Strip common regex anchors for literal matching
        let clean = literal.trim_start_matches('^').trim_end_matches('$');
        StringKind::Literal(clean.as_bytes().to_vec())
    } else {
        return Err(format!("unknown string type in: {line}"));
    };

    Ok(YaraString { name, kind, nocase })
}

fn unescape_str(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n')  => out.push(b'\n'),
                Some('r')  => out.push(b'\r'),
                Some('t')  => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"')  => out.push(b'"'),
                Some('x')  => {
                    let h1 = chars.next().and_then(|c| c.to_digit(16));
                    let h2 = chars.next().and_then(|c| c.to_digit(16));
                    if let (Some(h1), Some(h2)) = (h1, h2) {
                        out.push((h1 * 16 + h2) as u8);
                    }
                }
                Some(c) => { out.push(b'\\'); out.extend(c.to_string().as_bytes()); }
                None => {}
            }
        } else {
            out.extend(c.to_string().as_bytes());
        }
    }
    out
}

fn parse_condition(cond: &str) -> Condition {
    let t = cond.trim().to_lowercase();
    let t = t.as_str();
    if t == "any of them" || t.starts_with("any of ($") {
        Condition::AnyOfThem
    } else if t == "all of them" || t.starts_with("all of ($") {
        Condition::AllOfThem
    } else if t == "true" || t.is_empty() {
        Condition::True
    } else if t.starts_with('$') {
        // Take first identifier only (e.g., "$a and $b" → "$a")
        let end = t.find(|c: char| c.is_whitespace() || c == ')').unwrap_or(t.len());
        Condition::Ref(t[..end].to_string())
    } else {
        // Complex conditions (uint comparisons, etc.) — default to any
        Condition::AnyOfThem
    }
}

fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' { i += 1; }
        } else if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') { i += 1; }
            i += 2;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}
