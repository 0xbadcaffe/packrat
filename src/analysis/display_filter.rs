//! Display filter engine — Wireshark-style post-capture filter expressions.
//!
//! Supports:
//!   tcp                          protocol existence
//!   ip.src == 192.168.1.1        field comparison
//!   tcp.dstport == 443
//!   frame.len > 100
//!   not udp
//!   tcp and ip.src == 10.0.0.1
//!   http.host ~ "api"            regex/contains
//!   dns.qname contains "corp"
//!   tcp.port in [80,443,8080]    set membership
//!   tag == "suspicious"
//!   marked == true

use std::collections::VecDeque;
use crate::net::packet::Packet;

// ─── AST ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Expr {
    /// A bare protocol name: `tcp`, `http`, `dns`
    Proto(String),
    /// `marked == true/false`
    Marked(bool),
    /// `tag == "label"`
    HasTag(String),
    /// `field op value`
    Cmp { field: String, op: CmpOp, value: Value },
    /// `field ~ "pattern"` or `field contains "string"`
    Contains { field: String, pattern: String, regex: bool },
    /// `field in [v1, v2, ...]`
    In { field: String, values: Vec<Value> },
    /// `not expr`
    Not(Box<Expr>),
    /// `a and b`
    And(Box<Expr>, Box<Expr>),
    /// `a or b`
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CmpOp { Eq, Ne, Lt, Gt, Le, Ge }

#[derive(Debug, Clone)]
pub enum Value {
    Str(String),
    Num(f64),
    Bool(bool),
}

// ─── Parser ───────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

struct Tokens<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Tokens<'a> {
    fn new(s: &'a str) -> Self { Self { src: s.as_bytes(), pos: 0 } }

    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos] == b' ' { self.pos += 1; }
    }

    fn peek(&mut self) -> Option<u8> { self.skip_ws(); self.src.get(self.pos).copied() }

    fn eat_while(&mut self, f: impl Fn(u8) -> bool) -> &'a str {
        let start = self.pos;
        while self.pos < self.src.len() && f(self.src[self.pos]) { self.pos += 1; }
        std::str::from_utf8(&self.src[start..self.pos]).unwrap_or("")
    }

    fn eat_word(&mut self) -> String {
        self.skip_ws();
        self.eat_while(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b':')
            .to_string()
    }

    fn eat_str(&mut self) -> Result<String, ParseError> {
        self.skip_ws();
        if self.peek() != Some(b'"') {
            return Err(ParseError("expected quoted string".into()));
        }
        self.pos += 1;
        let mut s = String::new();
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            self.pos += 1;
            if c == b'"' { return Ok(s); }
            if c == b'\\' && self.pos < self.src.len() {
                s.push(self.src[self.pos] as char);
                self.pos += 1;
            } else {
                s.push(c as char);
            }
        }
        Err(ParseError("unterminated string".into()))
    }

    fn eat_num(&mut self) -> Option<f64> {
        self.skip_ws();
        let s = self.eat_while(|c| c.is_ascii_digit() || c == b'.');
        s.parse().ok()
    }

    fn try_eat(&mut self, s: &str) -> bool {
        self.skip_ws();
        let bytes = s.as_bytes();
        if self.src[self.pos..].starts_with(bytes) {
            self.pos += bytes.len();
            true
        } else {
            false
        }
    }

    fn is_eof(&mut self) -> bool { self.skip_ws(); self.pos >= self.src.len() }
}

/// Parse a filter expression string into an AST.
pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let mut t = Tokens::new(input);
    let expr = parse_or(&mut t)?;
    if !t.is_eof() {
        return Err(ParseError(format!("unexpected token at position {}", t.pos)));
    }
    Ok(expr)
}

fn parse_or(t: &mut Tokens<'_>) -> Result<Expr, ParseError> {
    let mut left = parse_and(t)?;
    while {t.skip_ws(); t.try_eat("or") || t.try_eat("||")} {
        let right = parse_and(t)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(t: &mut Tokens<'_>) -> Result<Expr, ParseError> {
    let mut left = parse_not(t)?;
    while {t.skip_ws(); t.try_eat("and") || t.try_eat("&&")} {
        let right = parse_not(t)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_not(t: &mut Tokens<'_>) -> Result<Expr, ParseError> {
    t.skip_ws();
    if t.try_eat("not ") || t.try_eat("!") {
        let inner = parse_not(t)?;
        return Ok(Expr::Not(Box::new(inner)));
    }
    parse_atom(t)
}

fn parse_atom(t: &mut Tokens<'_>) -> Result<Expr, ParseError> {
    t.skip_ws();
    // Parenthesised
    if t.peek() == Some(b'(') {
        t.pos += 1;
        let inner = parse_or(t)?;
        t.skip_ws();
        if t.peek() != Some(b')') { return Err(ParseError("expected ')'".into())); }
        t.pos += 1;
        return Ok(inner);
    }

    let word = t.eat_word();
    if word.is_empty() { return Err(ParseError("expected expression".into())); }

    // Special bare keywords
    match word.as_str() {
        "marked" => {
            t.skip_ws();
            if t.try_eat("==") || t.try_eat("!=") {
                t.skip_ws();
                let w2 = t.eat_word();
                let v = w2 == "true";
                return Ok(Expr::Marked(v));
            }
            return Ok(Expr::Marked(true));
        }
        "tag" => {
            t.skip_ws();
            t.try_eat("==");
            t.skip_ws();
            let s = t.eat_str()?;
            return Ok(Expr::HasTag(s));
        }
        _ => {}
    }

    // Check for operator following the field name
    t.skip_ws();

    // `field contains "str"` or `field ~ "re"`
    if t.try_eat("contains ") {
        t.skip_ws();
        let s = t.eat_str()?;
        return Ok(Expr::Contains { field: word, pattern: s, regex: false });
    }
    if t.try_eat("~") {
        t.skip_ws();
        let s = t.eat_str()?;
        return Ok(Expr::Contains { field: word, pattern: s, regex: true });
    }

    // `field in [v1,v2,...]`
    if t.try_eat("in ") || t.try_eat("in[") {
        t.skip_ws();
        if t.peek() == Some(b'[') { t.pos += 1; }
        let mut vals = Vec::new();
        loop {
            t.skip_ws();
            if t.peek() == Some(b']') { t.pos += 1; break; }
            if t.peek() == Some(b'"') {
                vals.push(Value::Str(t.eat_str()?));
            } else if let Some(n) = t.eat_num() {
                vals.push(Value::Num(n));
            }
            t.skip_ws();
            if t.peek() == Some(b',') { t.pos += 1; }
        }
        return Ok(Expr::In { field: word, values: vals });
    }

    // Comparison operator
    let op = if t.try_eat("==") { CmpOp::Eq }
        else if t.try_eat("!=") { CmpOp::Ne }
        else if t.try_eat(">=") { CmpOp::Ge }
        else if t.try_eat("<=") { CmpOp::Le }
        else if t.try_eat(">")  { CmpOp::Gt }
        else if t.try_eat("<")  { CmpOp::Lt }
        else {
            // Bare word = protocol existence: `tcp`, `http`, `dns`
            return Ok(Expr::Proto(word));
        };

    t.skip_ws();
    let value = if t.peek() == Some(b'"') {
        Value::Str(t.eat_str()?)
    } else {
        let w = t.eat_word();
        if w == "true" { Value::Bool(true) }
        else if w == "false" { Value::Bool(false) }
        else if let Ok(n) = w.parse::<f64>() { Value::Num(n) }
        else { Value::Str(w) }
    };

    Ok(Expr::Cmp { field: word, op, value })
}

// ─── Evaluator ────────────────────────────────────────────────────────────────

/// Context passed to the evaluator — holds references to supporting data.
pub struct EvalCtx<'a> {
    pub pkt:     &'a Packet,
    pub marked:  bool,
    pub tags:    &'a [String],
}

/// Evaluate a compiled expression against a packet in context.
pub fn eval(expr: &Expr, ctx: &EvalCtx<'_>) -> bool {
    match expr {
        Expr::Proto(p) => {
            ctx.pkt.protocol.to_lowercase() == p.to_lowercase()
            || ctx.pkt.info.to_lowercase().contains(p.to_lowercase().as_str())
        }
        Expr::Marked(v) => ctx.marked == *v,
        Expr::HasTag(t) => ctx.tags.iter().any(|tag| tag == t),
        Expr::Not(e)    => !eval(e, ctx),
        Expr::And(a, b) => eval(a, ctx) && eval(b, ctx),
        Expr::Or(a, b)  => eval(a, ctx) || eval(b, ctx),

        Expr::Contains { field, pattern, regex } => {
            let fv = get_field_str(ctx.pkt, field);
            if *regex {
                // Simple substring match (real regex would need the `regex` crate)
                fv.to_lowercase().contains(&pattern.to_lowercase())
            } else {
                fv.to_lowercase().contains(&pattern.to_lowercase())
            }
        }

        Expr::In { field, values } => {
            let fv_str = get_field_str(ctx.pkt, field);
            let fv_num = get_field_num(ctx.pkt, field);
            values.iter().any(|v| match v {
                Value::Str(s) => fv_str.to_lowercase() == s.to_lowercase(),
                Value::Num(n) => fv_num.map(|f| (f - n).abs() < 0.5).unwrap_or(false),
                Value::Bool(_) => false,
            })
        }

        Expr::Cmp { field, op, value } => {
            match value {
                Value::Str(s) => {
                    let fv = get_field_str(ctx.pkt, field);
                    cmp_str(&fv, op, s)
                }
                Value::Num(n) => {
                    if let Some(fv) = get_field_num(ctx.pkt, field) {
                        cmp_num(fv, op, *n)
                    } else {
                        false
                    }
                }
                Value::Bool(b) => {
                    let fv = get_field_bool(ctx.pkt, field);
                    match op {
                        CmpOp::Eq => fv == *b,
                        CmpOp::Ne => fv != *b,
                        _ => false,
                    }
                }
            }
        }
    }
}

fn cmp_str(a: &str, op: &CmpOp, b: &str) -> bool {
    match op {
        CmpOp::Eq => a.to_lowercase() == b.to_lowercase(),
        CmpOp::Ne => a.to_lowercase() != b.to_lowercase(),
        CmpOp::Lt => a < b,
        CmpOp::Gt => a > b,
        CmpOp::Le => a <= b,
        CmpOp::Ge => a >= b,
    }
}

fn cmp_num(a: f64, op: &CmpOp, b: f64) -> bool {
    match op {
        CmpOp::Eq => (a - b).abs() < 0.5,
        CmpOp::Ne => (a - b).abs() >= 0.5,
        CmpOp::Lt => a < b,
        CmpOp::Gt => a > b,
        CmpOp::Le => a <= b,
        CmpOp::Ge => a >= b,
    }
}

fn get_field_str<'a>(pkt: &'a Packet, field: &str) -> String {
    match field {
        "ip.src" | "ip.addr" => pkt.src.clone(),
        "ip.dst"             => pkt.dst.clone(),
        "tcp.srcport" | "udp.srcport" => pkt.src_port.map(|p| p.to_string()).unwrap_or_default(),
        "tcp.dstport" | "udp.dstport" | "tcp.port" | "udp.port"
                             => pkt.dst_port.map(|p| p.to_string()).unwrap_or_default(),
        "proto" | "ip.proto" => pkt.protocol.clone(),
        "info" | "frame.info" => pkt.info.clone(),
        "http.host"          => extract_http_header(&pkt.info, "Host"),
        "http.method"        => pkt.info.split_whitespace().next().unwrap_or("").to_string(),
        "http.uri" | "http.request.uri" => extract_http_uri(&pkt.info),
        "dns.qname"          => extract_dns_qname(&pkt.info),
        "tls.sni" | "ssl.sni" => extract_tls_sni(pkt),
        _                    => String::new(),
    }
}

fn get_field_num(pkt: &Packet, field: &str) -> Option<f64> {
    match field {
        "frame.len" | "frame.length" => Some(pkt.length as f64),
        "tcp.srcport" | "udp.srcport" => pkt.src_port.map(|p| p as f64),
        "tcp.dstport" | "udp.dstport" | "tcp.port" | "udp.port"
                                      => pkt.dst_port.map(|p| p as f64),
        "ip.ttl"                      => Some(pkt.bytes.get(22).copied().unwrap_or(0) as f64),
        "vlan.id"                     => pkt.vlan_id.map(|v| v as f64),
        "frame.number"                => Some(pkt.no as f64),
        _                             => None,
    }
}

fn get_field_bool(_pkt: &Packet, field: &str) -> bool {
    match field {
        // These would need the notebook context in a real implementation
        "marked" => false,
        _        => false,
    }
}

fn extract_http_header(info: &str, header: &str) -> String {
    let target = format!("{}:", header);
    if let Some(pos) = info.find(&target) {
        info[pos + target.len()..].split_whitespace().next()
            .unwrap_or("").trim_end_matches(',').to_string()
    } else {
        String::new()
    }
}

fn extract_http_uri(info: &str) -> String {
    let parts: Vec<&str> = info.split_whitespace().collect();
    if parts.len() >= 2 { parts[1].to_string() } else { String::new() }
}

fn extract_dns_qname(info: &str) -> String {
    // "Query 0x1234 A example.com" or similar
    let parts: Vec<&str> = info.split_whitespace().collect();
    parts.iter().find(|&&p| p.contains('.') && !p.starts_with("0x"))
        .map(|&s| s.to_string())
        .unwrap_or_default()
}

fn extract_tls_sni(pkt: &Packet) -> String {
    // Try to find SNI in raw bytes (ClientHello extension type 0x0000)
    let bytes = &pkt.bytes;
    if bytes.len() < 54 { return String::new(); }
    // Look for SNI extension type (0x00 0x00) in the TLS handshake
    for i in 54..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x00 && bytes[i+1] == 0x00 && i + 5 < bytes.len() {
            let len = u16::from_be_bytes([bytes[i+3], bytes[i+4]]) as usize;
            if i + 5 + len <= bytes.len() {
                let name = std::str::from_utf8(&bytes[i+5..i+5+len]).unwrap_or("");
                if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') && name.contains('.') {
                    return name.to_string();
                }
            }
        }
    }
    String::new()
}

// ─── Compiled filter ──────────────────────────────────────────────────────────

/// A parsed and ready-to-evaluate display filter.
pub struct DisplayFilter {
    pub input: String,
    pub expr:  Option<Expr>,
    pub error: Option<String>,
}

impl Default for DisplayFilter {
    fn default() -> Self {
        Self { input: String::new(), expr: None, error: None }
    }
}

impl DisplayFilter {
    pub fn set(&mut self, input: impl Into<String>) {
        self.input = input.into();
        if self.input.trim().is_empty() {
            self.expr = None;
            self.error = None;
            return;
        }
        match parse(&self.input) {
            Ok(e)  => { self.expr = Some(e); self.error = None; }
            Err(e) => { self.expr = None; self.error = Some(e.0); }
        }
    }

    pub fn is_active(&self) -> bool { self.expr.is_some() }
    pub fn has_error(&self) -> bool { self.error.is_some() }

    pub fn matches(&self, pkt: &Packet, marked: bool, tags: &[String]) -> bool {
        match &self.expr {
            None    => true,
            Some(e) => eval(e, &EvalCtx { pkt, marked, tags }),
        }
    }

    /// Simple legacy text-match fallback (protocol / src / dst / info).
    pub fn matches_simple(q: &str, pkt: &Packet) -> bool {
        if q.is_empty() { return true; }
        let q = q.to_lowercase();
        pkt.protocol.to_lowercase().contains(&q)
        || pkt.src.contains(&q)
        || pkt.dst.contains(&q)
        || pkt.info.to_lowercase().contains(&q)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::packet::Packet;

    fn make_pkt(proto: &str, src: &str, dst: &str, sport: u16, dport: u16, len: u16) -> Packet {
        Packet {
            no: 1, timestamp: 0.0,
            src: src.into(), dst: dst.into(),
            protocol: proto.into(), length: len,
            info: format!("{} → {}", src, dst),
            bytes: vec![0u8; len as usize],
            src_port: Some(sport), dst_port: Some(dport), vlan_id: None,
        }
    }

    #[test]
    fn test_proto_filter() {
        let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
        let ctx = EvalCtx { pkt: &pkt, marked: false, tags: &[] };
        assert!(eval(&parse("tcp").unwrap(), &ctx));
        assert!(!eval(&parse("udp").unwrap(), &ctx));
    }

    #[test]
    fn test_field_cmp() {
        let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 443, 200);
        let ctx = EvalCtx { pkt: &pkt, marked: false, tags: &[] };
        assert!(eval(&parse("ip.src == \"1.2.3.4\"").unwrap(), &ctx));
        assert!(eval(&parse("tcp.dstport == 443").unwrap(), &ctx));
        assert!(eval(&parse("frame.len > 100").unwrap(), &ctx));
        assert!(!eval(&parse("frame.len < 100").unwrap(), &ctx));
    }

    #[test]
    fn test_boolean_logic() {
        let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
        let ctx = EvalCtx { pkt: &pkt, marked: false, tags: &[] };
        assert!(eval(&parse("tcp and ip.src == \"1.2.3.4\"").unwrap(), &ctx));
        assert!(eval(&parse("not udp").unwrap(), &ctx));
        assert!(eval(&parse("udp or tcp").unwrap(), &ctx));
    }

    #[test]
    fn test_in_filter() {
        let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 443, 100);
        let ctx = EvalCtx { pkt: &pkt, marked: false, tags: &[] };
        assert!(eval(&parse("tcp.port in [80,443,8080]").unwrap(), &ctx));
        assert!(!eval(&parse("tcp.port in [80,8080]").unwrap(), &ctx));
    }

    #[test]
    fn test_marked() {
        let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
        let ctx_marked   = EvalCtx { pkt: &pkt, marked: true,  tags: &[] };
        let ctx_unmarked = EvalCtx { pkt: &pkt, marked: false, tags: &[] };
        assert!(eval(&parse("marked == true").unwrap(), &ctx_marked));
        assert!(!eval(&parse("marked == true").unwrap(), &ctx_unmarked));
    }

    #[test]
    fn test_tag_filter() {
        let pkt = make_pkt("TCP", "1.2.3.4", "5.6.7.8", 1234, 80, 100);
        let tags = vec!["suspicious".to_string(), "c2".to_string()];
        let ctx = EvalCtx { pkt: &pkt, marked: false, tags: &tags };
        assert!(eval(&parse("tag == \"suspicious\"").unwrap(), &ctx));
        assert!(!eval(&parse("tag == \"benign\"").unwrap(), &ctx));
    }
}
