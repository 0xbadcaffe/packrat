use super::*;

// ─── Parser ───────────────────────────────────────────────────────────────────

pub fn parse_rules(text: &str) -> (Vec<YaraRule>, Vec<String>) {
    let clean = strip_comments(text);
    let mut rules = Vec::new();
    let mut errors = Vec::new();

    let mut s: &str = &clean;

    loop {
        let Some(pos) = find_rule_keyword(s) else {
            break;
        };
        s = &s[pos + 4..];
        s = s.trim_start();

        // Rule name
        let name_end = s
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(s.len());
        let name = s[..name_end].to_string();
        if name.is_empty() {
            errors.push("empty rule name".into());
            continue;
        }
        s = &s[name_end..];
        s = s.trim_start();

        // Optional tags: `: tag1 tag2`
        let mut tags = Vec::new();
        if s.starts_with(':') {
            s = &s[1..];
            s = s.trim_start();
            while !s.is_empty() && !s.starts_with('{') {
                let end = s
                    .find(|c: char| !c.is_alphanumeric() && c != '_')
                    .unwrap_or(s.len());
                if end > 0 {
                    tags.push(s[..end].to_string());
                }
                s = s[end..].trim_start();
            }
        }

        // Opening brace
        let Some(bpos) = s.find('{') else {
            errors.push(format!("rule {name}: missing '{{'"));
            break;
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
                    if depth == 0 {
                        end_pos = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = s[..end_pos].to_string();
        s = &s[end_pos + 1..];

        match parse_rule_body(&name, &tags, &body) {
            Ok(rule) => rules.push(rule),
            Err(e) => errors.push(format!("rule {name}: {e}")),
        }
    }

    (rules, errors)
}

pub(super) fn find_rule_keyword(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    while i + 4 <= b.len() {
        if &b[i..i + 4] == b"rule" {
            let before_ok = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            let after_ok =
                i + 4 >= b.len() || !(b[i + 4].is_ascii_alphanumeric() || b[i + 4] == b'_');
            if before_ok && after_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

pub(super) fn parse_rule_body(name: &str, tags: &[String], body: &str) -> Result<YaraRule, String> {
    let mut description = String::new();
    let mut strings = Vec::new();
    let mut condition = Condition::True;

    // State machine over lines — split into sections by "meta:" / "strings:" / "condition:"
    let mut section = "";
    let mut buf = String::new();

    for line in body.lines() {
        let t = line.trim();
        match t {
            "meta:" => {
                flush_section(
                    section,
                    &buf,
                    &mut description,
                    &mut strings,
                    &mut condition,
                )?;
                buf.clear();
                section = "meta";
            }
            "strings:" => {
                flush_section(
                    section,
                    &buf,
                    &mut description,
                    &mut strings,
                    &mut condition,
                )?;
                buf.clear();
                section = "strings";
            }
            "condition:" => {
                flush_section(
                    section,
                    &buf,
                    &mut description,
                    &mut strings,
                    &mut condition,
                )?;
                buf.clear();
                section = "condition";
            }
            "" => {}
            _ => {
                buf.push_str(t);
                buf.push('\n');
            }
        }
    }
    if !buf.is_empty() {
        flush_section(
            section,
            &buf,
            &mut description,
            &mut strings,
            &mut condition,
        )?;
    }

    Ok(YaraRule {
        name: name.to_string(),
        description,
        tags: tags.to_vec(),
        strings,
        condition,
    })
}

pub(super) fn flush_section(
    section: &str,
    buf: &str,
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
                if t.is_empty() {
                    continue;
                }
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

pub(super) fn parse_string_def(line: &str) -> Result<YaraString, String> {
    // $name = "literal" [nocase]
    // $name = { HH ?? HH } [nocase]
    let mut parts = line.splitn(2, '=');
    let name = parts.next().unwrap_or("").trim().to_string();
    let rhs = parts
        .next()
        .ok_or_else(|| format!("missing = in: {line}"))?
        .trim();

    if !name.starts_with('$') {
        return Err(format!("string name must start with $: {name}"));
    }

    let nocase = rhs.contains("nocase");

    let kind = if rhs.starts_with('"') {
        // Literal string
        let inner = &rhs[1..];
        let end = inner
            .find('"')
            .ok_or_else(|| format!("unterminated string: {line}"))?;
        StringKind::Literal(unescape_str(&inner[..end]))
    } else if rhs.starts_with('{') {
        // Hex pattern
        let end = rhs
            .find('}')
            .ok_or_else(|| format!("unterminated hex: {line}"))?;
        let hex_str = &rhs[1..end];
        let mut pat = Vec::new();
        for tok in hex_str.split_whitespace() {
            // Skip alternation/grouping tokens
            if tok == "|" || tok == "(" || tok == ")" {
                continue;
            }
            if tok == "??" || tok == "?" {
                pat.push(HexByte::Wild);
            } else if tok.len() == 2 {
                let b = u8::from_str_radix(tok, 16)
                    .map_err(|_| format!("bad hex byte '{tok}' in: {line}"))?;
                pat.push(HexByte::Exact(b));
            } else if tok.len() == 1
                && tok
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_hexdigit())
                    .unwrap_or(false)
            {
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

pub(super) fn unescape_str(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('x') => {
                    let h1 = chars.next().and_then(|c| c.to_digit(16));
                    let h2 = chars.next().and_then(|c| c.to_digit(16));
                    if let (Some(h1), Some(h2)) = (h1, h2) {
                        out.push((h1 * 16 + h2) as u8);
                    }
                }
                Some(c) => {
                    out.push(b'\\');
                    out.extend(c.to_string().as_bytes());
                }
                None => {}
            }
        } else {
            out.extend(c.to_string().as_bytes());
        }
    }
    out
}

pub(super) fn parse_condition(cond: &str) -> Condition {
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
        let end = t
            .find(|c: char| c.is_whitespace() || c == ')')
            .unwrap_or(t.len());
        Condition::Ref(t[..end].to_string())
    } else {
        // Complex conditions (uint comparisons, etc.) — default to any
        Condition::AnyOfThem
    }
}

pub(super) fn strip_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}
