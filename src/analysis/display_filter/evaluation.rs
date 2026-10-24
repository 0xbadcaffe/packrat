use super::*;

/// Evaluate a compiled expression against a packet in context.
pub fn eval(expr: &Expr, ctx: &EvalCtx<'_>) -> bool {
    match expr {
        Expr::Proto(p) => {
            ctx.pkt.protocol.to_lowercase() == p.to_lowercase()
                || ctx
                    .pkt
                    .info
                    .to_lowercase()
                    .contains(p.to_lowercase().as_str())
                || ctx.pkt.src.contains(p)
                || ctx.pkt.dst.contains(p)
        }
        Expr::Marked(v) => ctx.marked == *v,
        Expr::HasTag(t) => ctx.tags.iter().any(|tag| tag == t),
        Expr::Not(e) => !eval(e, ctx),
        Expr::And(a, b) => eval(a, ctx) && eval(b, ctx),
        Expr::Or(a, b) => eval(a, ctx) || eval(b, ctx),

        Expr::Contains {
            field,
            pattern,
            regex,
        } => {
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
            let fv_nums = get_field_nums(ctx.pkt, field);
            values.iter().any(|v| match v {
                Value::Str(s) => fv_str.to_lowercase() == s.to_lowercase(),
                Value::Num(n) => fv_nums.iter().any(|f| (f - n).abs() < 0.5),
                Value::Bool(_) => false,
            })
        }

        Expr::Cmp { field, op, value } => match value {
            Value::Str(s) => {
                let fv = get_field_str(ctx.pkt, field);
                cmp_str(&fv, op, s)
            }
            Value::Num(n) => get_field_nums(ctx.pkt, field)
                .iter()
                .any(|fv| cmp_num(*fv, op, *n)),
            Value::Bool(b) => {
                let fv = get_field_bool(ctx.pkt, field);
                match op {
                    CmpOp::Eq => fv == *b,
                    CmpOp::Ne => fv != *b,
                    _ => false,
                }
            }
        },
    }
}

pub(super) fn cmp_str(a: &str, op: &CmpOp, b: &str) -> bool {
    match op {
        CmpOp::Eq => a.to_lowercase() == b.to_lowercase(),
        CmpOp::Ne => a.to_lowercase() != b.to_lowercase(),
        CmpOp::Lt => a < b,
        CmpOp::Gt => a > b,
        CmpOp::Le => a <= b,
        CmpOp::Ge => a >= b,
    }
}

pub(super) fn cmp_num(a: f64, op: &CmpOp, b: f64) -> bool {
    match op {
        CmpOp::Eq => (a - b).abs() < 0.5,
        CmpOp::Ne => (a - b).abs() >= 0.5,
        CmpOp::Lt => a < b,
        CmpOp::Gt => a > b,
        CmpOp::Le => a <= b,
        CmpOp::Ge => a >= b,
    }
}

pub(super) fn get_field_str<'a>(pkt: &'a Packet, field: &str) -> String {
    match field {
        "ip.src" | "ip.addr" => pkt.src.clone(),
        "ip.dst" => pkt.dst.clone(),
        "tcp.srcport" | "udp.srcport" => pkt.src_port.map(|p| p.to_string()).unwrap_or_default(),
        "tcp.dstport" | "udp.dstport" | "tcp.port" | "udp.port" => {
            pkt.dst_port.map(|p| p.to_string()).unwrap_or_default()
        }
        "proto" | "ip.proto" => pkt.protocol.clone(),
        "info" | "frame.info" => pkt.info.clone(),
        "http.host" => extract_http_header(&pkt.info, "Host"),
        "http.method" => pkt.info.split_whitespace().next().unwrap_or("").to_string(),
        "http.uri" | "http.request.uri" => extract_http_uri(&pkt.info),
        "dns.qname" => extract_dns_qname(&pkt.info),
        "tls.sni" | "ssl.sni" => extract_tls_sni(pkt),
        _ => String::new(),
    }
}

pub(super) fn get_field_num(pkt: &Packet, field: &str) -> Option<f64> {
    match field {
        "frame.len" | "frame.length" => Some(pkt.length as f64),
        "tcp.srcport" | "udp.srcport" => pkt.src_port.map(|p| p as f64),
        "tcp.dstport" | "udp.dstport" | "tcp.port" | "udp.port" => pkt.dst_port.map(|p| p as f64),
        "ip.ttl" => Some(pkt.bytes.get(22).copied().unwrap_or(0) as f64),
        "vlan.id" => pkt.vlan_id.map(|v| v as f64),
        "vlan.pcp" => pkt.vlan_pcp.map(|v| v as f64),
        "vlan.dei" => pkt.vlan_dei.map(|v| v as f64),
        "vlan.outer" | "vlan.outer_id" => pkt.outer_vlan_id.map(|v| v as f64),
        "frame.number" => Some(pkt.no as f64),
        _ => None,
    }
}

pub(super) fn get_field_nums(pkt: &Packet, field: &str) -> Vec<f64> {
    match field {
        "tcp.port" | "udp.port" => {
            let mut ports = Vec::new();
            if let Some(p) = pkt.src_port {
                ports.push(p as f64);
            }
            if let Some(p) = pkt.dst_port {
                ports.push(p as f64);
            }
            ports
        }
        _ => get_field_num(pkt, field).into_iter().collect(),
    }
}

pub(super) fn get_field_bool(pkt: &Packet, field: &str) -> bool {
    match field {
        // These would need the notebook context in a real implementation
        "marked" => false,
        "vlan.qinq" => pkt.outer_vlan_id.is_some() && pkt.vlan_id.is_some(),
        _ => false,
    }
}

pub(super) fn extract_http_header(info: &str, header: &str) -> String {
    let target = format!("{}:", header);
    if let Some(pos) = info.find(&target) {
        info[pos + target.len()..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches(',')
            .to_string()
    } else {
        String::new()
    }
}

pub(super) fn extract_http_uri(info: &str) -> String {
    let parts: Vec<&str> = info.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        String::new()
    }
}

pub(super) fn extract_dns_qname(info: &str) -> String {
    // "Query 0x1234 A example.com" or similar
    let parts: Vec<&str> = info.split_whitespace().collect();
    parts
        .iter()
        .find(|&&p| p.contains('.') && !p.starts_with("0x"))
        .map(|&s| s.to_string())
        .unwrap_or_default()
}

pub(super) fn extract_tls_sni(pkt: &Packet) -> String {
    // Try to find SNI in raw bytes (ClientHello extension type 0x0000)
    let bytes = &pkt.bytes;
    if bytes.len() < 54 {
        return String::new();
    }
    // Look for SNI extension type (0x00 0x00) in the TLS handshake
    for i in 54..bytes.len().saturating_sub(5) {
        if bytes[i] == 0x00 && bytes[i + 1] == 0x00 && i + 5 < bytes.len() {
            let len = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
            if i + 5 + len <= bytes.len() {
                let name = std::str::from_utf8(&bytes[i + 5..i + 5 + len]).unwrap_or("");
                if name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    && name.contains('.')
                {
                    return name.to_string();
                }
            }
        }
    }
    String::new()
}
