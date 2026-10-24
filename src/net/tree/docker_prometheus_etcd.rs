use super::*;

pub(super) fn docker(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(33554467u64).wrapping_add(157u64) % 64512u64) as u16),
    );
    let dp = pkt.dst_port.unwrap_or(2375);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: {}",
            sp, dp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf(
                "Destination Port:",
                &format!("{} (Docker API)", dp),
                FieldColor::Yellow,
            ),
        ],
    });
    let endpoints = [
        "/containers/json",
        "/images/json",
        "/networks",
        "/volumes",
        "/containers/{id}/start",
        "/containers/{id}/logs",
        "/_ping",
        "/version",
        "/events",
    ];
    let ep = endpoints[stable(pkt.no, endpoints.len())];
    let methods = ["GET", "POST", "DELETE"];
    let m = methods[stable(pkt.no, methods.len())];
    let sec_field = if pkt.dst_port == Some(2375) || pkt.src_port == Some(2375) {
        tf("Security:", "UNENCRYPTED (plain HTTP)", FieldColor::Red)
    } else {
        tf("Security:", "TLS mutual auth", FieldColor::Green)
    };
    sections.push(TreeSection {
        title: format!("Docker Remote API — {} {}", m, ep),
        expanded: true,
        fields: vec![
            tf("Method:", m, FieldColor::Green),
            tf("Endpoint:", ep, FieldColor::Cyan),
            tf("Version:", "HTTP/1.1", FieldColor::Default),
            tf("Host:", "unix:/var/run/docker.sock", FieldColor::Default),
            tf("API Version:", "v1.43", FieldColor::Yellow),
            sec_field,
        ],
    });
}

pub(super) fn prometheus(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(16777259u64).wrapping_add(158u64) % 64512u64) as u16),
    );
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: 9090",
            sp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf("Destination Port:", "9090 (Prometheus)", FieldColor::Yellow),
        ],
    });
    let paths = [
        "/metrics",
        "/api/v1/query",
        "/api/v1/query_range",
        "/api/v1/targets",
        "/api/v1/alerts",
        "/api/v1/rules",
    ];
    let path = paths[stable(pkt.no, paths.len())];
    let queries = [
        "http_requests_total",
        "node_cpu_seconds_total",
        "go_goroutines",
        "process_resident_memory_bytes",
    ];
    let q = queries[stable(pkt.no, queries.len())];
    sections.push(TreeSection {
        title: format!("Prometheus — GET {}", path),
        expanded: true,
        fields: vec![
            tf("Method:", "GET", FieldColor::Green),
            tf("Path:", path, FieldColor::Cyan),
            tf("Query:", q, FieldColor::Yellow),
            tf("Format:", "OpenMetrics", FieldColor::Default),
        ],
    });
}

pub(super) fn etcd(pkt: &Packet, sections: &mut Vec<TreeSection>) {
    let sp = pkt.src_port.unwrap_or(
        (1024u16 + (pkt.no.wrapping_mul(8388617u64).wrapping_add(159u64) % 64512u64) as u16),
    );
    let dp = pkt.dst_port.unwrap_or(2379);
    sections.push(TreeSection {
        title: format!(
            "Transmission Control Protocol, Src Port: {}, Dst Port: {}",
            sp, dp
        ),
        expanded: false,
        fields: vec![
            tf("Source Port:", &sp.to_string(), FieldColor::Cyan),
            tf(
                "Destination Port:",
                &format!("{} (etcd)", dp),
                FieldColor::Yellow,
            ),
        ],
    });
    let ops = [
        "Range",
        "Put",
        "DeleteRange",
        "Txn",
        "Watch",
        "LeaseGrant",
        "MemberList",
        "Status",
    ];
    let op = ops[stable(pkt.no, ops.len())];
    let keys = [
        "/registry/pods/default",
        "/registry/services",
        "/election/master",
        "/config/app",
    ];
    let key = keys[stable(pkt.no, keys.len())];
    let rev: u64 = (1000u64 + (pkt.no.wrapping_mul(2654435761u64).wrapping_add(160u64) % 99000u64));
    sections.push(TreeSection {
        title: format!("etcd gRPC — {}", op),
        expanded: true,
        fields: vec![
            tf("Operation:", op, FieldColor::Yellow),
            tf("Key:", key, FieldColor::Cyan),
            tf("Revision:", &rev.to_string(), FieldColor::Default),
            tf(
                "Cluster ID:",
                &format!(
                    "0x{:016x}",
                    pkt.no.wrapping_mul(67108859u64).wrapping_add(36u64)
                ),
                FieldColor::Default,
            ),
            tf(
                "Member ID:",
                &format!(
                    "0x{:016x}",
                    pkt.no.wrapping_mul(33554467u64).wrapping_add(37u64)
                ),
                FieldColor::Default,
            ),
        ],
    });
}
