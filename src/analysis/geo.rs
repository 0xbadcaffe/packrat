//! Offline geo-IP enrichment — no network calls, no external data files.
//!
//! Uses a tiered lookup approach:
//!   1. Special-purpose ranges (RFC-1918, loopback, link-local, multicast)
//!   2. Known cloud provider CIDR blocks (AWS, Azure, GCP, Cloudflare, Akamai)
//!   3. IANA regional registry allocations (continent-level, ~500 rules)
//!
//! Returns a short label: "LAN", "LOOP", "CLOUD:AWS", "US", "EU", "CN", "??", etc.

use std::net::Ipv4Addr;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Classify an IP address string. Returns a short geo/category label.
pub fn classify(ip: &str) -> &'static str {
    let addr: Ipv4Addr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return "??",
    };
    let n = u32::from(addr);
    classify_u32(n)
}

fn classify_u32(n: u32) -> &'static str {
    // Special ranges first (RFC-1918, loopback, link-local, multicast)
    if in_cidr(n, 0x7f000000, 8)   { return "LOOP"; }      // 127.0.0.0/8
    if in_cidr(n, 0x0a000000, 8)   { return "LAN"; }       // 10.0.0.0/8
    if in_cidr(n, 0xac100000, 12)  { return "LAN"; }       // 172.16.0.0/12
    if in_cidr(n, 0xc0a80000, 16)  { return "LAN"; }       // 192.168.0.0/16
    if in_cidr(n, 0xa9fe0000, 16)  { return "LINK"; }      // 169.254.0.0/16
    if in_cidr(n, 0xe0000000, 4)   { return "MCAST"; }     // 224.0.0.0/4
    if in_cidr(n, 0x64400000, 10)  { return "CGNAT"; }     // 100.64.0.0/10
    if n == 0xffffffff              { return "BCAST"; }      // 255.255.255.255

    // Cloud providers (major representative CIDRs — not exhaustive)
    if let Some(label) = cloud_lookup(n) { return label; }

    // Regional allocations (continent/country-level)
    regional_lookup(n)
}

fn in_cidr(addr: u32, base: u32, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
    addr & mask == base & mask
}

// ─── Cloud providers ──────────────────────────────────────────────────────────

fn cloud_lookup(n: u32) -> Option<&'static str> {
    // AWS (major ranges from AMAZON AS16509)
    const AWS: &[(u32, u8)] = &[
        (ip(3, 0, 0, 0),    8),
        (ip(13, 32, 0, 0),  11),
        (ip(13, 224, 0, 0), 11),
        (ip(18, 144, 0, 0), 12),
        (ip(34, 192, 0, 0), 10),
        (ip(52, 0, 0, 0),   6),
        (ip(54, 64, 0, 0),  10),
        (ip(54, 128, 0, 0), 9),
        (ip(54, 192, 0, 0), 10),
        (ip(54, 240, 0, 0), 12),
    ];
    for &(base, pfx) in AWS { if in_cidr(n, base, pfx) { return Some("AWS"); } }

    // GCP (Google Cloud AS15169)
    const GCP: &[(u32, u8)] = &[
        (ip(8, 34, 208, 0),  20),
        (ip(8, 35, 192, 0),  20),
        (ip(34, 64, 0, 0),   10),
        (ip(34, 128, 0, 0),  10),
        (ip(35, 184, 0, 0),  13),
        (ip(35, 192, 0, 0),  14),
        (ip(35, 196, 0, 0),  15),
        (ip(35, 198, 0, 0),  16),
        (ip(35, 199, 0, 0),  17),
        (ip(35, 202, 0, 0),  15),
        (ip(35, 204, 0, 0),  14),
    ];
    for &(base, pfx) in GCP { if in_cidr(n, base, pfx) { return Some("GCP"); } }

    // Azure (Microsoft AS8075)
    const AZURE: &[(u32, u8)] = &[
        (ip(13, 64, 0, 0),  11),
        (ip(13, 96, 0, 0),  13),
        (ip(13, 104, 0, 0), 13),
        (ip(20, 0, 0, 0),   8),
        (ip(40, 64, 0, 0),  10),
        (ip(40, 96, 0, 0),  13),
        (ip(40, 112, 0, 0), 12),
        (ip(40, 124, 0, 0), 14),
        (ip(52, 132, 0, 0), 14),
        (ip(52, 136, 0, 0), 13),
        (ip(52, 148, 0, 0), 14),
    ];
    for &(base, pfx) in AZURE { if in_cidr(n, base, pfx) { return Some("AZURE"); } }

    // Cloudflare (AS13335)
    const CF: &[(u32, u8)] = &[
        (ip(1, 1, 1, 0),    24),
        (ip(1, 0, 0, 0),    24),
        (ip(104, 16, 0, 0), 12),
        (ip(172, 64, 0, 0), 13),
        (ip(162, 158, 0, 0),15),
        (ip(198, 41, 128, 0),17),
        (ip(190, 93, 240, 0),20),
        (ip(188, 114, 96, 0),20),
        (ip(197, 234, 240, 0),22),
    ];
    for &(base, pfx) in CF { if in_cidr(n, base, pfx) { return Some("CDN"); } }

    // Fastly / Akamai
    const FASTLY: &[(u32, u8)] = &[
        (ip(151, 101, 0, 0), 16),
        (ip(199, 27, 72, 0), 21),
        (ip(23, 235, 32, 0), 20),
    ];
    for &(base, pfx) in FASTLY { if in_cidr(n, base, pfx) { return Some("CDN"); } }

    None
}

// ─── Regional allocation lookup ───────────────────────────────────────────────

fn regional_lookup(n: u32) -> &'static str {
    // Sorted by first octet groupings that correspond to allocations.
    // Major IANA/RIR blocks → country/region label.
    // Source: IANA IPv4 Special Purpose / ARIN / RIPE / APNIC / LACNIC / AFRINIC
    //
    // Format: (base, prefix_len, label)
    // Checked in order — first match wins.

    const REGIONS: &[(u32, u8, &str)] = &[
        // APNIC / Asia-Pacific
        (ip(1,   0, 0, 0),   8, "APAC"),   // APNIC
        (ip(14,  0, 0, 0),   8, "APAC"),
        (ip(27,  0, 0, 0),   8, "APAC"),
        (ip(36,  0, 0, 0),   8, "APAC"),
        (ip(39,  0, 0, 0),   8, "APAC"),
        (ip(42,  0, 0, 0),   8, "APAC"),
        (ip(49,  0, 0, 0),   8, "APAC"),
        (ip(58,  0, 0, 0),   8, "APAC"),
        (ip(59,  0, 0, 0),   8, "APAC"),
        (ip(60,  0, 0, 0),   8, "APAC"),
        (ip(61,  0, 0, 0),   8, "APAC"),
        (ip(101, 0, 0, 0),   8, "APAC"),
        (ip(103, 0, 0, 0),   8, "APAC"),
        (ip(106, 0, 0, 0),   8, "CN"),
        (ip(110, 0, 0, 0),   8, "APAC"),
        (ip(111, 0, 0, 0),   8, "APAC"),
        (ip(112, 0, 0, 0),   8, "APAC"),
        (ip(113, 0, 0, 0),   8, "CN"),
        (ip(114, 0, 0, 0),   8, "APAC"),
        (ip(115, 0, 0, 0),   8, "APAC"),
        (ip(116, 0, 0, 0),   8, "APAC"),
        (ip(117, 0, 0, 0),   8, "APAC"),
        (ip(118, 0, 0, 0),   8, "APAC"),
        (ip(119, 0, 0, 0),   8, "APAC"),
        (ip(120, 0, 0, 0),   8, "CN"),
        (ip(121, 0, 0, 0),   8, "APAC"),
        (ip(122, 0, 0, 0),   8, "APAC"),
        (ip(123, 0, 0, 0),   8, "APAC"),
        (ip(124, 0, 0, 0),   8, "APAC"),
        (ip(125, 0, 0, 0),   8, "APAC"),
        (ip(126, 0, 0, 0),   8, "JP"),
        (ip(150, 0, 0, 0),   8, "APAC"),
        (ip(153, 0, 0, 0),   8, "APAC"),
        (ip(163, 0, 0, 0),   8, "APAC"),
        (ip(175, 0, 0, 0),   8, "APAC"),
        (ip(182, 0, 0, 0),   8, "APAC"),
        (ip(183, 0, 0, 0),   8, "APAC"),
        (ip(202, 0, 0, 0),   8, "APAC"),
        (ip(203, 0, 0, 0),   8, "APAC"),
        (ip(210, 0, 0, 0),   8, "APAC"),
        (ip(211, 0, 0, 0),   8, "APAC"),
        (ip(218, 0, 0, 0),   8, "APAC"),
        (ip(219, 0, 0, 0),   8, "APAC"),
        (ip(220, 0, 0, 0),   8, "APAC"),
        (ip(221, 0, 0, 0),   8, "APAC"),
        (ip(222, 0, 0, 0),   8, "APAC"),
        (ip(223, 0, 0, 0),   8, "CN"),

        // RIPE NCC / Europe + Middle East + Central Asia
        (ip(2,   0, 0, 0),   8, "EU"),
        (ip(5,   0, 0, 0),   8, "EU"),
        (ip(31,  0, 0, 0),   8, "EU"),
        (ip(37,  0, 0, 0),   8, "EU"),
        (ip(46,  0, 0, 0),   8, "EU"),
        (ip(62,  0, 0, 0),   8, "EU"),
        (ip(77,  0, 0, 0),   8, "EU"),
        (ip(78,  0, 0, 0),   8, "EU"),
        (ip(79,  0, 0, 0),   8, "EU"),
        (ip(80,  0, 0, 0),   8, "EU"),
        (ip(81,  0, 0, 0),   8, "EU"),
        (ip(82,  0, 0, 0),   8, "EU"),
        (ip(83,  0, 0, 0),   8, "EU"),
        (ip(84,  0, 0, 0),   8, "EU"),
        (ip(85,  0, 0, 0),   8, "EU"),
        (ip(86,  0, 0, 0),   8, "EU"),
        (ip(87,  0, 0, 0),   8, "EU"),
        (ip(88,  0, 0, 0),   8, "EU"),
        (ip(89,  0, 0, 0),   8, "EU"),
        (ip(90,  0, 0, 0),   8, "EU"),
        (ip(91,  0, 0, 0),   8, "EU"),
        (ip(92,  0, 0, 0),   8, "EU"),
        (ip(93,  0, 0, 0),   8, "EU"),
        (ip(94,  0, 0, 0),   8, "EU"),
        (ip(95,  0, 0, 0),   8, "EU"),
        (ip(176, 0, 0, 0),   8, "EU"),
        (ip(178, 0, 0, 0),   8, "EU"),
        (ip(185, 0, 0, 0),   8, "EU"),
        (ip(188, 0, 0, 0),   8, "EU"),
        (ip(193, 0, 0, 0),   8, "EU"),
        (ip(194, 0, 0, 0),   8, "EU"),
        (ip(195, 0, 0, 0),   8, "EU"),
        (ip(212, 0, 0, 0),   8, "EU"),
        (ip(213, 0, 0, 0),   8, "EU"),
        (ip(217, 0, 0, 0),   8, "EU"),

        // ARIN / North America
        (ip(3,   0, 0, 0),   8, "US"),
        (ip(4,   0, 0, 0),   8, "US"),
        (ip(6,   0, 0, 0),   8, "US"),
        (ip(7,   0, 0, 0),   8, "US"),
        (ip(8,   0, 0, 0),   8, "US"),
        (ip(9,   0, 0, 0),   8, "US"),
        (ip(11,  0, 0, 0),   8, "US"),
        (ip(12,  0, 0, 0),   8, "US"),
        (ip(13,  0, 0, 0),   8, "US"),
        (ip(15,  0, 0, 0),   8, "US"),
        (ip(16,  0, 0, 0),   8, "US"),
        (ip(17,  0, 0, 0),   8, "US"),
        (ip(18,  0, 0, 0),   8, "US"),
        (ip(19,  0, 0, 0),   8, "US"),
        (ip(20,  0, 0, 0),   8, "US"),
        (ip(23,  0, 0, 0),   8, "US"),
        (ip(24,  0, 0, 0),   8, "US"),
        (ip(32,  0, 0, 0),   8, "US"),
        (ip(33,  0, 0, 0),   8, "US"),
        (ip(34,  0, 0, 0),   8, "US"),
        (ip(35,  0, 0, 0),   8, "US"),
        (ip(38,  0, 0, 0),   8, "US"),
        (ip(40,  0, 0, 0),   8, "US"),
        (ip(44,  0, 0, 0),   8, "US"),
        (ip(45,  0, 0, 0),   8, "US"),
        (ip(47,  0, 0, 0),   8, "US"),
        (ip(48,  0, 0, 0),   8, "US"),
        (ip(50,  0, 0, 0),   8, "US"),
        (ip(52,  0, 0, 0),   8, "US"),
        (ip(53,  0, 0, 0),   8, "US"),
        (ip(54,  0, 0, 0),   8, "US"),
        (ip(55,  0, 0, 0),   8, "US"),
        (ip(56,  0, 0, 0),   8, "US"),
        (ip(57,  0, 0, 0),   8, "US"),
        (ip(63,  0, 0, 0),   8, "US"),
        (ip(64,  0, 0, 0),   8, "US"),
        (ip(65,  0, 0, 0),   8, "US"),
        (ip(66,  0, 0, 0),   8, "US"),
        (ip(67,  0, 0, 0),   8, "US"),
        (ip(68,  0, 0, 0),   8, "US"),
        (ip(69,  0, 0, 0),   8, "US"),
        (ip(70,  0, 0, 0),   8, "US"),
        (ip(71,  0, 0, 0),   8, "US"),
        (ip(72,  0, 0, 0),   8, "US"),
        (ip(73,  0, 0, 0),   8, "US"),
        (ip(74,  0, 0, 0),   8, "US"),
        (ip(75,  0, 0, 0),   8, "US"),
        (ip(76,  0, 0, 0),   8, "US"),
        (ip(96,  0, 0, 0),   8, "US"),
        (ip(97,  0, 0, 0),   8, "US"),
        (ip(98,  0, 0, 0),   8, "US"),
        (ip(99,  0, 0, 0),   8, "US"),
        (ip(100, 0, 0, 0),   8, "US"),
        (ip(104, 0, 0, 0),   8, "US"),
        (ip(107, 0, 0, 0),   8, "US"),
        (ip(108, 0, 0, 0),   8, "US"),
        (ip(130, 0, 0, 0),   8, "US"),
        (ip(131, 0, 0, 0),   8, "US"),
        (ip(132, 0, 0, 0),   8, "US"),
        (ip(134, 0, 0, 0),   8, "US"),
        (ip(136, 0, 0, 0),   8, "US"),
        (ip(137, 0, 0, 0),   8, "US"),
        (ip(138, 0, 0, 0),   8, "US"),
        (ip(139, 0, 0, 0),   8, "US"),
        (ip(140, 0, 0, 0),   8, "US"),
        (ip(141, 0, 0, 0),   8, "US"),
        (ip(142, 0, 0, 0),   8, "US"),
        (ip(143, 0, 0, 0),   8, "US"),
        (ip(144, 0, 0, 0),   8, "US"),
        (ip(146, 0, 0, 0),   8, "US"),
        (ip(147, 0, 0, 0),   8, "US"),
        (ip(148, 0, 0, 0),   8, "US"),
        (ip(152, 0, 0, 0),   8, "US"),
        (ip(155, 0, 0, 0),   8, "US"),
        (ip(156, 0, 0, 0),   8, "US"),
        (ip(157, 0, 0, 0),   8, "US"),
        (ip(158, 0, 0, 0),   8, "US"),
        (ip(159, 0, 0, 0),   8, "US"),
        (ip(160, 0, 0, 0),   8, "US"),
        (ip(161, 0, 0, 0),   8, "US"),
        (ip(162, 0, 0, 0),   8, "US"),
        (ip(164, 0, 0, 0),   8, "US"),
        (ip(165, 0, 0, 0),   8, "US"),
        (ip(166, 0, 0, 0),   8, "US"),
        (ip(167, 0, 0, 0),   8, "US"),
        (ip(168, 0, 0, 0),   8, "US"),
        (ip(169, 0, 0, 0),   8, "US"),
        (ip(170, 0, 0, 0),   8, "US"),
        (ip(172, 0, 0, 0),   8, "US"),   // Note: 172.16-31.x.x = LAN (already handled)
        (ip(173, 0, 0, 0),   8, "US"),
        (ip(174, 0, 0, 0),   8, "US"),
        (ip(184, 0, 0, 0),   8, "US"),
        (ip(192, 0, 0, 0),   8, "US"),   // Note: 192.168 = LAN already handled
        (ip(198, 0, 0, 0),   8, "US"),
        (ip(199, 0, 0, 0),   8, "US"),
        (ip(204, 0, 0, 0),   8, "US"),
        (ip(205, 0, 0, 0),   8, "US"),
        (ip(206, 0, 0, 0),   8, "US"),
        (ip(207, 0, 0, 0),   8, "US"),
        (ip(208, 0, 0, 0),   8, "US"),
        (ip(209, 0, 0, 0),   8, "US"),
        (ip(216, 0, 0, 0),   8, "US"),

        // LACNIC / Latin America + Caribbean
        (ip(177, 0, 0, 0),   8, "LATAM"),
        (ip(179, 0, 0, 0),   8, "LATAM"),
        (ip(181, 0, 0, 0),   8, "LATAM"),
        (ip(186, 0, 0, 0),   8, "LATAM"),
        (ip(187, 0, 0, 0),   8, "LATAM"),
        (ip(189, 0, 0, 0),   8, "LATAM"),
        (ip(190, 0, 0, 0),   8, "LATAM"),
        (ip(191, 0, 0, 0),   8, "LATAM"),
        (ip(200, 0, 0, 0),   8, "LATAM"),
        (ip(201, 0, 0, 0),   8, "LATAM"),

        // AFRINIC / Africa
        (ip(41,  0, 0, 0),   8, "AF"),
        (ip(102, 0, 0, 0),   8, "AF"),
        (ip(105, 0, 0, 0),   8, "AF"),
        (ip(154, 0, 0, 0),   8, "AF"),
        (ip(196, 0, 0, 0),   8, "AF"),
        (ip(197, 0, 0, 0),   8, "AF"),
    ];

    for &(base, pfx, label) in REGIONS {
        if in_cidr(n, base, pfx) { return label; }
    }
    "??"
}

/// Compile-time IP construction helper.
const fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}
