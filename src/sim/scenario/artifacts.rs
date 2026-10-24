use super::*;

/// Carved objects to pre-seed in the Objects tab.
pub fn carved_objects() -> Vec<crate::analysis::carving::CarvedObject> {
    use crate::analysis::carving::CarvedObject;
    // Minimal realistic magic-byte prefixes so the type is recognisable.
    vec![
        CarvedObject {
            id: 1,
            kind: "application/exe".into(),
            name: "evil.exe (from SMB stream to \\\\intranet\\C$)".into(),
            source: "smb:192.168.1.50:49403-192.168.1.20:445".into(),
            offset: 0,
            data: {
                let mut v = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
                v.extend(vec![0u8; 512]);
                v
            },
            sha256: "4a5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d".into(),
            yara_hits: vec![
                "Trojan.CobaltStrike.Beacon".into(),
                "Malware.Generic.PE".into(),
            ],
        },
        CarvedObject {
            id: 2,
            kind: "application/elf".into(),
            name: "backdoor.elf (from TCP stream 203.0.113.7:4444)".into(),
            source: "tcp:192.168.1.50:50000-203.0.113.7:4444".into(),
            offset: 128,
            data: {
                let mut v = b"\x7fELF\x02\x01\x01\x00".to_vec();
                v.extend(vec![0u8; 768]);
                v
            },
            sha256: "7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c".into(),
            yara_hits: vec!["Linux.Backdoor.Mirai".into()],
        },
        CarvedObject {
            id: 3,
            kind: "application/pdf".into(),
            name: "invoice_Q4.pdf (from HTTP GET /docs)".into(),
            source: "http:192.168.1.50:49152-192.168.1.20:80".into(),
            offset: 0,
            data: {
                let mut v = b"%PDF-1.4\n".to_vec();
                v.extend(vec![0u8; 4096]);
                v.extend(b"%%EOF");
                v
            },
            sha256: "1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d".into(),
            yara_hits: vec![],
        },
        CarvedObject {
            id: 4,
            kind: "application/zip".into(),
            name: "tools.zip (from FTP RETR)".into(),
            source: "ftp:192.168.1.50:49200-192.168.1.30:21".into(),
            offset: 0,
            data: {
                let mut v = b"PK\x03\x04\x14\x00\x00\x00".to_vec();
                v.extend(vec![0u8; 2048]);
                v
            },
            sha256: "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b".into(),
            yara_hits: vec!["Suspicious.ArchiveTool".into()],
        },
        CarvedObject {
            id: 5,
            kind: "image/png".into(),
            name: "screenshot_2024.png (from HTTP response)".into(),
            source: "http:192.168.1.20:80-192.168.1.50:49153".into(),
            offset: 0,
            data: {
                let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
                v.extend(vec![0u8; 1024]);
                v
            },
            sha256: "3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e".into(),
            yara_hits: vec![],
        },
    ]
}

/// Detection rules to load into the rule engine (seeded rules + pre-fired hits).
pub fn rules() -> Vec<(crate::analysis::rules::Rule, u64)> {
    use crate::analysis::rules::{Action, CmpOp, Condition, Rule};
    use crate::model::evidence::Severity;
    vec![
        (
            Rule {
                id: "rule-001".into(),
                name: "C2 Beacon Detection".into(),
                description: "TCP PSH/ACK to known C2 port 4444 at regular intervals".into(),
                enabled: true,
                auto_contain: false,
                hits: 30,
                condition: Condition::And(vec![
                    Condition::Equals {
                        field: "proto".into(),
                        value: "TCP".into(),
                    },
                    Condition::Num {
                        field: "dstport".into(),
                        op: CmpOp::Eq,
                        value: 4444,
                    },
                ]),
                actions: vec![Action::Alert {
                    message: "C2 beacon to port 4444".into(),
                    severity: Severity::Critical,
                }],
            },
            30,
        ),
        (
            Rule {
                id: "rule-002".into(),
                name: "DNS Tunnel Detection".into(),
                description: "High-entropy subdomain queries indicative of DNS tunnelling".into(),
                enabled: true,
                auto_contain: false,
                hits: 5,
                condition: Condition::And(vec![
                    Condition::Equals {
                        field: "proto".into(),
                        value: "DNS".into(),
                    },
                    Condition::Contains {
                        field: "info".into(),
                        value: "evil-tunnel.com".into(),
                    },
                ]),
                actions: vec![
                    Action::Alert {
                        message: "DNS tunnel query detected".into(),
                        severity: Severity::High,
                    },
                    Action::Tag {
                        tag: "dns-tunnel".into(),
                    },
                ],
            },
            5,
        ),
        (
            Rule {
                id: "rule-003".into(),
                name: "Cleartext HTTP Credentials".into(),
                description: "HTTP Authorization header in plaintext (port 80)".into(),
                enabled: true,
                auto_contain: false,
                hits: 2,
                condition: Condition::And(vec![
                    Condition::Equals {
                        field: "proto".into(),
                        value: "HTTP".into(),
                    },
                    Condition::Contains {
                        field: "info".into(),
                        value: "Authorization".into(),
                    },
                ]),
                actions: vec![
                    Action::Alert {
                        message: "Cleartext credential in HTTP".into(),
                        severity: Severity::High,
                    },
                    Action::Log {
                        message: "Credential exposure — upgrade to HTTPS".into(),
                    },
                ],
            },
            2,
        ),
        (
            Rule {
                id: "rule-004".into(),
                name: "Kerberos AS-REQ Spray".into(),
                description: "Repeated Kerberos pre-auth requests — password spray indicator"
                    .into(),
                enabled: true,
                auto_contain: false,
                hits: 5,
                condition: Condition::And(vec![
                    Condition::Equals {
                        field: "proto".into(),
                        value: "Kerberos".into(),
                    },
                    Condition::Contains {
                        field: "info".into(),
                        value: "AS-REQ".into(),
                    },
                ]),
                actions: vec![Action::Alert {
                    message: "Kerberos spray attempt".into(),
                    severity: Severity::High,
                }],
            },
            5,
        ),
        (
            Rule {
                id: "rule-005".into(),
                name: "SMB Admin Share Access".into(),
                description: "Connection to administrative C$ or ADMIN$ share".into(),
                enabled: true,
                auto_contain: false,
                hits: 1,
                condition: Condition::And(vec![
                    Condition::Equals {
                        field: "proto".into(),
                        value: "SMB".into(),
                    },
                    Condition::Contains {
                        field: "info".into(),
                        value: "C$".into(),
                    },
                ]),
                actions: vec![
                    Action::Alert {
                        message: "Lateral movement via SMB admin share".into(),
                        severity: Severity::Critical,
                    },
                    Action::Tag {
                        tag: "lateral-movement".into(),
                    },
                ],
            },
            1,
        ),
        (
            Rule {
                id: "rule-006".into(),
                name: "FTP Cleartext Password".into(),
                description: "FTP PASS command containing plaintext password".into(),
                enabled: true,
                auto_contain: false,
                hits: 1,
                condition: Condition::And(vec![
                    Condition::Equals {
                        field: "proto".into(),
                        value: "FTP".into(),
                    },
                    Condition::Contains {
                        field: "info".into(),
                        value: "PASS".into(),
                    },
                ]),
                actions: vec![Action::Alert {
                    message: "Cleartext FTP credential".into(),
                    severity: Severity::Medium,
                }],
            },
            1,
        ),
        (
            Rule {
                id: "rule-007".into(),
                name: "OT Protocol Access (Modbus)".into(),
                description: "Modbus traffic to ICS/SCADA devices — monitor for anomalies".into(),
                enabled: true,
                auto_contain: false,
                hits: 1,
                condition: Condition::Equals {
                    field: "proto".into(),
                    value: "Modbus".into(),
                },
                actions: vec![Action::Log {
                    message: "Modbus FC3 register read — verify source is authorised".into(),
                }],
            },
            1,
        ),
        (
            Rule {
                id: "rule-008".into(),
                name: "Large Frame Anomaly".into(),
                description: "Frames above 8KB may indicate data exfiltration or exploit".into(),
                enabled: false,
                auto_contain: false,
                hits: 0,
                condition: Condition::Num {
                    field: "len".into(),
                    op: CmpOp::Gt,
                    value: 8192,
                },
                actions: vec![Action::Alert {
                    message: "Oversized frame".into(),
                    severity: Severity::Low,
                }],
            },
            0,
        ),
    ]
}

/// Return the IOC IP list for the scenario (seeded into IocEngine on startup).
pub fn ioc_ips() -> Vec<&'static str> {
    vec![C2, "203.0.113.99", "198.51.100.7"]
}

/// Canonical scenario analyst notes to pre-populate Notebook.
pub fn notebook_notes() -> Vec<(&'static str, Option<&'static str>)> {
    vec![
        (
            "C2 IP 203.0.113.7 confirmed via DNS lookup correlation",
            Some("pkt#3"),
        ),
        (
            "DNS tunnel detected: high-entropy subdomains to evil-tunnel.com",
            Some("pkt#5"),
        ),
        (
            "Cleartext credentials extracted from HTTP POST to intranet",
            Some("pkt#8"),
        ),
        (
            "TLS RC4 cipher suite to C2 — known-weak, pre-TLS1.2",
            Some("pkt#41"),
        ),
        (
            "Kerberos AS-REQ spray: 5 accounts tried in < 1s",
            Some("pkt#50"),
        ),
        (
            "SMB lateral movement to 192.168.1.20 — accessed C$ share",
            Some("pkt#57"),
        ),
    ]
}

/// Host tags to pre-seed.
pub fn host_tags() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (VICTIM, vec!["compromised", "victim", "priority-1"]),
        (C2, vec!["c2", "ioc", "threat-actor"]),
        (INTRA_A, vec!["lateral-movement-target"]),
        (GATEWAY, vec!["infrastructure"]),
    ]
}
