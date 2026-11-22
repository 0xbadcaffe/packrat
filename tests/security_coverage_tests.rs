use std::collections::BTreeSet;

use packrat_tui::net::security::DETECTOR_SIGNATURES;

struct CoverageGroup {
    signatures: &'static [&'static str],
    positive_test: &'static str,
}

const COVERAGE: &[CoverageGroup] = &[
    CoverageGroup {
        signatures: &["DNS reply changed at the same resolver"],
        positive_test: "unsupported_dns_answer_changes_remain_low_confidence_wire_findings",
    },
    CoverageGroup {
        signatures: &["DNS answer set changed at the same resolver"],
        positive_test: "reports_only_semantic_changes_for_supported_dns_answers",
    },
    CoverageGroup {
        signatures: &["Malformed IPv4 fragment"],
        positive_test: "detects_malformed_ipv4_fragment_length",
    },
    CoverageGroup {
        signatures: &["Tiny IPv4 fragment", "IPv4 fragment flood"],
        positive_test: "detects_tiny_and_excessive_ipv4_fragments",
    },
    CoverageGroup {
        signatures: &["Conflicting IPv4 fragments"],
        positive_test: "detects_conflicting_ipv4_fragment_overlap",
    },
    CoverageGroup {
        signatures: &["Malformed TCP header", "Illegal TCP flag combination"],
        positive_test: "detects_illegal_and_malformed_tcp_headers",
    },
    CoverageGroup {
        signatures: &["TCP payload after reset"],
        positive_test: "detects_tcp_payload_continuing_after_reset",
    },
    CoverageGroup {
        signatures: &["Conflicting TCP retransmission"],
        positive_test: "detects_conflicting_tcp_retransmission_but_allows_identical_retransmission",
    },
    CoverageGroup {
        signatures: &["TCP stealth scan probe"],
        positive_test: "detects_tcp_stealth_scan_flag_patterns",
    },
    CoverageGroup {
        signatures: &["Vertical port scan", "Horizontal host scan"],
        positive_test: "detects_vertical_and_horizontal_scan_windows",
    },
    CoverageGroup {
        signatures: &["SYN arrival spike"],
        positive_test: "detects_distinct_syn_arrival_spike_within_one_second",
    },
    CoverageGroup {
        signatures: &["ICMP address sweep"],
        positive_test: "detects_icmp_address_sweep",
    },
    CoverageGroup {
        signatures: &["Excessive IPv6 extension headers"],
        positive_test: "detects_excessive_ipv6_extension_header_chain",
    },
    CoverageGroup {
        signatures: &[
            "Invalid IPv6 neighbor discovery hop limit",
            "IPv6 neighbor binding changed",
        ],
        positive_test: "detects_invalid_ipv6_neighbor_discovery_and_binding_change",
    },
    CoverageGroup {
        signatures: &[
            "Invalid IPv6 router advertisement source",
            "IPv6 router advertisement flood",
        ],
        positive_test: "detects_invalid_and_flooded_router_advertisements",
    },
    CoverageGroup {
        signatures: &["STP topology change", "LLDP chassis identity changed"],
        positive_test: "detects_stp_topology_change_and_lldp_identity_change",
    },
    CoverageGroup {
        signatures: &["Periodic fixed-size traffic"],
        positive_test: "detects_periodic_fixed_size_traffic",
    },
    CoverageGroup {
        signatures: &[
            "Large asymmetric outbound transfer",
            "High-entropy outbound transfer",
        ],
        positive_test: "detects_large_high_entropy_outbound_transfer",
    },
    CoverageGroup {
        signatures: &["Direct external DNS resolver use"],
        positive_test: "detects_external_resolver_use",
    },
    CoverageGroup {
        signatures: &["Oversized DNS TXT traffic"],
        positive_test: "large_txt_counts_only_complete_answer_character_strings",
    },
    CoverageGroup {
        signatures: &["DNS NXDOMAIN burst"],
        positive_test: "nxdomain_burst_counts_distinct_matched_names_and_keeps_packet_pairs",
    },
    CoverageGroup {
        signatures: &["Administrative service response fan-out"],
        positive_test: "administrative_fanout_requires_scoped_syn_ack_pairs",
    },
    CoverageGroup {
        signatures: &["NTLM authentication fan-out"],
        positive_test: "ntlm_fanout_requires_smb2_authenticate_and_retains_scoped_evidence",
    },
    CoverageGroup {
        signatures: &["DHCP server identity changed"],
        positive_test: "detects_new_dhcp_server_authority_per_vlan",
    },
    CoverageGroup {
        signatures: &["DHCP client identity burst"],
        positive_test: "detects_dhcp_starvation_identity_burst",
    },
    CoverageGroup {
        signatures: &["Conflicting IPv6 fragments"],
        positive_test: "security_reports_conflicting_ipv6_fragments",
    },
    CoverageGroup {
        signatures: &["IPv6 fragment reassembly rejected"],
        positive_test: "rejects_excessive_ipv6_fragment_count",
    },
    CoverageGroup {
        signatures: &["HTTP request smuggling ambiguity"],
        positive_test: "detects_http_request_smuggling_framing_ambiguities",
    },
    CoverageGroup {
        signatures: &[
            "Critical industrial control command",
            "Industrial state-changing command",
        ],
        positive_test: "ignores_read_only_modbus_and_emits_critical_control_alerts",
    },
    CoverageGroup {
        signatures: &["DNS transaction question mismatch"],
        positive_test: "correlates_matching_transactions_and_rejects_question_substitution",
    },
    CoverageGroup {
        signatures: &["DNS reply without observed query"],
        positive_test: "reply_without_observed_query_is_a_visibility_alert_not_an_incident",
    },
    CoverageGroup {
        signatures: &["DNS reply correlation ambiguous"],
        positive_test: "ambiguous_reply_does_not_consume_candidate_queries",
    },
    CoverageGroup {
        signatures: &["DNS invalid question count"],
        positive_test: "invalid_dns_question_counts_are_reported_but_do_not_enter_correlation",
    },
    CoverageGroup {
        signatures: &[
            "Unexpected DNS responder",
            "Conflicting DNS responses",
        ],
        positive_test: "detects_unexpected_and_competing_responses",
    },
    CoverageGroup {
        signatures: &["SMBv1 server response"],
        positive_test: "legacy_smb_alert_requires_a_complete_successful_server_reply",
    },
    CoverageGroup {
        signatures: &["NBNS WPAD address reply"],
        positive_test: "wpad_finding_requires_a_complete_nbns_address_reply",
    },
    CoverageGroup {
        signatures: &["JNDI label in DNS query"],
        positive_test: "jndi_dns_lead_requires_a_standalone_wire_question_label",
    },
    CoverageGroup {
        signatures: &[
            "Log4Shell (CVE-2021-44228)",
            "Shellcode NOP sled",
            "Directory Traversal",
            "SQL Injection Probe",
            "XSS Probe",
            "Heartbleed (CVE-2014-0160)",
        ],
        positive_test: "shipped_signature_replays",
    },
];

const TEST_SOURCES: &str = concat!(
    include_str!("security_policy_tests.rs"),
    include_str!("security_policy/cases_1.rs"),
    include_str!("security_policy/cases_2.rs"),
    include_str!("security_policy/cases_3.rs"),
    include_str!("security_policy/dhcp_cases.rs"),
    include_str!("security_policy/tcp_reset_cases.rs"),
    include_str!("ipv6_fragment_tests.rs"),
    include_str!("dns_transaction_tests.rs"),
    include_str!("dns_transaction/txt_reply_tests.rs"),
    include_str!("dns_transaction/external_resolver_tests.rs"),
    include_str!("dns_transaction/jndi_label_tests.rs"),
    include_str!("dns_transaction/investigation_tests.rs"),
    include_str!("industrial_policy_tests.rs"),
);

#[test]
fn every_detector_has_positive_and_negative_coverage() {
    assert!(TEST_SOURCES.contains("fn benign_baseline_triggers_no_catalogued_detectors"));
    let catalog: BTreeSet<_> = DETECTOR_SIGNATURES.iter().copied().collect();
    assert_eq!(
        catalog.len(),
        DETECTOR_SIGNATURES.len(),
        "duplicate detector signature"
    );

    let mut covered = BTreeSet::new();
    for group in COVERAGE {
        assert!(
            TEST_SOURCES.contains(&format!("fn {}", group.positive_test)),
            "positive test {} does not exist",
            group.positive_test
        );
        for signature in group.signatures {
            assert!(
                catalog.contains(signature),
                "coverage names unknown detector {signature}"
            );
            assert!(
                covered.insert(*signature),
                "duplicate coverage for {signature}"
            );
        }
    }
    assert_eq!(
        covered, catalog,
        "every detector must declare replay coverage"
    );
}
