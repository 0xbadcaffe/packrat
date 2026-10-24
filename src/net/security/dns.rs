use super::*;

impl SecurityEngine {
    // ─── DNS Exfiltration Scoring ─────────────────────────────────────────────

    pub(super) fn check_dns_tunnel(&mut self, pkt: &Packet) {
        let dst_port = pkt.dst_port.unwrap_or(0);
        let src_port = pkt.src_port.unwrap_or(0);
        if dst_port != 53 && src_port != 53 && !pkt.protocol.eq_ignore_ascii_case("DNS") {
            return;
        }

        // Parse domain from info string formats:
        // "Query 0xXXXX A sub.domain.com"
        // "Response A 1.2.3.4"
        // "Standard query 0xXXXX A hostname.example.com"
        let domain = match Self::extract_dns_domain(&pkt.info) {
            Some(d) => d,
            None => return,
        };

        let (subdomain, apex) = Self::split_apex(&domain);

        if apex.is_empty() {
            return;
        }

        // Compute subdomain entropy
        let sub_entropy = if subdomain.is_empty() {
            0.0
        } else {
            shannon_entropy(subdomain.as_bytes())
        };

        let sub_len = subdomain.len();

        let acc = self.dns_accum.entry(apex.clone()).or_insert(DnsAccum {
            queries: 0,
            max_entropy: 0.0,
            max_len: 0,
            unique_subs: std::collections::HashSet::new(),
        });
        acc.queries += 1;
        if sub_entropy > acc.max_entropy {
            acc.max_entropy = sub_entropy;
        }
        if sub_len > acc.max_len {
            acc.max_len = sub_len;
        }
        if !subdomain.is_empty() {
            acc.unique_subs.insert(subdomain.clone());
        }

        let score = (acc.queries as f64 / 10.0) + acc.max_entropy + (acc.max_len as f64 / 10.0);

        // Update or insert in dns_suspects
        if let Some(existing) = self.dns_suspects.iter_mut().find(|d| d.apex == apex) {
            existing.query_count = acc.queries;
            existing.max_entropy = acc.max_entropy;
            existing.max_subdomain_len = acc.max_len;
            existing.unique_subdomains = acc.unique_subs.len();
            existing.score = score;
        } else {
            if self.dns_suspects.len() >= MAX_ENTRIES {
                self.dns_suspects.remove(0);
            }
            self.dns_suspects.push(DnsTunnelSuspect {
                apex: apex.clone(),
                query_count: acc.queries,
                max_entropy: acc.max_entropy,
                max_subdomain_len: acc.max_len,
                unique_subdomains: acc.unique_subs.len(),
                score,
            });
        }
    }

    pub(super) fn extract_dns_domain(info: &str) -> Option<String> {
        // Patterns: "Query 0xXXXX A domain", "Standard query 0xXXXX A domain", "Response A domain"
        let lower = info.to_lowercase();
        let words: Vec<&str> = info.split_whitespace().collect();
        // Find a word that looks like a domain (contains a dot, doesn't start with digit for pure IP)
        // Strategy: scan words backwards for a domain-like token
        for word in words.iter().rev() {
            let w = word.trim_end_matches('.');
            if w.contains('.') && !w.starts_with(|c: char| c.is_ascii_digit()) {
                // Skip version-like strings
                if lower.contains("response") && w.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                return Some(w.to_lowercase());
            }
        }
        None
    }

    /// Split "sub.domain.example.com" → ("sub.domain", "example.com")
    pub(super) fn split_apex(domain: &str) -> (String, String) {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() <= 2 {
            return (String::new(), domain.to_string());
        }
        let apex = parts[parts.len() - 2..].join(".");
        let subdomain = parts[..parts.len() - 2].join(".");
        (subdomain, apex)
    }

    // ─── Byte pattern helpers ─────────────────────────────────────────────────

    pub(super) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    pub(super) fn contains_str_ci(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    }

    pub(super) fn nop_sled_16(data: &[u8]) -> bool {
        let mut run = 0usize;
        for &b in data {
            if b == 0x90 {
                run += 1;
                if run >= 16 {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        false
    }

    pub(super) fn count_pattern_ascii(data: &[u8], pattern: &[u8]) -> usize {
        if pattern.is_empty() || data.len() < pattern.len() {
            return 0;
        }
        data.windows(pattern.len())
            .filter(|w| *w == pattern)
            .count()
    }

    pub(super) fn ascii_payload(bytes: &[u8], offset: usize) -> String {
        if bytes.len() <= offset {
            return String::new();
        }
        bytes[offset..]
            .iter()
            .map(|&b| {
                if b.is_ascii() && (b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t') {
                    b as char
                } else {
                    '.'
                }
            })
            .collect()
    }
}
