//! NSS/SSLKEYLOGFILE secret ingestion and ClientHello correlation.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_KEY_LOG_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SECRETS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct KeySecret {
    pub label: String,
    pub client_random: String,
    pub secret: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct KeyShelf {
    pub path: Option<PathBuf>,
    pub secrets: HashMap<String, Vec<KeySecret>>,
    pub last_error: Option<String>,
}

impl KeyShelf {
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<usize, String> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .map_err(|error| format!("read key log {}: {error}", path.display()))?;
        let mut text = String::new();
        file.take(MAX_KEY_LOG_BYTES + 1).read_to_string(&mut text)
            .map_err(|error| format!("read key log {}: {error}", path.display()))?;
        if text.len() as u64 > MAX_KEY_LOG_BYTES {
            return Err("Key log exceeds import size limit".into());
        }
        let mut secrets: HashMap<String, Vec<KeySecret>> = HashMap::new();
        let mut count = 0;
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 3 || !is_supported_label(fields[0]) { continue; }
            let client_random = normalize_hex(fields[1])
                .filter(|value| value.len() == 64)
                .ok_or_else(|| format!("invalid client random on key-log line {}", line_no + 1))?;
            let secret = decode_hex(fields[2])
                .ok_or_else(|| format!("invalid secret on key-log line {}", line_no + 1))?;
            if (fields[0] == "CLIENT_RANDOM" && secret.len() != 48)
                || (fields[0] != "CLIENT_RANDOM" && !matches!(secret.len(), 32 | 48)) {
                return Err(format!("invalid secret length on key-log line {}", line_no + 1));
            }
            if let Some(existing) = secrets.get(&client_random)
                .and_then(|entries| entries.iter().find(|entry| entry.label == fields[0])) {
                if existing.secret != secret {
                    return Err(format!("conflicting secret on key-log line {}", line_no + 1));
                }
                continue;
            }
            if count >= MAX_SECRETS { return Err("Key log exceeds secret count limit".into()); }
            secrets.entry(client_random.clone()).or_default().push(KeySecret {
                label: fields[0].into(),
                client_random,
                secret,
            });
            count += 1;
        }
        self.path = Some(path.to_path_buf());
        self.secrets = secrets;
        self.last_error = None;
        Ok(count)
    }

    pub fn reload(&mut self) -> Result<usize, String> {
        let path = self.path.clone().ok_or("no key-log path configured")?;
        self.load(path)
    }

    pub fn has_client_random(&self, client_random: &str) -> bool {
        self.secrets.contains_key(&client_random.to_ascii_lowercase())
    }

    pub fn secret_count(&self) -> usize {
        self.secrets.values().map(Vec::len).sum()
    }
}

fn is_supported_label(label: &str) -> bool {
    matches!(
        label,
        "CLIENT_RANDOM"
            | "CLIENT_EARLY_TRAFFIC_SECRET"
            | "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
            | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
            | "CLIENT_TRAFFIC_SECRET_0"
            | "SERVER_TRAFFIC_SECRET_0"
            | "EXPORTER_SECRET"
            | "EARLY_EXPORTER_SECRET"
            | "QUIC_CLIENT_EARLY_TRAFFIC_SECRET"
            | "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET"
            | "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET"
            | "QUIC_CLIENT_TRAFFIC_SECRET_0"
            | "QUIC_SERVER_TRAFFIC_SECRET_0"
    )
}

fn normalize_hex(value: &str) -> Option<String> {
    decode_hex(value).map(|_| value.to_ascii_lowercase())
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 { return None; }
    value.as_bytes().chunks_exact(2).map(|pair| {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        Some(((high << 4) | low) as u8)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tls12_and_tls13_key_log_lines() {
        let path = std::env::temp_dir().join(format!("packrat-keys-{}.log", std::process::id()));
        let random = "00".repeat(32);
        let secret = "11".repeat(48);
        std::fs::write(
            &path,
            format!("CLIENT_RANDOM {random} {secret}\nCLIENT_TRAFFIC_SECRET_0 {random} {secret}\n"),
        ).unwrap();
        let mut shelf = KeyShelf::default();
        assert_eq!(shelf.load(&path).unwrap(), 2);
        assert!(shelf.has_client_random(&random));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn malformed_unicode_hex_never_panics_or_replaces_loaded_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.log");
        let random = "00".repeat(32);
        let secret = "11".repeat(48);
        std::fs::write(&path, format!("CLIENT_RANDOM {random} {secret}\n")).unwrap();
        let mut shelf = KeyShelf::default();
        shelf.load(&path).unwrap();
        for value in ["a\u{20ac}", "\u{1f400}", "\u{00e9}aa", "0x11", "zz", "1", ""] {
            assert!(decode_hex(value).is_none() || value.is_empty());
            std::fs::write(&path, format!("CLIENT_RANDOM {random} {value}\n")).unwrap();
            if value.is_empty() { continue; }
            assert!(shelf.load(&path).is_err());
            assert_eq!(shelf.secret_count(), 1);
            assert!(shelf.has_client_random(&random));
        }
    }

    #[test]
    fn duplicates_are_idempotent_and_conflicting_or_invalid_keys_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.log");
        let random = "AA".repeat(32);
        let line = format!("CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "11".repeat(32));
        std::fs::write(&path, line.repeat(3)).unwrap();
        let mut shelf = KeyShelf::default();
        assert_eq!(shelf.load(&path).unwrap(), 1);
        std::fs::write(&path, format!("{line}CLIENT_TRAFFIC_SECRET_0 {random} {}\n", "22".repeat(32))).unwrap();
        assert!(shelf.reload().unwrap_err().contains("conflicting"));
        assert_eq!(shelf.secret_count(), 1);
        for (random, secret) in [("11", "22".repeat(48)), (&random[..], "22".repeat(3))] {
            std::fs::write(&path, format!("CLIENT_RANDOM {random} {secret}\n")).unwrap();
            assert!(shelf.load(&path).is_err());
        }
    }

    #[test]
    fn oversized_key_logs_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.log");
        std::fs::write(&path, vec![b' '; MAX_KEY_LOG_BYTES as usize + 1]).unwrap();
        assert!(KeyShelf::default().load(&path).unwrap_err().contains("size limit"));
    }
}
