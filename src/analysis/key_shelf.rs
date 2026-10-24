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
#[path = "../../tests/unit/analysis_key_shelf_tests.rs"]
mod tests;
