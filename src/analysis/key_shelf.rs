//! NSS/SSLKEYLOGFILE secret ingestion and ClientHello correlation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("read key log {}: {error}", path.display()))?;
        let mut secrets: HashMap<String, Vec<KeySecret>> = HashMap::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 3 || !is_supported_label(fields[0]) { continue; }
            let client_random = normalize_hex(fields[1])
                .ok_or_else(|| format!("invalid client random on key-log line {}", line_no + 1))?;
            let secret = decode_hex(fields[2])
                .ok_or_else(|| format!("invalid secret on key-log line {}", line_no + 1))?;
            secrets.entry(client_random.clone()).or_default().push(KeySecret {
                label: fields[0].into(),
                client_random,
                secret,
            });
        }
        let count = secrets.values().map(Vec::len).sum();
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
    (0..value.len()).step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
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
}
