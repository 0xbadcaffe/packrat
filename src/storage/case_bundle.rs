//! Case bundle — portable archive of an investigation.
//!
//! Bundles the session (notes/tags/rules), IOC list, carved objects,
//! and optionally the original PCAP into a single JSON or zip archive.

use std::path::{Path, PathBuf};
use anyhow::Result;

use crate::analysis::carving::CarvedObject;
use crate::analysis::ioc::Ioc;
use crate::analysis::notebook::Notebook;
use crate::model::tags::TagStore;

// ─── Bundle manifest ──────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BundleManifest {
    pub version:    u32,
    pub created_at: f64,
    pub analyst:    String,
    pub case_id:    String,
    pub title:      String,
    pub notes:      String,
}

// ─── Case bundle ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CaseBundle {
    pub manifest:  BundleManifest,
    pub notebook:  Notebook,
    pub tags:      TagStore,
    pub iocs:      Vec<Ioc>,
    /// Carved object metadata (data not included by default).
    pub objects:   Vec<ObjectEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObjectEntry {
    pub id:     u64,
    pub kind:   String,
    pub name:   String,
    pub source: String,
    pub sha256: String,
    pub size:   usize,
    pub yara_hits: Vec<String>,
}

impl From<&CarvedObject> for ObjectEntry {
    fn from(o: &CarvedObject) -> Self {
        ObjectEntry {
            id:        o.id,
            kind:      o.kind.clone(),
            name:      o.name.clone(),
            source:    o.source.clone(),
            sha256:    o.sha256.clone(),
            size:      o.data.len(),
            yara_hits: o.yara_hits.clone(),
        }
    }
}

// ─── Export / import ──────────────────────────────────────────────────────────

impl CaseBundle {
    pub fn new(case_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            manifest: BundleManifest {
                version:    1,
                created_at: now(),
                case_id:    case_id.into(),
                title:      title.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    pub fn add_object(&mut self, obj: &CarvedObject) {
        self.objects.push(ObjectEntry::from(obj));
    }

    /// Export to a JSON file.
    pub fn export_json(&self, path: impl AsRef<Path>) -> Result<PathBuf> {
        let path = path.as_ref();
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(path.to_path_buf())
    }

    /// Import from a JSON file.
    pub fn import_json(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
