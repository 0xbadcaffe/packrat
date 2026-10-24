//! Project persistence — save, load, and recent-project tracking.

use std::path::{Path, PathBuf};
use std::io::{BufWriter, Read, Write};
use anyhow::{Context, Result};

use crate::model::project::{ProjectSaveMode, ProjectState, RecentProject, SCHEMA_VERSION};

// ─── Save / load ──────────────────────────────────────────────────────────────

const MAX_PROJECT_BYTES: u64 = 512 * 1024 * 1024;

fn atomic_json_write(value: &impl serde::Serialize, path: &Path, max_bytes: u64) -> Result<()> {
    let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create directory: {}", parent.display()))?;
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    {
        let mut writer = BufWriter::new(pending.as_file_mut());
        serde_json::to_writer_pretty(&mut writer, value)?;
        writer.flush()?;
    }
    anyhow::ensure!(pending.as_file().metadata()?.len() <= max_bytes, "Project exceeds size limit");
    pending.as_file().sync_all()?;
    pending.persist(path).with_context(|| format!("cannot replace project: {}", path.display()))?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Save a project to `path` as pretty-printed JSON.
pub fn save(state: &ProjectState, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    atomic_json_write(state, path, MAX_PROJECT_BYTES)
}

/// Load a project from `path`.  Performs lightweight schema migration.
pub fn load(path: impl AsRef<Path>) -> Result<ProjectState> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open project: {}", path.display()))?;
    anyhow::ensure!(file.metadata()?.len() <= MAX_PROJECT_BYTES, "Project exceeds size limit");
    let mut data = String::new();
    file.take(MAX_PROJECT_BYTES + 1).read_to_string(&mut data)?;
    anyhow::ensure!(data.len() as u64 <= MAX_PROJECT_BYTES, "Project exceeds size limit");
    let mut state: ProjectState = serde_json::from_str(&data)
        .with_context(|| format!("invalid project file: {}", path.display()))?;
    anyhow::ensure!(state.metadata.schema_version <= SCHEMA_VERSION, "Project uses a newer unsupported schema");
    // Schema migration hook — bump version and apply transforms as needed.
    if state.metadata.schema_version < SCHEMA_VERSION {
        state.metadata.schema_version = SCHEMA_VERSION;
    }
    state.metadata.last_opened_at = now();
    Ok(state)
}

// ─── Recent projects ──────────────────────────────────────────────────────────

fn recent_path() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("packrat").join("recent_projects.json"))
}

/// Return the most-recently-used project list (up to 20 entries).
pub fn recent_projects() -> Vec<RecentProject> {
    let Some(path) = recent_path() else { return Vec::new(); };
    let Ok(data) = std::fs::read_to_string(&path) else { return Vec::new(); };
    serde_json::from_str(&data).unwrap_or_default()
}

/// Prepend a project to the recent list, deduplicating by path.
pub fn add_to_recent(
    name: &str,
    path: &Path,
    desc: Option<&str>,
    mode: ProjectSaveMode,
) -> Result<()> {
    let mut list = recent_projects();
    let entry_path = path.to_string_lossy().to_string();
    list.retain(|r| r.path != entry_path);
    list.insert(0, RecentProject {
        name:        name.to_string(),
        path:        entry_path,
        last_opened: now(),
        description: desc.map(str::to_string),
        save_mode:   mode,
    });
    list.truncate(20);

    if let Some(p) = recent_path() {
        atomic_json_write(&list, &p, MAX_PROJECT_BYTES)?;
    }
    Ok(())
}

// ─── Default paths ────────────────────────────────────────────────────────────

pub fn default_project_dir() -> PathBuf {
    dirs_next::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("packrat")
        .join("projects")
}

/// Derive a safe file path from a project name.
pub fn default_project_path(name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    default_project_dir().join(format!("{safe}.packrat.json"))
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
#[path = "../../tests/unit/storage_project_store_tests.rs"]
mod tests;
