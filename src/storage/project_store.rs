//! Project persistence — save, load, and recent-project tracking.

use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

use crate::model::project::{ProjectSaveMode, ProjectState, RecentProject, SCHEMA_VERSION};

// ─── Save / load ──────────────────────────────────────────────────────────────

/// Save a project to `path` as pretty-printed JSON.
pub fn save(state: &ProjectState, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("cannot create directory: {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(state)?;
    std::fs::write(path, json)
        .with_context(|| format!("cannot write project: {}", path.display()))?;
    Ok(())
}

/// Load a project from `path`.  Performs lightweight schema migration.
pub fn load(path: impl AsRef<Path>) -> Result<ProjectState> {
    let path = path.as_ref();
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("cannot open project: {}", path.display()))?;
    let mut state: ProjectState = serde_json::from_str(&data)
        .with_context(|| format!("invalid project file: {}", path.display()))?;
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
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, serde_json::to_string_pretty(&list)?)?;
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
