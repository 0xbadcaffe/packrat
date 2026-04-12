//! Theme preference persistence.
//!
//! Stores the selected theme name in `~/.config/packrat/prefs.json`.

use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Prefs {
    theme: String,
}

fn prefs_path() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("packrat").join("prefs.json"))
}

/// Load the persisted theme name, or return the default.
pub fn load_theme_name() -> String {
    let Some(path) = prefs_path() else { return "Dark Pro".into(); };
    let Ok(data) = std::fs::read_to_string(&path) else { return "Dark Pro".into(); };
    serde_json::from_str::<Prefs>(&data)
        .map(|p| p.theme)
        .unwrap_or_else(|_| "Dark Pro".into())
}

/// Persist the selected theme name.
pub fn save_theme_name(name: &str) -> Result<()> {
    let Some(path) = prefs_path() else { return Ok(()); };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let prefs = Prefs { theme: name.to_string() };
    std::fs::write(path, serde_json::to_string_pretty(&prefs)?)?;
    Ok(())
}
