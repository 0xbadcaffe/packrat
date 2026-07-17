//! Theme preference persistence.
//!
//! Stores the selected theme name in `~/.config/packrat/prefs.json`.

use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Preferences {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default)]
    pub auto_scroll: bool,
    #[serde(default)]
    pub alert_automation: usize,
    #[serde(default)]
    pub startup_workspace: usize,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            auto_scroll: false,
            alert_automation: 0,
            startup_workspace: 0,
        }
    }
}

fn default_theme() -> String { "Dark Pro".into() }

fn prefs_path() -> Option<PathBuf> {
    dirs_next::config_dir().map(|d| d.join("packrat").join("prefs.json"))
}

/// Load the persisted theme name, or return the default.
pub fn load_theme_name() -> String {
    load().theme
}

pub fn load() -> Preferences {
    let Some(path) = prefs_path() else { return Preferences::default(); };
    let Ok(data) = std::fs::read_to_string(&path) else { return Preferences::default(); };
    serde_json::from_str(&data).unwrap_or_default()
}

/// Persist the selected theme name.
pub fn save_theme_name(name: &str) -> Result<()> {
    let mut preferences = load();
    preferences.theme = name.to_string();
    save(&preferences)
}

pub fn save(preferences: &Preferences) -> Result<()> {
    let Some(path) = prefs_path() else { return Ok(()); };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(preferences)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_theme_only_preferences_receive_safe_defaults() {
        let preferences: Preferences = serde_json::from_str(r#"{"theme":"Matrix"}"#).unwrap();
        assert_eq!(preferences.theme, "Matrix");
        assert!(!preferences.auto_scroll);
        assert_eq!(preferences.alert_automation, 0);
        assert_eq!(preferences.startup_workspace, 0);
    }
}
