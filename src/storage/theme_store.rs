//! Theme preference persistence.
//!
//! Stores the selected theme name in `~/.config/packrat/prefs.json`.

use std::path::PathBuf;
use anyhow::Result;

pub const DEFAULT_UI_REFRESH_MS: u64 = 50;
pub const MIN_UI_REFRESH_MS: u64 = 20;
pub const MAX_UI_REFRESH_MS: u64 = 250;
pub const DEFAULT_CAPTURE_TIMEOUT_MS: u64 = 100;
pub const MIN_CAPTURE_TIMEOUT_MS: u64 = 25;
pub const MAX_CAPTURE_TIMEOUT_MS: u64 = 1_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Preferences {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_auto_scroll")]
    pub auto_scroll: bool,
    #[serde(default)]
    pub alert_automation: usize,
    #[serde(default)]
    pub startup_workspace: usize,
    #[serde(default)]
    pub navigation_version: u8,
    #[serde(default = "default_ui_refresh_ms")]
    pub ui_refresh_ms: u64,
    #[serde(default = "default_capture_timeout_ms")]
    pub capture_timeout_ms: u64,
    #[serde(default)]
    pub save_alerts: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            auto_scroll: default_auto_scroll(),
            alert_automation: 0,
            startup_workspace: 0,
            navigation_version: 1,
            ui_refresh_ms: DEFAULT_UI_REFRESH_MS,
            capture_timeout_ms: DEFAULT_CAPTURE_TIMEOUT_MS,
            save_alerts: false,
        }
    }
}

impl Preferences {
    pub fn migrate_navigation(&mut self) {
        if self.navigation_version == 0 {
            self.startup_workspace = match self.startup_workspace {
                1 => 1,
                3 | 4 => 2,
                _ => 0,
            };
            self.navigation_version = 1;
        }
        self.ui_refresh_ms = self.ui_refresh_ms.clamp(MIN_UI_REFRESH_MS, MAX_UI_REFRESH_MS);
        self.capture_timeout_ms = self
            .capture_timeout_ms
            .clamp(MIN_CAPTURE_TIMEOUT_MS, MAX_CAPTURE_TIMEOUT_MS);
    }
}

fn default_theme() -> String { "Dark Pro".into() }
fn default_auto_scroll() -> bool { true }
fn default_ui_refresh_ms() -> u64 { DEFAULT_UI_REFRESH_MS }
fn default_capture_timeout_ms() -> u64 { DEFAULT_CAPTURE_TIMEOUT_MS }

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
    let mut preferences: Preferences = serde_json::from_str(&data).unwrap_or_default();
    preferences.migrate_navigation();
    preferences
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
#[path = "../../tests/unit/storage_theme_store_tests.rs"]
mod tests;
