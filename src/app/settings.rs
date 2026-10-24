use super::*;

impl App {
    pub fn open_settings(&mut self) {
        self.settings_open = true;
        self.settings_cursor = 0;
    }

    pub fn close_settings(&mut self) {
        self.settings_open = false;
    }

    pub fn activate_settings_selection(&mut self) {
        match self.settings_cursor {
            1 => self.auto_scroll = !self.auto_scroll,
            2 => {
                self.preferred_workspace = Workspace::from_index(
                    (self.preferred_workspace.index() + 1) % Workspace::COUNT,
                );
            }
            3 => {
                self.core.alert_center.cycle_automation_mode();
            }
            4 => {
                self.traffic_latch.mode = match self.traffic_latch.mode {
                    LatchMode::Monitor => LatchMode::Preview,
                    LatchMode::Preview => LatchMode::Manual,
                    LatchMode::Manual => LatchMode::Automatic,
                    LatchMode::Automatic => LatchMode::Monitor,
                };
            }
            5 => {
                self.traffic_latch.expires_seconds =
                    (self.traffic_latch.expires_seconds + 60).min(86_400)
            }
            6 => {
                self.traffic_latch.max_active_blocks =
                    (self.traffic_latch.max_active_blocks + 1).min(1_024)
            }
            7 => self.clear_guard_kill_switch(),
            _ => {}
        }
        self.save_preferences();
        self.set_status("Preferences updated");
    }

    pub fn adjust_settings_selection(&mut self, increase: bool) {
        match self.settings_cursor {
            1 | 2 | 3 | 4 | 7 => self.activate_settings_selection(),
            5 => {
                self.traffic_latch.expires_seconds = if increase {
                    (self.traffic_latch.expires_seconds + 60).min(86_400)
                } else {
                    self.traffic_latch
                        .expires_seconds
                        .saturating_sub(60)
                        .max(60)
                };
            }
            6 => {
                self.traffic_latch.max_active_blocks = if increase {
                    (self.traffic_latch.max_active_blocks + 1).min(1_024)
                } else {
                    self.traffic_latch
                        .max_active_blocks
                        .saturating_sub(1)
                        .max(1)
                };
            }
            _ => {}
        }
        self.save_preferences();
    }

    pub(super) fn save_preferences(&self) {
        if !self.persist_preferences {
            return;
        }
        let automation = match self.core.alert_center.automation_mode {
            AutomationMode::Off => 0,
            AutomationMode::Watch => 1,
            AutomationMode::Triage => 2,
        };
        let _ = theme_store::save(&theme_store::Preferences {
            theme: self.selected_theme_name.clone(),
            auto_scroll: self.auto_scroll,
            alert_automation: automation,
            startup_workspace: self.preferred_workspace.index(),
            navigation_version: 1,
        });
    }
}
