use super::*;

// ─── Project manager overlay ──────────────────────────────────────────────────

pub(super) fn handle_project_manager(app: &mut App, key: KeyEvent) {
    let pm = &mut app.project_manager;

    // ── Open tab: file path input ─────────────────────────────────────────────
    if pm.tab == PmTab::Open {
        match key.code {
            KeyCode::Esc => {
                app.project_manager_open = false;
            }
            KeyCode::Enter => {
                let path = pm.open_path.trim().to_string();
                if path.is_empty() {
                    pm.status = Some("Enter a file path first".into());
                } else {
                    app.load_project(&path);
                }
            }
            KeyCode::Backspace => {
                pm.open_path.pop();
            }
            KeyCode::Char(c) => {
                pm.open_path.push(c);
                pm.open_editing = true;
                pm.status = None;
            }
            KeyCode::Tab => {
                pm.tab = PmTab::Recent;
                pm.open_editing = false;
            }
            _ => {}
        }
        return;
    }

    // ── New tab: multi-field form ─────────────────────────────────────────────
    if pm.tab == PmTab::New {
        if pm.editing {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => {
                    pm.editing = false;
                }
                KeyCode::Backspace => match pm.active_field {
                    PmField::Name => {
                        pm.new_name.pop();
                    }
                    PmField::Desc => {
                        pm.new_desc.pop();
                    }
                    PmField::Path => {
                        pm.new_path.pop();
                    }
                    PmField::Mode => {}
                },
                KeyCode::Char(c) => {
                    match pm.active_field {
                        PmField::Name => {
                            pm.new_name.push(c);
                        }
                        PmField::Desc => {
                            pm.new_desc.push(c);
                        }
                        PmField::Path => {
                            pm.new_path.push(c);
                        }
                        PmField::Mode => {}
                    }
                    pm.status = None;
                }
                _ => {}
            }
            // Auto-fill path from name if path is empty
            if pm.new_path.is_empty() && !pm.new_name.is_empty() {
                let default = project_store::default_project_path(&pm.new_name);
                pm.new_path = default.to_string_lossy().to_string();
            }
            return;
        }

        match key.code {
            KeyCode::Esc => {
                app.project_manager_open = false;
            }
            KeyCode::Tab => {
                pm.active_field = match pm.active_field {
                    PmField::Name => PmField::Desc,
                    PmField::Desc => PmField::Path,
                    PmField::Path => PmField::Mode,
                    PmField::Mode => {
                        pm.tab = PmTab::Open;
                        PmField::Name
                    }
                };
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                if pm.active_field == PmField::Mode {
                    // Execute create
                    if pm.new_name.is_empty() {
                        pm.status = Some("Project name is required".into());
                    } else {
                        let name = pm.new_name.clone();
                        let mode = pm.new_mode.clone();
                        let path = if pm.new_path.is_empty() {
                            project_store::default_project_path(&name)
                                .to_string_lossy()
                                .to_string()
                        } else {
                            pm.new_path.clone()
                        };
                        // close manager then save
                        app.project_manager_open = false;
                        app.save_project(&path, &name, mode);
                    }
                } else {
                    pm.editing = true;
                }
            }
            KeyCode::Char(' ') => {
                if pm.active_field == PmField::Mode {
                    pm.new_mode = match pm.new_mode {
                        ProjectSaveMode::Lightweight => ProjectSaveMode::Portable,
                        ProjectSaveMode::Portable => ProjectSaveMode::Lightweight,
                    };
                }
            }
            _ => {}
        }
        return;
    }

    // ── Recent tab (default) ──────────────────────────────────────────────────
    match key.code {
        KeyCode::Esc => {
            app.project_manager_open = false;
        }
        KeyCode::Tab => {
            pm.tab = match pm.tab {
                PmTab::Recent => PmTab::New,
                PmTab::New => PmTab::Open,
                PmTab::Open => PmTab::Recent,
            };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = pm.recent.len().saturating_sub(1);
            pm.recent_cursor = (pm.recent_cursor + 1).min(max);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            pm.recent_cursor = pm.recent_cursor.saturating_sub(1);
        }
        KeyCode::Enter => {
            let cursor = pm.recent_cursor;
            if let Some(r) = pm.recent.get(cursor).cloned() {
                app.load_project(&r.path);
            }
        }
        KeyCode::Delete | KeyCode::Char('d') => {
            // Remove entry from recent list (not from disk)
            let cursor = pm.recent_cursor;
            if cursor < app.project_manager.recent.len() {
                app.project_manager.recent.remove(cursor);
                if app.project_manager.recent_cursor > 0 {
                    app.project_manager.recent_cursor -= 1;
                }
            }
        }
        _ => {}
    }
}

// ─── Theme picker overlay ─────────────────────────────────────────────────────

pub(super) fn handle_theme_picker(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Char('\\') => {
            app.theme_picker_open = false;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = THEME_NAMES.len().saturating_sub(1);
            app.theme_picker_cursor = (app.theme_picker_cursor + 1).min(max);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.theme_picker_cursor = app.theme_picker_cursor.saturating_sub(1);
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(&name) = THEME_NAMES.get(app.theme_picker_cursor) {
                app.apply_theme(name);
            }
        }
        _ => {}
    }
}
