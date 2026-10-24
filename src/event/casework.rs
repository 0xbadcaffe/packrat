use super::*;

// ─── Hosts tab ────────────────────────────────────────────────────────────────

pub(super) fn handle_hosts(app: &mut App, key: KeyEvent) {
    // Tag input mode
    if app.hosts_tagging {
        match key.code {
            KeyCode::Esc => {
                app.hosts_tagging = false;
                app.hosts_tag_input.clear();
            }
            KeyCode::Enter => {
                app.apply_host_tag();
                app.hosts_tagging = false;
                app.hosts_tag_input.clear();
            }
            KeyCode::Backspace => {
                app.hosts_tag_input.pop();
            }
            KeyCode::Char(c) => {
                app.hosts_tag_input.push(c);
            }
            _ => {}
        }
        return;
    }

    if app.hosts_searching {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.hosts_searching = false;
            }
            KeyCode::Backspace => {
                app.hosts_search.pop();
            }
            KeyCode::Char(c) => {
                app.hosts_search.push(c);
            }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => {
            app.next_tab();
            return;
        }
        KeyCode::BackTab => {
            app.prev_tab();
            return;
        }
        KeyCode::Char('s') | KeyCode::Char('/') => {
            app.hosts_searching = true;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.core.hosts.len().saturating_sub(1);
            if app.hosts_scroll < max {
                app.hosts_scroll += 1;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.hosts_scroll = app.hosts_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => {
            app.hosts_scroll = 0;
        }
        KeyCode::Char('G') => {
            app.hosts_scroll = app.core.hosts.len().saturating_sub(1);
        }
        KeyCode::Char('C') => {
            app.hosts_search.clear();
            app.hosts_scroll = 0;
        }
        KeyCode::Char('c') => {
            app.core.hosts.clear();
        }
        KeyCode::Char('t') => {
            app.hosts_tagging = true;
            app.hosts_tag_input.clear();
        }
        KeyCode::Char('T') => {
            app.remove_host_tag();
        }
        KeyCode::Char('h') => {
            app.show_help = true;
        }
        _ => {}
    }
}

// ─── Notebook tab ─────────────────────────────────────────────────────────────

pub(super) fn handle_notebook(app: &mut App, key: KeyEvent) {
    if app.notebook_editing {
        match key.code {
            KeyCode::Esc => {
                app.notebook_editing = false;
                app.notebook_input.clear();
            }
            KeyCode::Enter => {
                if !app.notebook_input.is_empty() {
                    let text = app.notebook_input.clone();
                    app.notebook.add(text, None);
                    app.notebook_input.clear();
                }
                app.notebook_editing = false;
            }
            KeyCode::Backspace => {
                app.notebook_input.pop();
            }
            KeyCode::Char(c) => {
                app.notebook_input.push(c);
            }
            _ => {}
        }
        return;
    }

    if app.notebook_searching {
        match key.code {
            KeyCode::Esc => {
                app.notebook_searching = false;
                app.notebook_search.clear();
                app.notebook_scroll = 0;
            }
            KeyCode::Enter => {
                app.notebook_searching = false;
            }
            KeyCode::Backspace => {
                app.notebook_search.pop();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let count = app.notebook.search(&app.notebook_search).len();
                if count > 0 {
                    app.notebook_scroll = (app.notebook_scroll + 1).min(count - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.notebook_scroll = app.notebook_scroll.saturating_sub(1);
            }
            KeyCode::Char(c) => {
                app.notebook_search.push(c);
                app.notebook_scroll = 0;
            }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Char('n') => {
            app.notebook_editing = true;
        }
        KeyCode::Char('/') => {
            app.notebook_searching = true;
            app.notebook_search.clear();
            app.notebook_scroll = 0;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.notebook.len().saturating_sub(1);
            app.notebook_scroll = (app.notebook_scroll + 1).min(max);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.notebook_scroll = app.notebook_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => {
            app.notebook_scroll = 0;
        }
        KeyCode::Char('G') => {
            app.notebook_scroll = app.notebook.len().saturating_sub(1);
        }
        KeyCode::Char('d') => {
            // Delete the note at scroll position
            let notes = if app.notebook_search.is_empty() {
                app.notebook.all().iter().map(|n| n.id).collect::<Vec<_>>()
            } else {
                app.notebook
                    .search(&app.notebook_search.clone())
                    .iter()
                    .map(|n| n.id)
                    .collect::<Vec<_>>()
            };
            if let Some(&id) = notes.get(app.notebook_scroll) {
                app.notebook.delete(id);
                app.notebook_scroll = app.notebook_scroll.saturating_sub(1);
            }
        }
        KeyCode::Tab => {
            app.next_tab();
        }
        KeyCode::BackTab => {
            app.prev_tab();
        }
        KeyCode::Char('h') => {
            app.show_help = true;
        }
        _ => {}
    }
}
