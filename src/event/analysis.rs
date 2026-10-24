use super::*;

// ─── TLS tab ──────────────────────────────────────────────────────────────────

pub(super) fn handle_tls(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => app.next_tab(),
        KeyCode::Char('[') | KeyCode::Char(']') => {
            app.encrypted_view = match app.encrypted_view {
                crate::app::EncryptedView::Tls => crate::app::EncryptedView::Quic,
                crate::app::EncryptedView::Quic => crate::app::EncryptedView::Tls,
            };
            app.tls_selected = 0;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.core.tls_tracker.len().saturating_sub(1);
            if app.tls_selected < max {
                app.tls_selected += 1;
            }
            app.tls_scroll = app.tls_selected;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.tls_selected = app.tls_selected.saturating_sub(1);
            app.tls_scroll = app.tls_selected;
        }
        KeyCode::Char('g') => {
            app.tls_selected = 0;
            app.tls_scroll = 0;
        }
        KeyCode::Char('r') => app.refresh_selected_encrypted_reputation(),
        KeyCode::Char('G') => {
            app.tls_selected = app.core.tls_tracker.len().saturating_sub(1);
            app.tls_scroll = app.tls_selected;
        }
        KeyCode::Char('c') => {
            match app.encrypted_view {
                crate::app::EncryptedView::Tls => app.core.tls_tracker.clear(),
                crate::app::EncryptedView::Quic => app.core.quic_scope.clear(),
            }
            app.tls_selected = 0;
            app.tls_scroll = 0;
        }
        KeyCode::Char('h') => {
            app.show_help = true;
        }
        _ => {}
    }
}

// ─── Diff tab ─────────────────────────────────────────────────────────────────

pub(super) fn handle_diff(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => app.next_tab(),
        KeyCode::Down | KeyCode::Char('j') => {
            app.diff_scroll = app.diff_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.diff_scroll = app.diff_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => {
            app.diff_scroll = 0;
        }
        KeyCode::Char('d') => {
            app.diff_compute();
        }
        KeyCode::Char('X') => {
            app.diff_engine.clear();
            app.diff_baseline.clear();
            app.diff_scroll = 0;
            app.set_status("Diff cleared".to_string());
        }
        KeyCode::Char('h') => {
            app.show_help = true;
        }
        _ => {}
    }
}

// ─── Rules tab ────────────────────────────────────────────────────────────────

pub(super) fn handle_rules(app: &mut App, key: KeyEvent) {
    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        KeyCode::Tab => app.next_tab(),

        KeyCode::Down | KeyCode::Char('j') => {
            let max = app.core.rule_engine.rules.len().saturating_sub(1);
            if app.rules_scroll < max {
                app.rules_scroll += 1;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.rules_scroll = app.rules_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => {
            app.rules_scroll = 0;
        }
        KeyCode::Char('G') => {
            app.rules_scroll = app.core.rule_engine.rules.len().saturating_sub(1);
        }

        KeyCode::Char('t') => {
            // Toggle the rule at the current scroll position
            if let Some(rule) = app.core.rule_engine.rules.get(app.rules_scroll) {
                let id = rule.id.clone();
                app.core.rule_engine.toggle(&id);
            }
        }

        KeyCode::Char('r') => {
            app.reload_rules();
        }
        KeyCode::Char('C') => {
            app.core.rule_engine.clear_hits();
        }

        KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
}
