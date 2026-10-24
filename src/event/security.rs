use super::*;

// ─── Security tab ─────────────────────────────────────────────────────────────

pub(super) fn handle_security(app: &mut App, key: KeyEvent) {
    // Replay editing intercepts all keys — must check before global_tab_switch
    // so that typing digits in the file path doesn't jump to another tab.
    if matches!(app.security_tab, SecuritySubTab::Replay) && app.replay_editing {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                if matches!(key.code, KeyCode::Enter) {
                    app.replay.load();
                }
                app.replay_editing = false;
            }
            KeyCode::Backspace => {
                app.replay.path.pop();
            }
            KeyCode::Char(c) => {
                app.replay.path.push(c);
            }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    if matches!(app.security_tab, SecuritySubTab::Alerts) {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                app.core.alert_center.next();
                return;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.core.alert_center.previous();
                return;
            }
            KeyCode::Char('f') => {
                app.core.alert_center.cycle_severity_filter();
                return;
            }
            KeyCode::Char('m') => {
                app.pin_selected_alert();
                return;
            }
            KeyCode::Char('r') => {
                app.simulate_guard_response();
                return;
            }
            KeyCode::Enter => {
                app.core.alert_center.set_selected_disposition(
                    crate::analysis::alert_center::AlertDisposition::Reviewing,
                );
                return;
            }
            KeyCode::Char('C') => {
                app.core.alert_center.set_selected_disposition(
                    crate::analysis::alert_center::AlertDisposition::Confirmed,
                );
                return;
            }
            KeyCode::Char('z') => {
                app.core.alert_center.set_selected_disposition(
                    crate::analysis::alert_center::AlertDisposition::Benign,
                );
                return;
            }
            KeyCode::Char('K') => {
                app.core.alert_center.set_selected_disposition(
                    crate::analysis::alert_center::AlertDisposition::Contained,
                );
                return;
            }
            KeyCode::Char('x') => {
                app.core.alert_center.set_selected_disposition(
                    crate::analysis::alert_center::AlertDisposition::Closed,
                );
                return;
            }
            _ => {}
        }
    }

    match key.code {
        // Sub-tab cycling with [ / ]  (Tab/BackTab advance the main tab)
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.prev_tab(),
        KeyCode::Char('[') => app.security_subtab_prev(),
        KeyCode::Char(']') => app.security_subtab_next(),
        // Direct sub-tab keys
        KeyCode::Char('a') => app.security_tab = SecuritySubTab::Alerts,
        KeyCode::Char('e') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay_editing = true;
        }
        KeyCode::Char('e') => app.security_tab = SecuritySubTab::Ids,
        KeyCode::Char('c') => app.security_tab = SecuritySubTab::Credentials,
        KeyCode::Char('o') => app.security_tab = SecuritySubTab::OsFingerprint,
        KeyCode::Char('w') => app.security_tab = SecuritySubTab::ArpWatch,
        KeyCode::Char('d') => app.security_tab = SecuritySubTab::DnsTunnel,
        KeyCode::Char('u') => app.security_tab = SecuritySubTab::HttpAnalytics,
        KeyCode::Char('t') => app.security_tab = SecuritySubTab::TlsWeakness,
        KeyCode::Char('b') => app.security_tab = SecuritySubTab::BruteForce,
        KeyCode::Char('v') => app.security_tab = SecuritySubTab::VulnHits,
        KeyCode::Char('i') => app.security_tab = SecuritySubTab::IocHits,
        KeyCode::Char('p') => app.security_tab = SecuritySubTab::Replay,
        // Navigation
        KeyCode::Down | KeyCode::Char('j') => {
            app.security_scroll = app.security_scroll.saturating_add(1);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.security_scroll = app.security_scroll.saturating_sub(1);
        }
        KeyCode::Char('g') => app.security_scroll = 0,
        KeyCode::Char('G') => app.security_scroll = 9999,
        KeyCode::Char('C') => {
            app.core.security.clear();
            app.core.credentials.clear();
            app.core.alert_center.clear();
            app.security_scroll = 0;
        }
        KeyCode::Char('l') if matches!(app.security_tab, SecuritySubTab::RoutePolicy) => {
            app.cycle_route_policy_mode();
        }
        KeyCode::Char('y') if matches!(app.security_tab, SecuritySubTab::RoutePolicy) => {
            app.promote_observed_routes();
        }
        KeyCode::Char('r') if matches!(app.security_tab, SecuritySubTab::NetRegistry) => {
            app.refresh_selected_whois();
        }
        // Replay sub-tab controls
        KeyCode::Enter if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay.load();
        }
        KeyCode::Char(' ') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            if app.replay.running {
                app.replay.stop();
            } else {
                app.replay.start();
            }
        }
        KeyCode::Char('<') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay.speed_down();
        }
        KeyCode::Char('>') if matches!(app.security_tab, SecuritySubTab::Replay) => {
            app.replay.speed_up();
        }
        KeyCode::Char('h') => app.show_help = true,
        _ => {}
    }
}
