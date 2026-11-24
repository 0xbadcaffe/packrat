use super::*;
use crate::analysis::alert_center::AlertDisposition;

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
                app.alert_detail_scroll.set(0);
                app.configure_core(|core| core.alert_center.next());
                return;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.alert_detail_scroll.set(0);
                app.configure_core(|core| core.alert_center.previous());
                return;
            }
            KeyCode::Char('f') => {
                app.alert_detail_scroll.set(0);
                app.configure_core(|core| core.alert_center.cycle_severity_filter());
                return;
            }
            KeyCode::Char('F') => {
                app.alert_detail_scroll.set(0);
                app.configure_core(|core| core.alert_center.cycle_review_filter());
                return;
            }
            KeyCode::PageUp | KeyCode::PageDown => {
                let scroll = app.alert_detail_scroll.get();
                let page = app.alert_detail_page.get();
                app.alert_detail_scroll.set(if key.code == KeyCode::PageUp {
                    scroll.saturating_sub(page)
                } else {
                    scroll.saturating_add(page)
                });
                return;
            }
            KeyCode::Char('m') => {
                app.pin_selected_alert();
                return;
            }
            KeyCode::Char('V') => {
                app.investigate_selected_alert();
                return;
            }
            KeyCode::Char('E') => {
                app.export_selected_alert_archive_case();
                return;
            }
            KeyCode::Char('r') => {
                app.simulate_guard_response();
                return;
            }
            KeyCode::Enter => {
                app.review_selected_alert(AlertDisposition::Reviewing);
                return;
            }
            KeyCode::Char('C') => {
                app.review_selected_alert(AlertDisposition::Confirmed);
                return;
            }
            KeyCode::Char('z') => {
                app.review_selected_alert(AlertDisposition::Benign);
                return;
            }
            KeyCode::Char('K') => {
                app.review_selected_alert(AlertDisposition::Contained);
                return;
            }
            KeyCode::Char('x') => {
                app.review_selected_alert(AlertDisposition::Closed);
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
            app.configure_core(|core| {
                core.security.clear();
                core.credentials.clear();
                core.alert_center.clear();
            });
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
