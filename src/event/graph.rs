use super::*;

// ─── Operator Graph tab ───────────────────────────────────────────────────────

pub(super) fn handle_graph(app: &mut App, key: KeyEvent) {
    // Search input mode
    if app.graph_ui.searching {
        match key.code {
            KeyCode::Esc => {
                app.graph_ui.searching = false;
            }
            KeyCode::Enter => {
                app.graph_ui.searching = false;
            }
            KeyCode::Backspace => {
                app.graph_ui.search.pop();
            }
            KeyCode::Char(c) => {
                app.graph_ui.search.push(c);
            }
            _ => {}
        }
        return;
    }

    if global_tab_switch(app, &key) {
        return;
    }

    match key.code {
        // Main tab navigation
        KeyCode::Tab => {
            app.next_tab();
            return;
        }
        KeyCode::BackTab => {
            app.prev_tab();
            return;
        }
        // Mode cycling with m / M
        KeyCode::Char('m') => {
            app.graph_ui.mode = app.graph_ui.mode.next();
        }

        // Node list navigation
        KeyCode::Down | KeyCode::Char('j') => match app.graph_ui.mode {
            GraphUiModeState::Neighborhood | GraphUiModeState::Adjacency => {
                app.graph_ui.list_scroll = app.graph_ui.list_scroll.saturating_add(1);
            }
            GraphUiModeState::Paths => {
                let max = app
                    .query_core(|core| core.operator_graph.paths.len().saturating_sub(1))
                    .unwrap_or(app.graph_ui.path_selected);
                if app.graph_ui.path_selected < max {
                    app.graph_ui.path_selected += 1;
                }
            }
            GraphUiModeState::Clusters => {
                let max = app
                    .query_core(|core| core.operator_graph.clusters.len().saturating_sub(1))
                    .unwrap_or(app.graph_ui.cluster_selected);
                if app.graph_ui.cluster_selected < max {
                    app.graph_ui.cluster_selected += 1;
                }
            }
            GraphUiModeState::Evidence => {
                app.graph_ui.evidence_scroll = app.graph_ui.evidence_scroll.saturating_add(1);
            }
        },
        KeyCode::Up | KeyCode::Char('k') => match app.graph_ui.mode {
            GraphUiModeState::Neighborhood | GraphUiModeState::Adjacency => {
                app.graph_ui.list_scroll = app.graph_ui.list_scroll.saturating_sub(1);
            }
            GraphUiModeState::Paths => {
                app.graph_ui.path_selected = app.graph_ui.path_selected.saturating_sub(1);
            }
            GraphUiModeState::Clusters => {
                app.graph_ui.cluster_selected = app.graph_ui.cluster_selected.saturating_sub(1);
            }
            GraphUiModeState::Evidence => {
                app.graph_ui.evidence_scroll = app.graph_ui.evidence_scroll.saturating_sub(1);
            }
        },

        // Select node
        KeyCode::Enter => {
            match app.graph_ui.mode {
                GraphUiModeState::Neighborhood | GraphUiModeState::Adjacency => {
                    let core_handle = app.core.clone();
                    let Some(core) = core_handle.try_read().ok().flatten() else {
                        return;
                    };
                    // Select the highlighted node in the list
                    let filter = app.graph_ui.filter.clone();
                    let search = app.graph_ui.search.clone();
                    let snapshot = core.operator_graph.filtered_snapshot(&filter);
                    let visible: Vec<_> = {
                        let q = search.to_lowercase();
                        snapshot
                            .node_ids
                            .iter()
                            .filter_map(|&id| core.operator_graph.get_node(id))
                            .filter(|n| q.is_empty() || n.label.to_lowercase().contains(&q))
                            .collect()
                    };
                    let scroll = app.graph_ui.list_scroll;
                    if let Some(node) = visible.get(scroll) {
                        let id = node.id;
                        if let Some(prev) = app.graph_ui.selected_node {
                            app.graph_ui.pivot_history.push(prev);
                        }
                        app.graph_ui.selected_node = Some(id);
                        app.graph_ui.neighbor_scroll = 0;
                        app.graph_ui.detail_scroll = 0;
                    }
                }
                GraphUiModeState::Paths => {
                    // Jump to first node of selected path
                    if let Some(node_id) = app
                        .query_core(|core| {
                            core.operator_graph
                                .paths
                                .get(app.graph_ui.path_selected)
                                .and_then(|path| path.nodes.first())
                                .copied()
                        })
                        .flatten()
                    {
                        app.graph_ui.selected_node = Some(node_id);
                        app.graph_ui.mode = GraphUiModeState::Neighborhood;
                    }
                }
                GraphUiModeState::Clusters => {
                    // Jump to first member of selected cluster
                    if let Some(node_id) = app
                        .query_core(|core| {
                            core.operator_graph
                                .clusters
                                .get(app.graph_ui.cluster_selected)
                                .and_then(|cluster| cluster.members.first())
                                .copied()
                        })
                        .flatten()
                    {
                        app.graph_ui.selected_node = Some(node_id);
                        app.graph_ui.mode = GraphUiModeState::Neighborhood;
                    }
                }
                _ => {}
            }
        }

        // Navigate back (pivot history)
        KeyCode::Backspace => {
            if let Some(prev) = app.graph_ui.pivot_history.pop() {
                app.graph_ui.selected_node = Some(prev);
            }
        }

        // Jump to paths/clusters mode
        KeyCode::Char('A') => {
            app.graph_ui.mode = GraphUiModeState::Adjacency;
        }
        KeyCode::Char('P') | KeyCode::Char('a') => {
            app.graph_ui.mode = GraphUiModeState::Paths;
        }
        KeyCode::Char('C') => {
            app.graph_ui.mode = GraphUiModeState::Clusters;
        }
        KeyCode::Char('E') => {
            app.graph_ui.mode = GraphUiModeState::Evidence;
        }

        // Compute pivots for selected node
        KeyCode::Char('p') => {
            if let Some(node_id) = app.graph_ui.selected_node {
                app.configure_core(move |core| core.operator_graph.recompute_pivots(node_id));
            }
        }

        // Search
        KeyCode::Char('/') => {
            app.graph_ui.searching = true;
        }

        // Export
        KeyCode::Char('x') => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let path = format!("packrat_graph_{}.json", ts);
            let _ = app.query_core(|core| {
                crate::storage::graph_store::export_json(&core.operator_graph, &path)
            });
        }

        KeyCode::Char('h') => {
            app.show_help = true;
        }

        _ => {}
    }
}
