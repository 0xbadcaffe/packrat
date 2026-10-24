use crate::model::graph::{GraphNodeId, GraphViewFilter};

// ─── UI state ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum GraphUiMode {
    Neighborhood,
    Adjacency,
    Paths,
    Clusters,
    Evidence,
}

impl std::fmt::Display for GraphUiMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Neighborhood => write!(f, "Neighborhood"),
            Self::Adjacency => write!(f, "Adjacency"),
            Self::Paths => write!(f, "Paths"),
            Self::Clusters => write!(f, "Clusters"),
            Self::Evidence => write!(f, "Evidence"),
        }
    }
}

#[derive(Debug, Default)]
pub struct GraphUiState {
    pub selected_node: Option<GraphNodeId>,
    pub list_scroll: usize,
    pub neighbor_scroll: usize,
    pub detail_scroll: usize,
    pub mode: GraphUiModeState,
    pub pivot_history: Vec<GraphNodeId>,
    pub filter: GraphViewFilter,
    pub search: String,
    pub searching: bool,
    pub path_selected: usize,
    pub cluster_selected: usize,
    pub evidence_scroll: usize,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub enum GraphUiModeState {
    #[default]
    Neighborhood,
    Adjacency,
    Paths,
    Clusters,
    Evidence,
}

impl GraphUiModeState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Neighborhood => "Neighborhood",
            Self::Adjacency => "Adjacency",
            Self::Paths => "Paths",
            Self::Clusters => "Clusters",
            Self::Evidence => "Evidence",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Neighborhood => Self::Adjacency,
            Self::Adjacency => Self::Paths,
            Self::Paths => Self::Clusters,
            Self::Clusters => Self::Evidence,
            Self::Evidence => Self::Neighborhood,
        }
    }
}
