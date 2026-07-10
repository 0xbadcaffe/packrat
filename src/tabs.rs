/// Application tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Packets,
    Analysis,
    Strings,
    Dynamic,
    Visualize,
    Flows,
    Craft,
    Traceroute,
    Security,
    Scanner,
    Hosts,
    Notebook,
    TlsAnalysis,
    Objects,
    Rules,
    Workbench,
    OperatorGraph,
    Diff,
}

/// Top-level investigation workspaces. Individual views remain lightweight
/// enum values, but are presented through these five operator-focused groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workspace {
    Traffic,
    Inspect,
    Defense,
    Actions,
    Case,
}

const TRAFFIC_VIEWS: &[Tab] = &[Tab::Packets, Tab::Flows, Tab::Hosts, Tab::TlsAnalysis];
const INSPECT_VIEWS: &[Tab] = &[
    Tab::Analysis,
    Tab::Strings,
    Tab::Visualize,
    Tab::Workbench,
    Tab::Objects,
    Tab::Diff,
];
const DEFENSE_VIEWS: &[Tab] = &[Tab::Security, Tab::Rules, Tab::OperatorGraph];
const ACTION_VIEWS: &[Tab] = &[Tab::Scanner, Tab::Traceroute, Tab::Craft];
const CASE_VIEWS: &[Tab] = &[Tab::Notebook, Tab::Dynamic];

impl Workspace {
    pub const COUNT: usize = 5;

    pub fn index(self) -> usize {
        match self {
            Self::Traffic => 0,
            Self::Inspect => 1,
            Self::Defense => 2,
            Self::Actions => 3,
            Self::Case => 4,
        }
    }

    pub fn from_index(index: usize) -> Self {
        match index {
            1 => Self::Inspect,
            2 => Self::Defense,
            3 => Self::Actions,
            4 => Self::Case,
            _ => Self::Traffic,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Traffic => "Traffic",
            Self::Inspect => "Inspect",
            Self::Defense => "Defense",
            Self::Actions => "Actions",
            Self::Case => "Case",
        }
    }

    pub fn home(self) -> Tab {
        self.views()[0]
    }

    pub fn views(self) -> &'static [Tab] {
        match self {
            Self::Traffic => TRAFFIC_VIEWS,
            Self::Inspect => INSPECT_VIEWS,
            Self::Defense => DEFENSE_VIEWS,
            Self::Actions => ACTION_VIEWS,
            Self::Case => CASE_VIEWS,
        }
    }
}

impl Tab {
    pub const COUNT: usize = 18;

    pub fn index(&self) -> usize {
        match self {
            Tab::Packets       => 0,
            Tab::Analysis      => 1,
            Tab::Strings       => 2,
            Tab::Dynamic       => 3,
            Tab::Visualize     => 4,
            Tab::Flows         => 5,
            Tab::Craft         => 6,
            Tab::Traceroute    => 7,
            Tab::Security      => 8,
            Tab::Scanner       => 9,
            Tab::Hosts         => 10,
            Tab::Notebook      => 11,
            Tab::TlsAnalysis   => 12,
            Tab::Objects       => 13,
            Tab::Rules         => 14,
            Tab::Workbench     => 15,
            Tab::OperatorGraph => 16,
            Tab::Diff          => 17,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0  => Tab::Packets,
            1  => Tab::Analysis,
            2  => Tab::Strings,
            3  => Tab::Dynamic,
            4  => Tab::Visualize,
            5  => Tab::Flows,
            6  => Tab::Craft,
            7  => Tab::Traceroute,
            8  => Tab::Security,
            9  => Tab::Scanner,
            10 => Tab::Hosts,
            11 => Tab::Notebook,
            12 => Tab::TlsAnalysis,
            13 => Tab::Objects,
            14 => Tab::Rules,
            15 => Tab::Workbench,
            16 => Tab::OperatorGraph,
            17 => Tab::Diff,
            _  => Tab::Packets,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Packets       => "Packets",
            Tab::Analysis      => "Analysis",
            Tab::Strings       => "Strings",
            Tab::Dynamic       => "Dynamic",
            Tab::Visualize     => "Visualize",
            Tab::Flows         => "Flows",
            Tab::Craft         => "Craft",
            Tab::Traceroute    => "Traceroute",
            Tab::Security      => "Security",
            Tab::Scanner       => "Scanner",
            Tab::Hosts         => "Hosts",
            Tab::Notebook      => "Notebook",
            Tab::TlsAnalysis   => "TLS",
            Tab::Objects       => "Objects",
            Tab::Rules         => "Rules",
            Tab::Workbench     => "Workbench",
            Tab::OperatorGraph => "Graph",
            Tab::Diff          => "Diff",
        }
    }

    pub fn workspace(self) -> Workspace {
        match self {
            Tab::Packets | Tab::Flows | Tab::Hosts | Tab::TlsAnalysis => Workspace::Traffic,
            Tab::Analysis
            | Tab::Strings
            | Tab::Visualize
            | Tab::Workbench
            | Tab::Objects
            | Tab::Diff => Workspace::Inspect,
            Tab::Security | Tab::Rules | Tab::OperatorGraph => Workspace::Defense,
            Tab::Scanner | Tab::Traceroute | Tab::Craft => Workspace::Actions,
            Tab::Notebook | Tab::Dynamic => Workspace::Case,
        }
    }

    pub fn is_workspace_home(self) -> bool {
        self == self.workspace().home()
    }
}
