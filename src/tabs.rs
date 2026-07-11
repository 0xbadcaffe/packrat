/// Application tabs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Packets,
    Investigate,
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
    Settings,
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
    Tab::Investigate,
    Tab::Analysis,
    Tab::Strings,
    Tab::Visualize,
    Tab::Workbench,
    Tab::Objects,
    Tab::Diff,
];
const DEFENSE_VIEWS: &[Tab] = &[Tab::Security, Tab::Rules, Tab::OperatorGraph];
const ACTION_VIEWS: &[Tab] = &[Tab::Scanner, Tab::Traceroute, Tab::Craft];
const CASE_VIEWS: &[Tab] = &[Tab::Notebook, Tab::Dynamic, Tab::Settings];

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
    pub const COUNT: usize = 20;

    pub fn index(&self) -> usize {
        match self {
            Tab::Packets       => 0,
            Tab::Investigate   => 1,
            Tab::Analysis      => 2,
            Tab::Strings       => 3,
            Tab::Dynamic       => 4,
            Tab::Visualize     => 5,
            Tab::Flows         => 6,
            Tab::Craft         => 7,
            Tab::Traceroute    => 8,
            Tab::Security      => 9,
            Tab::Scanner       => 10,
            Tab::Hosts         => 11,
            Tab::Notebook      => 12,
            Tab::TlsAnalysis   => 13,
            Tab::Objects       => 14,
            Tab::Rules         => 15,
            Tab::Workbench     => 16,
            Tab::OperatorGraph => 17,
            Tab::Diff          => 18,
            Tab::Settings      => 19,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0  => Tab::Packets,
            1  => Tab::Investigate,
            2  => Tab::Analysis,
            3  => Tab::Strings,
            4  => Tab::Dynamic,
            5  => Tab::Visualize,
            6  => Tab::Flows,
            7  => Tab::Craft,
            8  => Tab::Traceroute,
            9  => Tab::Security,
            10 => Tab::Scanner,
            11 => Tab::Hosts,
            12 => Tab::Notebook,
            13 => Tab::TlsAnalysis,
            14 => Tab::Objects,
            15 => Tab::Rules,
            16 => Tab::Workbench,
            17 => Tab::OperatorGraph,
            18 => Tab::Diff,
            19 => Tab::Settings,
            _  => Tab::Packets,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Packets       => "Packets",
            Tab::Investigate   => "Investigate",
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
            Tab::TlsAnalysis   => "Encrypted",
            Tab::Objects       => "Objects",
            Tab::Rules         => "Rules",
            Tab::Workbench     => "Workbench",
            Tab::OperatorGraph => "Graph",
            Tab::Diff          => "Diff",
            Tab::Settings      => "Settings",
        }
    }

    pub fn workspace(self) -> Workspace {
        match self {
            Tab::Packets | Tab::Flows | Tab::Hosts | Tab::TlsAnalysis => Workspace::Traffic,
            Tab::Investigate
            | Tab::Analysis
            | Tab::Strings
            | Tab::Visualize
            | Tab::Workbench
            | Tab::Objects
            | Tab::Diff => Workspace::Inspect,
            Tab::Security | Tab::Rules | Tab::OperatorGraph => Workspace::Defense,
            Tab::Scanner | Tab::Traceroute | Tab::Craft => Workspace::Actions,
            Tab::Notebook | Tab::Dynamic | Tab::Settings => Workspace::Case,
        }
    }

    pub fn is_workspace_home(self) -> bool {
        self == self.workspace().home()
    }
}
