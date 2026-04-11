/// Application tabs.
#[derive(Debug, Clone, PartialEq)]
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
}

impl Tab {
    pub const COUNT: usize = 17;

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
        }
    }
}
