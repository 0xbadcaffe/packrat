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
}

impl Tab {
    pub const COUNT: usize = 10;

    pub fn index(&self) -> usize {
        match self {
            Tab::Packets    => 0,
            Tab::Analysis   => 1,
            Tab::Strings    => 2,
            Tab::Dynamic    => 3,
            Tab::Visualize  => 4,
            Tab::Flows      => 5,
            Tab::Craft      => 6,
            Tab::Traceroute => 7,
            Tab::Security   => 8,
            Tab::Scanner    => 9,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Packets,
            1 => Tab::Analysis,
            2 => Tab::Strings,
            3 => Tab::Dynamic,
            4 => Tab::Visualize,
            5 => Tab::Flows,
            6 => Tab::Craft,
            7 => Tab::Traceroute,
            8 => Tab::Security,
            9 => Tab::Scanner,
            _ => Tab::Packets,
        }
    }
}
