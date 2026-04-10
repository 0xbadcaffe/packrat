/// Application tabs.
#[derive(Debug, Clone, PartialEq)]
pub enum Tab {
    Packets,
    Analysis,
    Strings,
    Dynamic,
    Visualize,
    Flows,
}

impl Tab {
    pub const COUNT: usize = 6;

    pub fn index(&self) -> usize {
        match self {
            Tab::Packets   => 0,
            Tab::Analysis  => 1,
            Tab::Strings   => 2,
            Tab::Dynamic   => 3,
            Tab::Visualize => 4,
            Tab::Flows     => 5,
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
            _ => Tab::Packets,
        }
    }
}
