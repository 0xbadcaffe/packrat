//! Evidence reference types for the Operator Graph.
//!
//! Links every graph node/edge back to its concrete source evidence.

use crate::model::evidence::{PacketRef, FlowRef, StreamRef, ObjectRef};

pub type AlertRef        = u64;
pub type RuleHitRef      = u64;
pub type IocHitRef       = u64;
pub type YaraHitRef      = u64;
pub type NoteRef         = u64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FirmwareMatchRef(pub u64);

/// A pointer to any concrete piece of evidence backing a graph relationship.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GraphEvidenceRef {
    Packet(PacketRef),
    Flow(FlowRef),
    Stream(StreamRef),
    Object(ObjectRef),
    Alert(AlertRef),
    RuleHit(RuleHitRef),
    IocHit(IocHitRef),
    YaraHit(YaraHitRef),
    Note(NoteRef),
    FirmwareMatch(FirmwareMatchRef),
}

impl std::fmt::Display for GraphEvidenceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Packet(r)        => write!(f, "pkt#{}", r.0),
            Self::Flow(r)          => write!(f, "flow:{}", r.0),
            Self::Stream(r)        => write!(f, "stream:{}", (r.0).0),
            Self::Object(r)        => write!(f, "obj#{}", r.0),
            Self::Alert(r)         => write!(f, "alert#{r}"),
            Self::RuleHit(r)       => write!(f, "rule#{r}"),
            Self::IocHit(r)        => write!(f, "ioc#{r}"),
            Self::YaraHit(r)       => write!(f, "yara#{r}"),
            Self::Note(r)          => write!(f, "note#{r}"),
            Self::FirmwareMatch(r) => write!(f, "fw#{}", r.0),
        }
    }
}
