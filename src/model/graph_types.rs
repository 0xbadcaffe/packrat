//! Typed node kinds, edge kinds, and payload structs for the Operator Graph.

use std::collections::HashSet;

// ─── Node kinds ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GraphNodeKind {
    Host,
    Service,
    Flow,
    Stream,
    Identity,
    Credential,
    Token,
    Certificate,
    FileObject,
    Alert,
    IOC,
    RuleHit,
    ProtocolArtifact,
    FirmwareArtifact,
    CampaignCluster,
}

impl std::fmt::Display for GraphNodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Host              => "Host",
            Self::Service           => "Service",
            Self::Flow              => "Flow",
            Self::Stream            => "Stream",
            Self::Identity          => "Identity",
            Self::Credential        => "Credential",
            Self::Token             => "Token",
            Self::Certificate       => "Certificate",
            Self::FileObject        => "FileObject",
            Self::Alert             => "Alert",
            Self::IOC               => "IOC",
            Self::RuleHit           => "RuleHit",
            Self::ProtocolArtifact  => "ProtocolArtifact",
            Self::FirmwareArtifact  => "FirmwareArtifact",
            Self::CampaignCluster   => "CampaignCluster",
        };
        write!(f, "{s}")
    }
}

impl GraphNodeKind {
    /// Short 3-4 char label for the TUI.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Host             => "HOST",
            Self::Service          => "SVC ",
            Self::Flow             => "FLOW",
            Self::Stream           => "STRM",
            Self::Identity         => "IDNT",
            Self::Credential       => "CRED",
            Self::Token            => "TOK ",
            Self::Certificate      => "CERT",
            Self::FileObject       => "FILE",
            Self::Alert            => "ALRT",
            Self::IOC              => "IOC ",
            Self::RuleHit          => "RULE",
            Self::ProtocolArtifact => "PROTO",
            Self::FirmwareArtifact => "FW  ",
            Self::CampaignCluster  => "CLUS",
        }
    }
}

// ─── Edge kinds ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum GraphEdgeKind {
    CommunicatesWith,
    ResolvesTo,
    PresentsCertificate,
    AuthenticatedWith,
    ReusedBy,
    ExtractedFrom,
    DownloadedFrom,
    UploadedTo,
    TriggersAlert,
    MatchesIoc,
    BelongsToFlow,
    BelongsToHost,
    FollowsInTime,
    LikelyRelatedTo,
    PivotCandidate,
    DerivedFrom,
    UsesService,
    EmitsToken,
    ReusesToken,
    LinkedToFirmware,
}

impl std::fmt::Display for GraphEdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CommunicatesWith    => "communicates_with",
            Self::ResolvesTo          => "resolves_to",
            Self::PresentsCertificate => "presents_cert",
            Self::AuthenticatedWith   => "authenticated_with",
            Self::ReusedBy            => "reused_by",
            Self::ExtractedFrom       => "extracted_from",
            Self::DownloadedFrom      => "downloaded_from",
            Self::UploadedTo          => "uploaded_to",
            Self::TriggersAlert       => "triggers_alert",
            Self::MatchesIoc          => "matches_ioc",
            Self::BelongsToFlow       => "belongs_to_flow",
            Self::BelongsToHost       => "belongs_to_host",
            Self::FollowsInTime       => "follows_in_time",
            Self::LikelyRelatedTo     => "likely_related_to",
            Self::PivotCandidate      => "pivot_candidate",
            Self::DerivedFrom         => "derived_from",
            Self::UsesService         => "uses_service",
            Self::EmitsToken          => "emits_token",
            Self::ReusesToken         => "reuses_token",
            Self::LinkedToFirmware    => "linked_to_firmware",
        };
        write!(f, "{s}")
    }
}

// ─── Node payloads ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HostNodeData {
    pub ips:       Vec<String>,
    pub macs:      Vec<String>,
    pub hostnames: HashSet<String>,
    pub dns_names: HashSet<String>,
    pub tls_names: HashSet<String>,
    pub open_ports: Vec<u16>,
    pub flows_in:  u64,
    pub flows_out: u64,
    pub bytes_in:  u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ServiceNodeData {
    pub protocol: String,
    pub port:     u16,
    pub role:     Option<String>,
    pub host_ip:  String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FlowNodeData {
    pub flow_id:   String,
    pub src:       String,
    pub dst:       String,
    pub proto:     String,
    pub pkt_count: u64,
    pub bytes:     u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StreamNodeData {
    pub flow_id:     String,
    pub client_size: usize,
    pub server_size: usize,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IdentityNodeData {
    pub name:        String,
    pub kind:        String,
    pub resolved_ip: Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CredentialNodeData {
    pub cred_type:  String,
    pub username:   Option<String>,
    pub pw_preview: String,
    pub scheme:     String,
    pub cleartext:  bool,
    pub confidence: f32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TokenNodeData {
    pub token_type:  String,
    pub preview:     String,
    pub fingerprint: String,
    pub source:      Option<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CertificateNodeData {
    pub subject:     String,
    pub issuer:      String,
    pub serial:      String,
    pub fingerprint: String,
    pub sans:        Vec<String>,
    pub not_before:  Option<String>,
    pub not_after:   Option<String>,
    pub self_signed: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FileObjectNodeData {
    pub filename:  String,
    pub mime:      String,
    pub sha256:    String,
    pub size:      usize,
    pub source:    String,
    pub yara_hits: Vec<String>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AlertNodeData {
    pub signature: String,
    pub severity:  String,
    pub detail:    String,
    pub pkt_no:    u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IocNodeData {
    pub ioc_kind:    String,
    pub value:       String,
    pub description: String,
    pub source:      String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RuleHitNodeData {
    pub rule_id:   String,
    pub rule_name: String,
    pub pkt_no:    u64,
    pub action:    String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ProtocolArtifactNodeData {
    pub proto:    String,
    pub artifact: String,
    pub detail:   String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FirmwareArtifactNodeData {
    pub source_file:   String,
    pub token:         String,
    pub artifact_kind: String,
    pub score:         f32,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CampaignClusterNodeData {
    pub cluster_id:   u64,
    pub member_count: u64,
    pub cluster_kind: String,
    pub score:        f32,
}

// ─── Discriminated node data ──────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum GraphNodeData {
    Host(HostNodeData),
    Service(ServiceNodeData),
    Flow(FlowNodeData),
    Stream(StreamNodeData),
    Identity(IdentityNodeData),
    Credential(CredentialNodeData),
    Token(TokenNodeData),
    Certificate(CertificateNodeData),
    FileObject(FileObjectNodeData),
    Alert(AlertNodeData),
    IOC(IocNodeData),
    RuleHit(RuleHitNodeData),
    ProtocolArtifact(ProtocolArtifactNodeData),
    FirmwareArtifact(FirmwareArtifactNodeData),
    CampaignCluster(CampaignClusterNodeData),
}

impl Default for GraphNodeData {
    fn default() -> Self { Self::Host(HostNodeData::default()) }
}

impl GraphNodeData {
    pub fn kind(&self) -> GraphNodeKind {
        match self {
            Self::Host(_)             => GraphNodeKind::Host,
            Self::Service(_)          => GraphNodeKind::Service,
            Self::Flow(_)             => GraphNodeKind::Flow,
            Self::Stream(_)           => GraphNodeKind::Stream,
            Self::Identity(_)         => GraphNodeKind::Identity,
            Self::Credential(_)       => GraphNodeKind::Credential,
            Self::Token(_)            => GraphNodeKind::Token,
            Self::Certificate(_)      => GraphNodeKind::Certificate,
            Self::FileObject(_)       => GraphNodeKind::FileObject,
            Self::Alert(_)            => GraphNodeKind::Alert,
            Self::IOC(_)              => GraphNodeKind::IOC,
            Self::RuleHit(_)          => GraphNodeKind::RuleHit,
            Self::ProtocolArtifact(_) => GraphNodeKind::ProtocolArtifact,
            Self::FirmwareArtifact(_) => GraphNodeKind::FirmwareArtifact,
            Self::CampaignCluster(_)  => GraphNodeKind::CampaignCluster,
        }
    }
}
