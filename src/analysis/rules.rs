//! Local rule engine — user-defined detection rules evaluated per-packet.
//!
//! Rules are simple condition→action pairs. Conditions are boolean
//! expressions over packet fields; actions are log/alert/tag.

use std::collections::VecDeque;

use crate::net::packet::Packet;
use crate::model::evidence::Severity;

// ─── Rule condition ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Condition {
    /// Field contains string (case-insensitive).
    Contains { field: String, value: String },
    /// Field equals value.
    Equals { field: String, value: String },
    /// Numeric field comparison: field op value.
    Num { field: String, op: CmpOp, value: u64 },
    /// Logical AND of sub-conditions.
    And(Vec<Condition>),
    /// Logical OR of sub-conditions.
    Or(Vec<Condition>),
    /// Negation of a known result; unavailable fields remain unknown.
    Not(Box<Condition>),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CmpOp { Lt, Le, Eq, Ge, Gt, Ne }

// ─── Rule action ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Action {
    Alert { message: String, severity: Severity },
    Tag   { tag: String },
    Log   { message: String },
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub id:          String,
    pub name:        String,
    pub description: String,
    pub enabled:     bool,
    #[serde(default)]
    pub auto_contain: bool,
    pub condition:   Condition,
    pub actions:     Vec<Action>,
    /// Hit count since last clear.
    pub hits:        u64,
}

impl Rule {
    pub fn new(id: impl Into<String>, name: impl Into<String>, cond: Condition, actions: Vec<Action>) -> Self {
        Self {
            id:          id.into(),
            name:        name.into(),
            description: String::new(),
            enabled:     true,
            auto_contain: false,
            condition:   cond,
            actions,
            hits:        0,
        }
    }
}

// ─── Rule hit ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RuleHit {
    pub rule_id:  String,
    pub rule_name: String,
    pub pkt_no:   u64,
    pub ts:       f64,
    pub action:   Action,
    pub message:  String,
    pub auto_contain: bool,
}

// ─── Rule engine ──────────────────────────────────────────────────────────────

const MAX_HITS: usize = 1000;

#[derive(Debug, Default)]
pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub hits:  VecDeque<RuleHit>,
    evicted_hits: u64,
}

impl RuleEngine {
    pub fn add_rule(&mut self, rule: Rule) { self.rules.push(rule); }

    pub fn remove_rule(&mut self, id: &str) { self.rules.retain(|r| r.id != id); }

    /// Load rules from JSON files in `~/.config/packrat/rules/`.
    /// Each file may contain a single Rule object or an array of Rule objects.
    pub fn load_from_dir(&mut self) -> Vec<String> {
        let dir = dirs_next::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("packrat")
            .join("rules");

        let mut errors: Vec<String> = Vec::new();
        if !dir.exists() { return errors; }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => { errors.push(format!("read dir: {e}")); return errors; }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "json" { continue; }

            let source = path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();

            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    // Try array first, then single rule
                    if let Ok(rules) = serde_json::from_str::<Vec<Rule>>(&text) {
                        for r in rules { self.rules.push(r); }
                    } else if let Ok(rule) = serde_json::from_str::<Rule>(&text) {
                        self.rules.push(rule);
                    } else {
                        errors.push(format!("{source}: invalid JSON rule format"));
                    }
                }
                Err(e) => errors.push(format!("{source}: {e}")),
            }
        }
        errors
    }

    pub fn toggle(&mut self, id: &str) {
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.enabled = !r.enabled;
        }
    }

    pub fn evaluate(&mut self, pkt: &Packet) {
        self.evaluate_with_hits(pkt, |_| {});
    }

    pub(crate) fn evaluate_with_hits(&mut self, pkt: &Packet, mut on_hit: impl FnMut(&RuleHit)) {
        for rule in &mut self.rules {
            if !rule.enabled { continue; }
            if eval_cond(&rule.condition, pkt) == Some(true) {
                rule.hits = rule.hits.saturating_add(1);
                for action in &rule.actions {
                    let message = match action {
                        Action::Alert { message, .. } => message.clone(),
                        Action::Tag   { tag }         => format!("tagged: {tag}"),
                        Action::Log   { message }     => message.clone(),
                    };
                    let hit = RuleHit {
                        rule_id:   rule.id.clone(),
                        rule_name: rule.name.clone(),
                        pkt_no:    pkt.no,
                        ts:        pkt.timestamp,
                        action:    action.clone(),
                        message,
                        auto_contain: rule.auto_contain,
                    };
                    on_hit(&hit);
                    if self.hits.len() == MAX_HITS {
                        self.hits.pop_front();
                        self.evicted_hits = self.evicted_hits.saturating_add(1);
                    }
                    self.hits.push_back(hit);
                }
            }
        }
    }

    pub fn evicted_hit_count(&self) -> u64 { self.evicted_hits }

    pub fn clear_hits(&mut self) {
        self.hits.clear();
        self.evicted_hits = 0;
        for r in &mut self.rules { r.hits = 0; }
    }
}

fn get_field_str<'a>(field: &str, pkt: &'a Packet) -> Option<&'a str> {
    match field {
        "src" | "ip.src"     => Some(&pkt.src),
        "dst" | "ip.dst"     => Some(&pkt.dst),
        "proto" | "protocol" => Some(&pkt.protocol),
        "info"               => Some(&pkt.info),
        _                    => None,
    }
}

fn get_field_num(field: &str, pkt: &Packet) -> Option<u64> {
    match field {
        "len" | "frame.len"  => Some(pkt.length as u64),
        "tcp.srcport" => crate::analysis::stream::tcp_port_pair(pkt).map(|(src, _)| u64::from(src)),
        "tcp.dstport" => crate::analysis::stream::tcp_port_pair(pkt).map(|(_, dst)| u64::from(dst)),
        "udp.srcport" => crate::analysis::dns_transactions::udp_port_pair(pkt).map(|(src, _)| u64::from(src)),
        "udp.dstport" => crate::analysis::dns_transactions::udp_port_pair(pkt).map(|(_, dst)| u64::from(dst)),
        "port" => pkt.dst_port.map(u64::from),
        "ip.ttl" => crate::net::parser::ipv4_ttl(pkt).map(u64::from),
        _ => None,
    }
}

fn eval_cond(cond: &Condition, pkt: &Packet) -> Option<bool> {
    match cond {
        Condition::Contains { field, value } => Some(
            get_field_str(field, pkt)?.to_lowercase().contains(value.to_lowercase().as_str()),
        ),
        Condition::Equals { field, value } => Some(get_field_str(field, pkt)?.eq_ignore_ascii_case(value)),
        Condition::Num { field, op, value } => {
            let actual = get_field_num(field, pkt)?;
            Some(match op {
                CmpOp::Lt => actual < *value,
                CmpOp::Le => actual <= *value,
                CmpOp::Eq => actual == *value,
                CmpOp::Ge => actual >= *value,
                CmpOp::Gt => actual > *value,
                CmpOp::Ne => actual != *value,
            })
        }
        Condition::And(conds) => eval_group(conds, pkt, false),
        Condition::Or(conds)  => eval_group(conds, pkt, true),
        Condition::Not(inner) => eval_cond(inner, pkt).map(|known| !known),
    }
}

fn eval_group(conditions: &[Condition], pkt: &Packet, decisive: bool) -> Option<bool> {
    let mut unknown = false;
    for condition in conditions {
        match eval_cond(condition, pkt) {
            Some(value) if value == decisive => return Some(decisive),
            Some(_) => {}
            None => unknown = true,
        }
    }
    (!unknown).then_some(!decisive)
}
