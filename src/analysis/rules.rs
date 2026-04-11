//! Local rule engine — user-defined detection rules evaluated per-packet.
//!
//! Rules are simple condition→action pairs. Conditions are boolean
//! expressions over packet fields; actions are log/alert/tag.

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
    /// Negation.
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
}

// ─── Rule engine ──────────────────────────────────────────────────────────────

const MAX_HITS: usize = 1000;

#[derive(Debug, Default)]
pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub hits:  Vec<RuleHit>,
}

impl RuleEngine {
    pub fn add_rule(&mut self, rule: Rule) { self.rules.push(rule); }

    pub fn remove_rule(&mut self, id: &str) { self.rules.retain(|r| r.id != id); }

    pub fn toggle(&mut self, id: &str) {
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.enabled = !r.enabled;
        }
    }

    pub fn evaluate(&mut self, pkt: &Packet) {
        for rule in &mut self.rules {
            if !rule.enabled { continue; }
            if eval_cond(&rule.condition, pkt) {
                rule.hits += 1;
                if self.hits.len() < MAX_HITS {
                    for action in &rule.actions {
                        let message = match action {
                            Action::Alert { message, .. } => message.clone(),
                            Action::Tag   { tag }         => format!("tagged: {tag}"),
                            Action::Log   { message }     => message.clone(),
                        };
                        self.hits.push(RuleHit {
                            rule_id:   rule.id.clone(),
                            rule_name: rule.name.clone(),
                            pkt_no:    pkt.no,
                            ts:        pkt.timestamp,
                            action:    action.clone(),
                            message,
                        });
                    }
                }
            }
        }
    }

    pub fn clear_hits(&mut self) {
        self.hits.clear();
        for r in &mut self.rules { r.hits = 0; }
    }
}

fn get_field_str<'a>(field: &str, pkt: &'a Packet) -> &'a str {
    match field {
        "src" | "ip.src"     => &pkt.src,
        "dst" | "ip.dst"     => &pkt.dst,
        "proto" | "protocol" => &pkt.protocol,
        "info"               => &pkt.info,
        _                    => "",
    }
}

fn get_field_num(field: &str, pkt: &Packet) -> Option<u64> {
    match field {
        "len" | "frame.len"  => Some(pkt.length as u64),
        "tcp.srcport"        => pkt.src_port.map(|p| p as u64),
        "tcp.dstport" | "port" => pkt.dst_port.map(|p| p as u64),
        "ip.ttl"             => {
            if pkt.bytes.len() > 22 { Some(pkt.bytes[22] as u64) } else { None }
        }
        _ => None,
    }
}

fn eval_cond(cond: &Condition, pkt: &Packet) -> bool {
    match cond {
        Condition::Contains { field, value } => {
            get_field_str(field, pkt).to_lowercase().contains(value.to_lowercase().as_str())
        }
        Condition::Equals { field, value } => {
            get_field_str(field, pkt).eq_ignore_ascii_case(value)
        }
        Condition::Num { field, op, value } => {
            if let Some(actual) = get_field_num(field, pkt) {
                match op {
                    CmpOp::Lt => actual < *value,
                    CmpOp::Le => actual <= *value,
                    CmpOp::Eq => actual == *value,
                    CmpOp::Ge => actual >= *value,
                    CmpOp::Gt => actual > *value,
                    CmpOp::Ne => actual != *value,
                }
            } else {
                false
            }
        }
        Condition::And(conds) => conds.iter().all(|c| eval_cond(c, pkt)),
        Condition::Or(conds)  => conds.iter().any(|c| eval_cond(c, pkt)),
        Condition::Not(inner) => !eval_cond(inner, pkt),
    }
}
