//! Analyst notebook — timestamped notes tied to evidence items.

use std::collections::HashMap;
use crate::model::evidence::EvidenceRef;

// ─── Note ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Note {
    pub id:        u64,
    pub text:      String,
    pub timestamp: f64,
    /// Optional source evidence this note is attached to.
    pub evidence:  Option<EvidenceRef>,
    /// Free-form tags on this note.
    pub tags:      Vec<String>,
}

// ─── Notebook ─────────────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Notebook {
    notes:   Vec<Note>,
    next_id: u64,
    /// Index: evidence → note ids
    by_evidence: HashMap<String, Vec<u64>>,
}

impl Notebook {
    pub fn add(&mut self, text: impl Into<String>, evidence: Option<EvidenceRef>) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        let ev_key = evidence.as_ref().map(|e| e.to_string());
        let note = Note {
            id,
            text: text.into(),
            timestamp: now(),
            evidence,
            tags: Vec::new(),
        };
        if let Some(key) = ev_key {
            self.by_evidence.entry(key).or_default().push(id);
        }
        self.notes.push(note);
        id
    }

    pub fn add_tag(&mut self, note_id: u64, tag: impl Into<String>) {
        if let Some(n) = self.notes.iter_mut().find(|n| n.id == note_id) {
            n.tags.push(tag.into());
        }
    }

    pub fn delete(&mut self, note_id: u64) {
        self.notes.retain(|n| n.id != note_id);
        for ids in self.by_evidence.values_mut() {
            ids.retain(|&id| id != note_id);
        }
    }

    pub fn edit(&mut self, note_id: u64, text: impl Into<String>) {
        if let Some(n) = self.notes.iter_mut().find(|n| n.id == note_id) {
            n.text = text.into();
        }
    }

    pub fn all(&self) -> &[Note] { &self.notes }

    pub fn for_evidence(&self, ev: &EvidenceRef) -> Vec<&Note> {
        let key = ev.to_string();
        self.by_evidence.get(&key)
            .map(|ids| ids.iter()
                .filter_map(|id| self.notes.iter().find(|n| n.id == *id))
                .collect())
            .unwrap_or_default()
    }

    pub fn search(&self, q: &str) -> Vec<&Note> {
        let q = q.to_lowercase();
        self.notes.iter()
            .filter(|n| n.text.to_lowercase().contains(&q)
                || n.tags.iter().any(|t| t.to_lowercase().contains(&q)))
            .collect()
    }

    pub fn len(&self) -> usize { self.notes.len() }
    pub fn is_empty(&self) -> bool { self.notes.is_empty() }
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
