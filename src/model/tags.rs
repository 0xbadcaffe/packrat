//! Tags, bookmarks, and mark state shared across notebook and evidence systems.

use std::collections::{HashMap, HashSet};
use crate::model::evidence::EvidenceRef;

/// A user-defined label attached to any evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Tag(pub String);

impl Tag {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Tag registry — tracks which tags are applied to which evidence items.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct TagStore {
    /// evidence → set of tags
    items: HashMap<EvidenceRef, HashSet<String>>,
    /// tag → set of evidence (reverse index)
    by_tag: HashMap<String, HashSet<EvidenceRef>>,
}

impl TagStore {
    pub fn add(&mut self, ev: EvidenceRef, tag: impl Into<String>) {
        let t = tag.into();
        self.items.entry(ev.clone()).or_default().insert(t.clone());
        self.by_tag.entry(t).or_default().insert(ev);
    }

    pub fn remove(&mut self, ev: &EvidenceRef, tag: &str) {
        if let Some(set) = self.items.get_mut(ev) { set.remove(tag); }
        if let Some(set) = self.by_tag.get_mut(tag) { set.remove(ev); }
    }

    pub fn tags_for(&self, ev: &EvidenceRef) -> Vec<&str> {
        self.items.get(ev)
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub fn items_with_tag(&self, tag: &str) -> Vec<&EvidenceRef> {
        self.by_tag.get(tag)
            .map(|s| s.iter().collect())
            .unwrap_or_default()
    }

    pub fn has_tag(&self, ev: &EvidenceRef, tag: &str) -> bool {
        self.items.get(ev).map(|s| s.contains(tag)).unwrap_or(false)
    }

    pub fn all_tags(&self) -> Vec<&str> {
        self.by_tag.keys().map(String::as_str).collect()
    }

    pub fn clear_item(&mut self, ev: &EvidenceRef) {
        if let Some(tags) = self.items.remove(ev) {
            for t in &tags {
                if let Some(set) = self.by_tag.get_mut(t) { set.remove(ev); }
            }
        }
    }

    pub fn is_marked(&self, ev: &EvidenceRef) -> bool {
        self.has_tag(ev, "__marked__")
    }

    pub fn mark(&mut self, ev: EvidenceRef) {
        self.add(ev, "__marked__");
    }

    pub fn unmark(&mut self, ev: EvidenceRef) {
        self.remove(&ev, "__marked__");
    }

    pub fn marked_items(&self) -> Vec<&EvidenceRef> {
        self.items_with_tag("__marked__")
    }
}
