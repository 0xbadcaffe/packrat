//! Tests for the analyst notebook: add, search, delete, tag, evidence linking.

use packrat_tui::analysis::notebook::Notebook;
use packrat_tui::model::evidence::{EvidenceRef, PacketRef};

// ── Basic CRUD ────────────────────────────────────────────────────────────────

#[test]
fn empty_notebook() {
    let nb = Notebook::default();
    assert!(nb.is_empty());
    assert_eq!(nb.len(), 0);
    assert!(nb.all().is_empty());
}

#[test]
fn add_one_note() {
    let mut nb = Notebook::default();
    let id = nb.add("C2 beacon detected", None);
    assert_eq!(nb.len(), 1);
    assert_eq!(id, 1);
    assert_eq!(nb.all()[0].text, "C2 beacon detected");
}

#[test]
fn add_multiple_notes_increments_id() {
    let mut nb = Notebook::default();
    let id1 = nb.add("First note", None);
    let id2 = nb.add("Second note", None);
    let id3 = nb.add("Third note", None);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(id3, 3);
    assert_eq!(nb.len(), 3);
}

#[test]
fn delete_note_by_id() {
    let mut nb = Notebook::default();
    let id1 = nb.add("Keep this", None);
    let id2 = nb.add("Delete this", None);
    nb.delete(id2);
    assert_eq!(nb.len(), 1);
    assert_eq!(nb.all()[0].id, id1);
}

#[test]
fn delete_nonexistent_id_is_noop() {
    let mut nb = Notebook::default();
    nb.add("Note", None);
    nb.delete(999);
    assert_eq!(nb.len(), 1);
}

#[test]
fn edit_note_text() {
    let mut nb = Notebook::default();
    let id = nb.add("Original text", None);
    nb.edit(id, "Updated text");
    assert_eq!(nb.all()[0].text, "Updated text");
}

#[test]
fn edit_nonexistent_id_is_noop() {
    let mut nb = Notebook::default();
    nb.add("Note", None);
    nb.edit(999, "Should not appear");
    assert_eq!(nb.all()[0].text, "Note");
}

// ── Tags on notes ─────────────────────────────────────────────────────────────

#[test]
fn add_tag_to_note() {
    let mut nb = Notebook::default();
    let id = nb.add("Suspicious traffic", None);
    nb.add_tag(id, "ioc");
    nb.add_tag(id, "priority-1");
    let note = &nb.all()[0];
    assert!(note.tags.contains(&"ioc".to_string()));
    assert!(note.tags.contains(&"priority-1".to_string()));
}

#[test]
fn add_tag_to_nonexistent_note_is_noop() {
    let mut nb = Notebook::default();
    nb.add_tag(999, "orphan");
    assert!(nb.is_empty());
}

// ── Search ────────────────────────────────────────────────────────────────────

#[test]
fn search_empty_query_returns_all() {
    let mut nb = Notebook::default();
    nb.add("C2 beacon", None);
    nb.add("DNS tunnel", None);
    // empty search → all
    let results = nb.search("");
    assert_eq!(results.len(), 2);
}

#[test]
fn search_by_text_match() {
    let mut nb = Notebook::default();
    nb.add("C2 beacon detected at 203.0.113.7", None);
    nb.add("DNS tunnel via high-entropy subdomains", None);
    nb.add("FTP cleartext credentials", None);

    let results = nb.search("dns");
    assert_eq!(results.len(), 1);
    assert!(results[0].text.contains("DNS"));
}

#[test]
fn search_case_insensitive() {
    let mut nb = Notebook::default();
    nb.add("SMB Lateral Movement detected", None);
    let r1 = nb.search("smb");
    let r2 = nb.search("SMB");
    let r3 = nb.search("Smb");
    assert_eq!(r1.len(), 1);
    assert_eq!(r2.len(), 1);
    assert_eq!(r3.len(), 1);
}

#[test]
fn search_by_tag() {
    let mut nb = Notebook::default();
    let id = nb.add("Kerberos spray attempt", None);
    nb.add_tag(id, "brute-force");
    nb.add("Normal traffic note", None);

    let results = nb.search("brute-force");
    assert_eq!(results.len(), 1);
    assert!(results[0].tags.contains(&"brute-force".to_string()));
}

#[test]
fn search_no_match_returns_empty() {
    let mut nb = Notebook::default();
    nb.add("Note about ARP", None);
    let results = nb.search("kerberos");
    assert!(results.is_empty());
}

#[test]
fn search_multiple_matches() {
    let mut nb = Notebook::default();
    nb.add("First TLS anomaly", None);
    nb.add("Second TLS anomaly", None);
    nb.add("Unrelated note", None);
    let results = nb.search("tls");
    assert_eq!(results.len(), 2);
}

// ── Evidence linking ──────────────────────────────────────────────────────────

#[test]
fn note_with_packet_evidence() {
    let mut nb = Notebook::default();
    let ev = EvidenceRef::Packet(PacketRef(42));
    let id = nb.add("Matched IOC in packet 42", Some(ev.clone()));
    let note = nb.all().iter().find(|n| n.id == id).unwrap();
    assert!(note.evidence.is_some());
}

#[test]
fn for_evidence_returns_linked_notes() {
    let mut nb = Notebook::default();
    let ev = EvidenceRef::Packet(PacketRef(7));
    nb.add("Note A about pkt 7", Some(ev.clone()));
    nb.add("Note B about pkt 7", Some(ev.clone()));
    nb.add("Unlinked note", None);

    let linked = nb.for_evidence(&ev);
    assert_eq!(linked.len(), 2);
}

#[test]
fn for_evidence_no_match_returns_empty() {
    let mut nb = Notebook::default();
    nb.add("Note without evidence", None);
    let ev = EvidenceRef::Packet(PacketRef(99));
    let linked = nb.for_evidence(&ev);
    assert!(linked.is_empty());
}

// ── Delete cleans up evidence index ──────────────────────────────────────────

#[test]
fn delete_removes_from_evidence_index() {
    let mut nb = Notebook::default();
    let ev = EvidenceRef::Packet(PacketRef(3));
    let id = nb.add("Linked note", Some(ev.clone()));
    nb.delete(id);
    let linked = nb.for_evidence(&ev);
    assert!(linked.is_empty());
}
