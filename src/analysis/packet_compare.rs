//! Structured comparison of two captured packets.

use std::collections::BTreeMap;

use crate::analysis::packet_fields;
use crate::net::packet::Packet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldDifferenceKind {
    Changed,
    LeftOnly,
    RightOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDifference {
    pub path: String,
    pub left: Option<String>,
    pub right: Option<String>,
    pub kind: FieldDifferenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketComparison {
    pub left_no: u64,
    pub right_no: u64,
    pub field_differences: Vec<FieldDifference>,
    pub first_byte_difference: Option<usize>,
    pub left_length: usize,
    pub right_length: usize,
}

pub fn compare(left: &Packet, right: &Packet) -> PacketComparison {
    let left_fields: BTreeMap<_, _> = packet_fields::extract_fields(left)
        .into_iter()
        .filter(|field| !matches!(field.path.as_str(), "frame.number" | "frame.time"))
        .map(|field| (field.path, field.value))
        .collect();
    let right_fields: BTreeMap<_, _> = packet_fields::extract_fields(right)
        .into_iter()
        .filter(|field| !matches!(field.path.as_str(), "frame.number" | "frame.time"))
        .map(|field| (field.path, field.value))
        .collect();

    let mut paths: Vec<_> = left_fields
        .keys()
        .chain(right_fields.keys())
        .cloned()
        .collect();
    paths.sort();
    paths.dedup();
    let field_differences = paths
        .into_iter()
        .filter_map(|path| {
            let left_value = left_fields.get(&path).cloned();
            let right_value = right_fields.get(&path).cloned();
            if left_value == right_value {
                return None;
            }
            let kind = match (&left_value, &right_value) {
                (Some(_), Some(_)) => FieldDifferenceKind::Changed,
                (Some(_), None) => FieldDifferenceKind::LeftOnly,
                (None, Some(_)) => FieldDifferenceKind::RightOnly,
                (None, None) => return None,
            };
            Some(FieldDifference {
                path,
                left: left_value,
                right: right_value,
                kind,
            })
        })
        .collect();

    let common = left.bytes.len().min(right.bytes.len());
    let first_byte_difference = left.bytes[..common]
        .iter()
        .zip(&right.bytes[..common])
        .position(|(left, right)| left != right)
        .or_else(|| (left.bytes.len() != right.bytes.len()).then_some(common));

    PacketComparison {
        left_no: left.no,
        right_no: right.no,
        field_differences,
        first_byte_difference,
        left_length: left.bytes.len(),
        right_length: right.bytes.len(),
    }
}
