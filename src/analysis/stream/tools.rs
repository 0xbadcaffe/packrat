use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMatch {
    pub segment_index: usize,
    pub byte_offset: usize,
}

#[derive(Debug, Clone, Default)]
pub struct StreamOverlayState {
    pub title: String,
    pub segments: Vec<(bool, Vec<u8>)>,
    pub search_query: String,
    pub searching: bool,
    pub matches: Vec<StreamMatch>,
    pub selected_match: usize,
}

impl StreamOverlayState {
    pub fn new(title: String, segments: Vec<(bool, Vec<u8>)>) -> Self {
        Self {
            title,
            segments,
            ..Self::default()
        }
    }

    pub fn refresh_matches(&mut self) {
        self.matches = search_segments(&self.segments, self.search_query.as_bytes());
        self.selected_match = self
            .selected_match
            .min(self.matches.len().saturating_sub(1));
    }

    pub fn next_match(&mut self) {
        if !self.matches.is_empty() {
            self.selected_match = (self.selected_match + 1) % self.matches.len();
        }
    }

    pub fn previous_match(&mut self) {
        if !self.matches.is_empty() {
            self.selected_match = if self.selected_match == 0 {
                self.matches.len() - 1
            } else {
                self.selected_match - 1
            };
        }
    }
}

pub fn search_segments(segments: &[(bool, Vec<u8>)], needle: &[u8]) -> Vec<StreamMatch> {
    if needle.is_empty() {
        return Vec::new();
    }
    let needle: Vec<_> = needle.iter().map(u8::to_ascii_lowercase).collect();
    let mut matches = Vec::new();
    for (segment_index, (_, bytes)) in segments.iter().enumerate() {
        if bytes.len() < needle.len() {
            continue;
        }
        for byte_offset in 0..=bytes.len() - needle.len() {
            if bytes[byte_offset..byte_offset + needle.len()]
                .iter()
                .map(u8::to_ascii_lowercase)
                .eq(needle.iter().copied())
            {
                matches.push(StreamMatch {
                    segment_index,
                    byte_offset,
                });
            }
        }
    }
    matches
}

pub fn export_segments(
    segments: &[(bool, Vec<u8>)],
    base_path: impl AsRef<Path>,
) -> std::io::Result<(PathBuf, PathBuf)> {
    let base = base_path.as_ref();
    let parent = base.parent().unwrap_or_else(|| Path::new("."));
    let stem = base
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("packrat_stream");
    let a_to_b = parent.join(format!("{stem}.a-to-b.bin"));
    let b_to_a = parent.join(format!("{stem}.b-to-a.bin"));
    let mut left = Vec::new();
    let mut right = Vec::new();
    for (from_a, bytes) in segments {
        if *from_a {
            left.extend_from_slice(bytes);
        } else {
            right.extend_from_slice(bytes);
        }
    }
    std::fs::write(&a_to_b, left)?;
    if let Err(error) = std::fs::write(&b_to_a, right) {
        let _ = std::fs::remove_file(&a_to_b);
        return Err(error);
    }
    Ok((a_to_b, b_to_a))
}
