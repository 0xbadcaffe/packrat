pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

pub fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s[..width].to_string()
    } else {
        format!("{:<width$}", s, width = width)
    }
}

pub fn fmt_bytes(b: u64) -> String {
    if b < 1_024 {
        format!("{}B", b)
    } else if b < 1_048_576 {
        format!("{:.1}K", b as f64 / 1_024.0)
    } else {
        format!("{:.1}M", b as f64 / 1_048_576.0)
    }
}
