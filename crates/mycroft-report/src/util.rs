//! Small formatting/escaping helpers shared by the renderers.

use mycroft_core::Timestamp;
use time::macros::format_description;

/// Human-readable UTC timestamp, e.g. `2026-07-15 14:35 UTC`.
pub fn fmt_ts(ts: Timestamp) -> String {
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute] UTC");
    ts.format(&fmt).unwrap_or_else(|_| ts.to_string())
}

/// Escape text for safe inclusion in HTML element content / attributes.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escape a string for a typst string literal (double-quoted).
pub fn typst_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
