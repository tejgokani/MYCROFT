//! nuclei JSONL (`nuclei -jsonl`) → findings. One finding per emitted match.
//!
//! Each line is an independent JSON object. Malformed lines are **skipped**, not
//! fatal: a single corrupt record must never sink an otherwise-good import.

use serde::Deserialize;

use crate::{severity_from_str, NormalizeError, NormalizedFinding};

#[derive(Debug, Deserialize)]
struct NucleiRecord {
    #[serde(rename = "template-id")]
    template_id: Option<String>,
    info: Option<NucleiInfo>,
    host: Option<String>,
    #[serde(rename = "matched-at")]
    matched_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    name: Option<String>,
    severity: Option<String>,
    description: Option<String>,
}

pub(crate) fn parse(
    raw: &[u8],
    target_hint: Option<&str>,
) -> Result<Vec<NormalizedFinding>, NormalizeError> {
    let text = std::str::from_utf8(raw).map_err(|e| NormalizeError::Parse {
        tool: "nuclei",
        detail: format!("output is not valid UTF-8: {e}"),
    })?;

    let mut findings = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Defensive: skip any line that is not a well-formed nuclei record.
        let Ok(rec) = serde_json::from_str::<NucleiRecord>(line) else {
            continue;
        };

        let info = rec.info.unwrap_or(NucleiInfo {
            name: None,
            severity: None,
            description: None,
        });
        let template_id = rec.template_id.unwrap_or_default();
        let title = info
            .name
            .filter(|s| !s.is_empty())
            .or_else(|| (!template_id.is_empty()).then(|| template_id.clone()))
            .unwrap_or_else(|| "nuclei finding".to_string());

        let severity = severity_from_str(info.severity.as_deref().unwrap_or("info"));

        let target = rec
            .matched_at
            .filter(|s| !s.is_empty())
            .or(rec.host)
            .or_else(|| target_hint.map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string());

        let mut description = String::new();
        if !template_id.is_empty() {
            description.push_str(&format!("template: {template_id}"));
        }
        if let Some(d) = info.description.filter(|s| !s.is_empty()) {
            if !description.is_empty() {
                description.push('\n');
            }
            description.push_str(&d);
        }
        if description.is_empty() {
            description.push_str("nuclei match");
        }

        findings.push(NormalizedFinding {
            title,
            severity,
            target,
            description,
        });
    }
    Ok(findings)
}
