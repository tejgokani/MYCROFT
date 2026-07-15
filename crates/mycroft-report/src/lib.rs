//! # mycroft-report — engagement report export.
//!
//! Renders the findings model (the source of truth) into client-ready output:
//! **Markdown** and a **self-contained, printable HTML** page (both always produced,
//! zero external tools), plus a **typst source** document. If a `typst` binary is on
//! PATH, a **PDF** is compiled from that source as well.
//!
//! The report is strictly read-only over the store (ARCHITECTURE.md) and surfaces the
//! result of the tamper-evident audit-chain verification so a reader can trust it.

#![forbid(unsafe_code)]

mod data;
mod html;
mod md;
mod typ;
mod util;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mycroft_core::EngagementId;
use mycroft_store::Db;

pub use data::ReportData;

/// The rendered report in every text format.
pub struct ReportBundle {
    pub markdown: String,
    pub html: String,
    pub typst: String,
}

/// A written report: the files produced on disk.
#[derive(Debug, Default)]
pub struct WrittenReport {
    pub markdown: PathBuf,
    pub html: PathBuf,
    pub typst: PathBuf,
    /// Present only if a `typst` binary compiled the PDF.
    pub pdf: Option<PathBuf>,
}

/// Render the report for an engagement in all text formats.
pub fn build(db: &Db, engagement_id: EngagementId) -> Result<ReportBundle> {
    let engagement = db
        .get_engagement(engagement_id)
        .context("loading engagement")?;
    let data = ReportData::gather(db, engagement)?;
    Ok(ReportBundle {
        markdown: md::render(&data),
        html: html::render(&data),
        typst: typ::render(&data),
    })
}

/// Render and write the report into `out_dir` (created if absent). Attempts a PDF via
/// a `typst` binary if one is available; its absence is not an error.
pub fn write(db: &Db, engagement_id: EngagementId, out_dir: &Path) -> Result<WrittenReport> {
    let bundle = build(db, engagement_id)?;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("creating report directory {}", out_dir.display()))?;

    let markdown = out_dir.join("report.md");
    let html = out_dir.join("report.html");
    let typst = out_dir.join("report.typ");
    std::fs::write(&markdown, &bundle.markdown).context("writing report.md")?;
    std::fs::write(&html, &bundle.html).context("writing report.html")?;
    std::fs::write(&typst, &bundle.typst).context("writing report.typ")?;

    let pdf = compile_pdf(&typst, out_dir);

    Ok(WrittenReport {
        markdown,
        html,
        typst,
        pdf,
    })
}

/// Compile the typst source to PDF via a `typst` binary if one is on PATH. Returns
/// `None` (not an error) when typst is unavailable or the compile fails — the other
/// formats already give a complete report.
fn compile_pdf(typst_path: &Path, out_dir: &Path) -> Option<PathBuf> {
    let pdf_path = out_dir.join("report.pdf");
    let status = std::process::Command::new("typst")
        .arg("compile")
        .arg(typst_path)
        .arg(&pdf_path)
        .status()
        .ok()?;
    (status.success() && pdf_path.exists()).then_some(pdf_path)
}
