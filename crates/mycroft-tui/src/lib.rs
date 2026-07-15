//! # mycroft-tui — the terminal UI.
//!
//! v0 ships the **runner pane**: an interactive console where typed commands are
//! routed through the same guarded, logged runner as `mycroft run`. Scope and command
//! history render live alongside. Later phases add the findings pane and (v1) AI pane.

#![forbid(unsafe_code)]

mod app;
mod ui;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use mycroft_core::EngagementId;
use mycroft_guard::SystemResolver;
use mycroft_store::Db;

use crate::app::App;

/// Launch the runner pane for an engagement and block until the operator quits.
///
/// `evidence_root` is where captured command output is written (matching the CLI's
/// `<db-stem>.evidence/` convention).
pub fn run(db: Db, engagement_id: EngagementId, evidence_root: PathBuf) -> Result<()> {
    let engagement = db.get_engagement(engagement_id)?;
    let mut app = App::new(&db, engagement)?;

    let resolver = SystemResolver;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // ratatui::init sets raw mode + alternate screen; restore() is called on every exit.
    let mut terminal = ratatui::init();
    let result = event_loop(
        &mut terminal,
        &mut app,
        &db,
        &resolver,
        &evidence_root,
        &runtime,
    );
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    db: &Db,
    resolver: &SystemResolver,
    evidence_root: &std::path::Path,
    runtime: &tokio::runtime::Runtime,
) -> Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui::draw(f, app))?;

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Esc => app.should_quit = true,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.should_quit = true
                }
                KeyCode::Enter => app.execute(db, resolver, evidence_root, runtime),
                KeyCode::Backspace => {
                    app.input.pop();
                }
                KeyCode::Char(c) => app.input.push(c),
                _ => {}
            }
        }
    }
    Ok(())
}
