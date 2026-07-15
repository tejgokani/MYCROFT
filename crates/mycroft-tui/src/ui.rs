//! Rendering for the runner pane. Pure view over [`App`] — no state mutation here.

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(3), // input
            Constraint::Length(1), // help
        ])
        .split(f.area());

    draw_header(f, app, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(root[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(body[0]);

    draw_scope(f, app, left[0]);
    draw_commands(f, app, left[1]);
    draw_output(f, app, body[1]);
    draw_input(f, app, root[2]);
    draw_help(f, root[3]);
}

fn draw_header(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let e = &app.engagement;
    let text = Line::from(vec![
        Span::styled(
            format!(" {} ", e.name),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  client: {}   status: {}", e.client, e.status)),
    ]);
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Mycroft"));
    f.render_widget(p, area);
}

fn draw_scope(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = if app.scope_rules.is_empty() {
        vec![ListItem::new("(no scope rules — everything is denied)")]
    } else {
        app.scope_rules
            .iter()
            .map(|r| {
                let color = if r.kind == mycroft_core::ScopeKind::Out {
                    Color::Red
                } else {
                    Color::Green
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{}] ", r.kind), Style::default().fg(color)),
                    Span::raw(format!("{:<7} {}", r.rule_type, r.pattern)),
                ]))
            })
            .collect()
    };
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Scope"));
    f.render_widget(list, area);
}

fn draw_commands(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let items: Vec<ListItem> = app
        .commands
        .iter()
        .map(|c| {
            let (label, color) = if c.blocked {
                ("BLOCK".to_string(), Color::Red)
            } else {
                (
                    format!(
                        "exit{}",
                        c.exit_code.map(|x| x.to_string()).unwrap_or_default()
                    ),
                    Color::Green,
                )
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{label:<7}"), Style::default().fg(color)),
                Span::raw(format!(" #{:<3} {}", c.id, c.raw_cmd)),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Commands (newest first)"),
    );
    f.render_widget(list, area);
}

fn draw_output(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Show the tail of the output that fits the pane height (auto-scroll to bottom).
    let inner_height = area.height.saturating_sub(2) as usize;
    let start = app.output.len().saturating_sub(inner_height);
    let lines: Vec<Line> = app.output[start..]
        .iter()
        .map(|l| {
            if l.starts_with('>') {
                Line::from(Span::styled(
                    l.clone(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ))
            } else if l.contains("BLOCKED") {
                Line::from(Span::styled(l.clone(), Style::default().fg(Color::Red)))
            } else {
                Line::from(l.clone())
            }
        })
        .collect();
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Output"))
        .wrap(Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_input(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let p = Paragraph::new(Line::from(vec![
        Span::styled("❯ ", Style::default().fg(Color::Cyan)),
        Span::raw(app.input.as_str()),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Run a command"),
    );
    f.render_widget(p, area);
    // Place the cursor after the prompt + current input.
    let x = area.x + 3 + app.input.chars().count() as u16;
    let y = area.y + 1;
    f.set_cursor_position((x, y));
}

fn draw_help(f: &mut Frame, area: ratatui::layout::Rect) {
    let help = Paragraph::new(Line::from(Span::styled(
        " Enter: run · Backspace: edit · Esc / Ctrl-C: quit ",
        Style::default().fg(Color::DarkGray),
    )));
    f.render_widget(help, area);
}
