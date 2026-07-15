//! TUI application state and the command-execution glue.
//!
//! The pane is a thin front-end over `mycroft-runner`: whatever the operator types is
//! routed through the *same* guard + logger + capture path as `mycroft run`. There is
//! no alternate execution route (ARCHITECTURE.md).

use std::path::Path;

use mycroft_core::{Command, Engagement, IssuedBy};
use mycroft_guard::{Resolver, Scope};
use mycroft_runner::{infer_target, CollectingSink, RunOutcome, RunSpec, Runner};
use mycroft_store::Db;

/// Maximum number of output log lines retained in memory.
const MAX_OUTPUT_LINES: usize = 1000;

/// All mutable state the runner pane renders.
pub struct App {
    pub engagement: Engagement,
    pub scope: Scope,
    pub scope_rules: Vec<mycroft_core::ScopeRule>,
    pub commands: Vec<Command>,
    pub input: String,
    pub output: Vec<String>,
    pub should_quit: bool,
}

impl App {
    /// Build the initial state from the engagement database.
    pub fn new(db: &Db, engagement: Engagement) -> anyhow::Result<Self> {
        let scope_rules = db.list_scope_rules(engagement.id)?;
        let scope = Scope::compile(&scope_rules)?;
        let commands = db.list_commands(engagement.id).unwrap_or_default();
        let mut app = App {
            engagement,
            scope,
            scope_rules,
            commands,
            input: String::new(),
            output: Vec::new(),
            should_quit: false,
        };
        app.push_output("Mycroft runner pane ready. Type a command and press Enter.".into());
        app.push_output("Every command is scope-guarded and logged. Esc to quit.".into());
        Ok(app)
    }

    fn push_output(&mut self, line: String) {
        self.output.push(line);
        if self.output.len() > MAX_OUTPUT_LINES {
            let overflow = self.output.len() - MAX_OUTPUT_LINES;
            self.output.drain(0..overflow);
        }
    }

    fn refresh_commands(&mut self, db: &Db) {
        if let Ok(cmds) = db.list_commands(self.engagement.id) {
            self.commands = cmds;
        }
    }

    /// Execute the current input line through the guarded runner and record the result.
    ///
    /// Input is split on whitespace (v0 has no shell-style quoting inside the pane);
    /// for arguments containing spaces, use `mycroft run -- …` from the shell.
    pub fn execute(
        &mut self,
        db: &Db,
        resolver: &dyn Resolver,
        evidence_root: &Path,
        rt: &tokio::runtime::Runtime,
    ) {
        let line = self.input.trim().to_string();
        if line.is_empty() {
            return;
        }
        self.input.clear();
        self.push_output(format!("> {line}"));

        let tokens: Vec<String> = line.split_whitespace().map(String::from).collect();
        let program = tokens[0].clone();
        let target = match infer_target(&tokens) {
            Ok(t) => t,
            Err(e) => {
                self.push_output(format!(
                    "  ! {e} — prefix with the target, e.g. `nmap 10.0.0.5`"
                ));
                return;
            }
        };

        self.push_output(format!("  running (target {})…", target.host()));
        let spec = RunSpec {
            raw_cmd: line.clone(),
            program,
            args: tokens[1..].to_vec(),
            target,
            issued_by: IssuedBy::Human,
        };

        let runner = Runner::new(
            db,
            self.engagement.id,
            &self.scope,
            resolver,
            evidence_root.to_path_buf(),
        );
        let mut sink = CollectingSink::default();
        match rt.block_on(runner.run(spec, &mut sink)) {
            Ok(RunOutcome::Blocked { reason, .. }) => {
                self.push_output(format!("  BLOCKED — {reason}"));
            }
            Ok(RunOutcome::Executed {
                exit_code,
                findings,
                ..
            }) => {
                for l in String::from_utf8_lossy(&sink.stdout).lines() {
                    self.push_output(format!("  {l}"));
                }
                for l in String::from_utf8_lossy(&sink.stderr).lines() {
                    self.push_output(format!("  [err] {l}"));
                }
                let code = exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string());
                let note = if findings > 0 {
                    format!("; {findings} finding(s) normalized")
                } else {
                    String::new()
                };
                self.push_output(format!("  exit {code}; output captured as evidence{note}"));
            }
            Err(e) => self.push_output(format!("  error: {e:#}")),
        }
        self.refresh_commands(db);
    }
}
