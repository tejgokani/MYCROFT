//! `mycroft` — the engagement console CLI.
//!
//! Phase 0 wires the engagement lifecycle: `init`, `scope`, `status`, `verify`.
//! `run`, `import`, and `report` land in their respective phases.

mod commands;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Mycroft — the operating system for a pentest engagement: recon to report, one console.
#[derive(Parser)]
#[command(name = "mycroft", version, about, long_about = None)]
struct Cli {
    /// Path to the engagement database (one file per engagement).
    #[arg(long, global = true, default_value = "mycroft.db")]
    db: PathBuf,

    /// Passphrase for an encrypted engagement DB (or set MYCROFT_KEY). Prefer the env var.
    #[arg(long, global = true)]
    passphrase: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new engagement database.
    Init(commands::InitArgs),
    /// Manage the engagement scope.
    #[command(subcommand)]
    Scope(commands::ScopeCommand),
    /// Run a tool through Mycroft: scope-guarded, logged, output captured.
    Run(commands::RunArgs),
    /// List recorded commands (executions and blocked attempts).
    Commands,
    /// Import an existing tool output file (nmap XML, nuclei JSONL) into findings.
    Import(commands::ImportArgs),
    /// List normalized findings, most severe first.
    Findings,
    /// Generate the engagement report (Markdown + HTML + typst, and PDF if typst is present).
    Report(commands::ReportArgs),
    /// Open the interactive runner pane (TUI).
    Tui,
    /// Show engagement summary.
    Status,
    /// Verify the tamper-evident audit chain.
    Verify,
}

fn main() {
    if let Err(e) = run() {
        // Actionable, single-line error to stderr (CLAUDE.md §8).
        eprintln!("mycroft: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let key = resolve_key(cli.passphrase);
    match cli.command {
        Command::Init(args) => commands::init(&cli.db, key.as_deref(), args),
        Command::Scope(cmd) => commands::scope(&cli.db, key.as_deref(), cmd),
        Command::Run(args) => commands::run(&cli.db, key.as_deref(), args),
        Command::Commands => commands::list_commands(&cli.db, key.as_deref()),
        Command::Import(args) => commands::import(&cli.db, key.as_deref(), args),
        Command::Findings => commands::findings(&cli.db, key.as_deref()),
        Command::Report(args) => commands::report(&cli.db, key.as_deref(), args),
        Command::Tui => commands::tui(&cli.db, key.as_deref()),
        Command::Status => commands::status(&cli.db, key.as_deref()),
        Command::Verify => commands::verify(&cli.db, key.as_deref()),
    }
}

/// Encryption key precedence: `--passphrase` flag, else `MYCROFT_KEY` env, else none.
fn resolve_key(passphrase: Option<String>) -> Option<String> {
    passphrase.or_else(|| std::env::var("MYCROFT_KEY").ok())
}
