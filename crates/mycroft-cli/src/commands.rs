//! CLI command handlers. Thin glue over `mycroft-store`; no business logic here.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use mycroft_core::{
    FindingStatus, GuardDecision, IssuedBy, ScopeKind, ScopeRuleType, Target, Tool,
};
use mycroft_guard::{evaluate, Scope, SystemResolver};
use mycroft_runner::{ConsoleSink, RunOutcome, RunSpec, Runner};
use mycroft_store::{Db, NewFinding};

/// Open the engagement DB, applying the encryption key seam when provided.
fn open_db(path: &Path, key: Option<&str>) -> Result<Db> {
    match key {
        Some(k) => Db::open_with_key(path, k),
        None => Db::open(path),
    }
    .with_context(|| format!("opening engagement database at {}", path.display()))
}

/// Load the single engagement in this file (one engagement per DB).
fn sole_engagement(db: &Db) -> Result<mycroft_core::Engagement> {
    db.list_engagements()?
        .into_iter()
        .next()
        .context("no engagement in this database — run `mycroft init` first")
}

#[derive(Args)]
pub struct InitArgs {
    /// Engagement name (e.g. `acme-external-2026q3`).
    #[arg(long)]
    pub name: String,
    /// Client name (e.g. `ACME Corp`).
    #[arg(long)]
    pub client: String,
    /// Encrypt the engagement DB at rest (requires a passphrase; needs the `encryption` build).
    #[arg(long, default_value_t = false)]
    pub encrypt: bool,
}

pub fn init(path: &Path, key: Option<&str>, args: InitArgs) -> Result<()> {
    if path.exists() {
        bail!(
            "{} already exists — refusing to overwrite an engagement",
            path.display()
        );
    }
    if args.encrypt && key.is_none() {
        bail!("--encrypt requires a passphrase (pass --passphrase or set MYCROFT_KEY)");
    }
    // When not encrypting, do not apply a stray key.
    let key = if args.encrypt { key } else { None };

    let db = open_db(path, key)?;
    let engagement = db
        .create_engagement(&args.name, &args.client)
        .context("creating engagement")?;

    println!(
        "Initialized engagement '{}' for '{}' (id {}) at {}",
        engagement.name,
        engagement.client,
        engagement.id,
        path.display()
    );
    println!("Genesis audit entry written. Add scope with `mycroft scope add`.");
    if args.encrypt {
        println!("Encryption-at-rest requested (effective when built with --features encryption).");
    }
    Ok(())
}

#[derive(Subcommand)]
pub enum ScopeCommand {
    /// Add a scope rule.
    Add(ScopeAddArgs),
    /// List scope rules.
    List,
    /// Preview the guard's verdict for a target (dry-run; nothing is executed).
    Check(ScopeCheckArgs),
}

#[derive(Args)]
pub struct ScopeCheckArgs {
    /// The target to check: an IP, hostname, or URL.
    pub target: String,
}

#[derive(Args)]
pub struct ScopeAddArgs {
    /// The pattern: a CIDR (`10.0.0.0/24`), domain (`*.example.com`), or URL.
    pub pattern: String,
    /// Include or exclude. Exclusions (`out`) take precedence during enforcement.
    #[arg(long, value_parser = ["in", "out"], default_value = "in")]
    pub kind: String,
    /// How to interpret the pattern.
    #[arg(long = "type", value_parser = ["cidr", "domain", "url"])]
    pub rule_type: String,
}

pub fn scope(path: &Path, key: Option<&str>, cmd: ScopeCommand) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    match cmd {
        ScopeCommand::Add(args) => {
            let kind = ScopeKind::parse(&args.kind)?;
            let rule_type = ScopeRuleType::parse(&args.rule_type)?;
            let rule = db.add_scope_rule(engagement.id, &args.pattern, kind, rule_type)?;
            println!(
                "Added scope rule #{}: [{}] {} ({})",
                rule.id, rule.kind, rule.pattern, rule.rule_type
            );
        }
        ScopeCommand::List => {
            let rules = db.list_scope_rules(engagement.id)?;
            if rules.is_empty() {
                println!("No scope rules yet. Add one with `mycroft scope add`.");
            } else {
                println!("Scope for '{}':", engagement.name);
                for r in rules {
                    println!(
                        "  #{:<3} [{:<3}] {:<10} {}",
                        r.id, r.kind, r.rule_type, r.pattern
                    );
                }
            }
        }
        ScopeCommand::Check(args) => {
            let rules = db.list_scope_rules(engagement.id)?;
            let scope = Scope::compile(&rules).context("compiling scope rules")?;
            let target = Target::parse(&args.target).context("parsing target")?;
            match evaluate(&target, &scope, &SystemResolver) {
                GuardDecision::Allow { resolved } => {
                    let addrs = resolved
                        .addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    let addrs = if addrs.is_empty() {
                        "—".to_string()
                    } else {
                        addrs
                    };
                    println!("ALLOW  {}  (resolved: {addrs})", target.host());
                }
                GuardDecision::Block { reason } => {
                    println!("BLOCK  {}  — {reason}", target.host());
                }
            }
        }
    }
    Ok(())
}

#[derive(Args)]
pub struct RunArgs {
    /// Explicit target to scope-check (IP, host, or URL). If omitted, Mycroft infers
    /// it from the command; `--target` is authoritative when detection is ambiguous.
    #[arg(long)]
    pub target: Option<String>,
    /// Record this command as AI-issued (default: human). AI takes the same guarded path.
    #[arg(long, default_value_t = false)]
    pub ai: bool,
    /// The tool and its arguments, after `--`, e.g. `-- nmap -sV 10.0.0.5`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    pub command: Vec<String>,
}

/// Where per-command evidence is written: a `<db-stem>.evidence/` dir beside the DB.
fn evidence_root_for(db_path: &Path) -> PathBuf {
    let stem = db_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("mycroft");
    db_path.with_file_name(format!("{stem}.evidence"))
}

/// Determine the target to scope-check. `--target` wins; otherwise infer from the
/// command's tokens via the shared [`mycroft_runner::infer_target`].
fn detect_target(explicit: Option<&str>, command: &[String]) -> Result<Target> {
    if let Some(t) = explicit {
        return Target::parse(t).with_context(|| format!("invalid --target `{t}`"));
    }
    mycroft_runner::infer_target(command).map_err(|e| anyhow::anyhow!("{e}; pass --target <host>"))
}

pub fn run(path: &Path, key: Option<&str>, args: RunArgs) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let rules = db.list_scope_rules(engagement.id)?;
    let scope = Scope::compile(&rules).context("compiling scope rules")?;

    let program = args.command[0].clone();
    let cmd_args = args.command[1..].to_vec();
    let target = detect_target(args.target.as_deref(), &args.command)?;
    let issued_by = if args.ai {
        IssuedBy::Ai
    } else {
        IssuedBy::Human
    };

    let spec = RunSpec {
        raw_cmd: args.command.join(" "),
        program,
        args: cmd_args,
        target,
        issued_by,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting async runtime")?;
    let resolver = SystemResolver;
    let runner = Runner::new(
        &db,
        engagement.id,
        &scope,
        &resolver,
        evidence_root_for(path),
    );
    let mut sink = ConsoleSink;
    let outcome = runtime.block_on(runner.run(spec, &mut sink))?;

    match outcome {
        RunOutcome::Blocked { command, reason } => {
            eprintln!("\n[mycroft] BLOCKED (command #{}) — {reason}", command.id);
            std::process::exit(3);
        }
        RunOutcome::Executed {
            command,
            exit_code,
            findings,
        } => {
            let code = exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_string());
            let note = if findings > 0 {
                format!("; {findings} finding(s) normalized")
            } else {
                String::new()
            };
            eprintln!(
                "\n[mycroft] recorded command #{} (exit {code}); output captured as evidence{note}",
                command.id
            );
            std::process::exit(exit_code.unwrap_or(0));
        }
    }
}

pub fn list_commands(path: &Path, key: Option<&str>) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let cmds = db.list_commands(engagement.id)?;
    if cmds.is_empty() {
        println!("No commands recorded yet. Run one with `mycroft run -- <tool> …`.");
        return Ok(());
    }
    println!("Commands for '{}':", engagement.name);
    for c in cmds {
        let status = if c.blocked {
            "BLOCKED".to_string()
        } else {
            format!(
                "exit {}",
                c.exit_code
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "?".to_string())
            )
        };
        println!(
            "  #{:<3} [{:<5}] {:<9} {:<20} {}",
            c.id, c.issued_by, status, c.target, c.raw_cmd
        );
    }
    Ok(())
}

#[derive(Args)]
pub struct ImportArgs {
    /// The tool that produced the file.
    #[arg(long, value_parser = ["nmap", "nuclei"])]
    pub tool: String,
    /// Path to the tool's native output (nmap XML from `-oX`, nuclei JSONL from `-jsonl`).
    pub file: PathBuf,
    /// Optional target hint for records that don't carry their own.
    #[arg(long)]
    pub target: Option<String>,
}

pub fn import(path: &Path, key: Option<&str>, args: ImportArgs) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let tool = Tool::from_name(&args.tool);
    let bytes =
        std::fs::read(&args.file).with_context(|| format!("reading {}", args.file.display()))?;

    let normalized = mycroft_normalize::normalize(&tool, &bytes, args.target.as_deref())
        .with_context(|| format!("normalizing {} output", tool))?;

    let mut count = 0;
    for nf in normalized {
        db.record_finding(
            engagement.id,
            &NewFinding {
                title: nf.title,
                severity: nf.severity,
                source_tool: tool.clone(),
                target: nf.target,
                description: nf.description,
                status: FindingStatus::New,
                command_id: None,
            },
        )?;
        count += 1;
    }
    println!(
        "Imported {count} finding(s) from {} ({}).",
        args.file.display(),
        tool
    );
    Ok(())
}

pub fn findings(path: &Path, key: Option<&str>) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let findings = db.list_findings(engagement.id)?;
    if findings.is_empty() {
        println!("No findings yet. Run a scan through `mycroft run` or `mycroft import`.");
        return Ok(());
    }
    println!("Findings for '{}':", engagement.name);
    for f in findings {
        println!(
            "  #{:<3} {:<8} {:<7} {:<24} {}",
            f.id,
            f.severity.to_string().to_uppercase(),
            f.source_tool,
            f.target,
            f.title
        );
    }
    Ok(())
}

#[derive(Args)]
pub struct ReportArgs {
    /// Output directory (default: `<db-stem>.report/` beside the database).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn report(path: &Path, key: Option<&str>, args: ReportArgs) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let out_dir = args.out.unwrap_or_else(|| {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("mycroft");
        path.with_file_name(format!("{stem}.report"))
    });

    let written = mycroft_report::write(&db, engagement.id, &out_dir)
        .context("generating engagement report")?;

    println!(
        "Report for '{}' written to {}:",
        engagement.name,
        out_dir.display()
    );
    println!("  {}", written.markdown.display());
    println!("  {}", written.html.display());
    println!("  {}", written.typst.display());
    match written.pdf {
        Some(pdf) => println!("  {} (compiled via typst)", pdf.display()),
        None => println!(
            "  (no PDF: install `typst` to compile report.typ, or print report.html from a browser)"
        ),
    }
    Ok(())
}

pub fn tui(path: &Path, key: Option<&str>) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let evidence_root = evidence_root_for(path);
    mycroft_tui::run(db, engagement.id, evidence_root).context("running the TUI")
}

pub fn status(path: &Path, key: Option<&str>) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    let scope_count = db.list_scope_rules(engagement.id)?.len();
    let command_count = db.list_commands(engagement.id)?.len();
    let finding_count = db.list_findings(engagement.id)?.len();
    println!("Engagement : {} (id {})", engagement.name, engagement.id);
    println!("Client     : {}", engagement.client);
    println!("Status     : {}", engagement.status);
    println!("Created    : {}", engagement.created_at);
    println!("Scope rules: {scope_count}");
    println!("Commands   : {command_count}");
    println!("Findings   : {finding_count}");
    Ok(())
}

pub fn verify(path: &Path, key: Option<&str>) -> Result<()> {
    let db = open_db(path, key)?;
    let engagement = sole_engagement(&db)?;
    match db.verify_audit(engagement.id) {
        Ok(()) => {
            println!("Audit chain intact for '{}'.", engagement.name);
            Ok(())
        }
        Err(e) => {
            Err(e).context("audit verification failed — the engagement record may be tampered")
        }
    }
}
