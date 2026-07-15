//! Process execution and dual capture.
//!
//! The child is spawned with an **argument vector, never a shell** (CLAUDE.md
//! deviation §7): no `sh -c`, so untrusted args are never interpolated into a shell.
//! stdout and stderr are streamed concurrently to (a) their evidence files, (b) a
//! rolling sha256, and (c) the live [`OutputSink`], reading both to EOF before
//! awaiting exit so a chatty child can never deadlock on a full pipe.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::sink::OutputSink;

/// Result of a captured execution.
pub struct Capture {
    /// Process exit code, or `None` if terminated by a signal.
    pub exit_code: Option<i32>,
    /// Hex sha256 of the full stdout stream (evidence integrity).
    pub stdout_sha256: String,
    /// Hex sha256 of the full stderr stream.
    pub stderr_sha256: String,
}

/// Spawn `program` with `args`, streaming output to files + `sink` and hashing it.
pub async fn run_and_capture(
    program: &str,
    args: &[String],
    stdout_path: &Path,
    stderr_path: &Path,
    sink: &mut dyn OutputSink,
) -> Result<Capture> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to launch `{program}`"))?;

    let mut cout = child
        .stdout
        .take()
        .context("child stdout was not captured")?;
    let mut cerr = child
        .stderr
        .take()
        .context("child stderr was not captured")?;

    let mut fo = tokio::fs::File::create(stdout_path)
        .await
        .with_context(|| format!("creating {}", stdout_path.display()))?;
    let mut fe = tokio::fs::File::create(stderr_path)
        .await
        .with_context(|| format!("creating {}", stderr_path.display()))?;

    let mut ho = Sha256::new();
    let mut he = Sha256::new();
    let mut bo = vec![0u8; 16 * 1024];
    let mut be = vec![0u8; 16 * 1024];
    let mut out_done = false;
    let mut err_done = false;

    while !(out_done && err_done) {
        tokio::select! {
            r = cout.read(&mut bo), if !out_done => {
                let n = r.context("reading child stdout")?;
                if n == 0 {
                    out_done = true;
                } else {
                    fo.write_all(&bo[..n]).await.context("writing stdout evidence")?;
                    ho.update(&bo[..n]);
                    sink.on_stdout(&bo[..n]);
                }
            }
            r = cerr.read(&mut be), if !err_done => {
                let n = r.context("reading child stderr")?;
                if n == 0 {
                    err_done = true;
                } else {
                    fe.write_all(&be[..n]).await.context("writing stderr evidence")?;
                    he.update(&be[..n]);
                    sink.on_stderr(&be[..n]);
                }
            }
        }
    }

    fo.flush().await.ok();
    fe.flush().await.ok();
    let status = child.wait().await.context("waiting for child to exit")?;

    Ok(Capture {
        exit_code: status.code(),
        stdout_sha256: hex::encode(ho.finalize()),
        stderr_sha256: hex::encode(he.finalize()),
    })
}
