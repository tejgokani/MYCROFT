//! Where live output goes while a command runs. Decoupling this lets the same runner
//! feed the terminal (CLI), a TUI pane, or a test buffer without any branching.

use std::io::Write;

/// A destination for live stdout/stderr chunks as a command executes.
pub trait OutputSink {
    /// Called with each stdout chunk as it is read.
    fn on_stdout(&mut self, chunk: &[u8]);
    /// Called with each stderr chunk as it is read.
    fn on_stderr(&mut self, chunk: &[u8]);
}

/// Streams output straight to the process's own stdout/stderr (the CLI `run` path).
#[derive(Debug, Default, Clone, Copy)]
pub struct ConsoleSink;

impl OutputSink for ConsoleSink {
    fn on_stdout(&mut self, chunk: &[u8]) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(chunk);
        let _ = out.flush();
    }
    fn on_stderr(&mut self, chunk: &[u8]) {
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(chunk);
        let _ = err.flush();
    }
}

/// Discards all output (when only the persisted evidence matters).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl OutputSink for NullSink {
    fn on_stdout(&mut self, _chunk: &[u8]) {}
    fn on_stderr(&mut self, _chunk: &[u8]) {}
}

/// Collects output in memory (tests, and the TUI pane buffer).
#[derive(Debug, Default, Clone)]
pub struct CollectingSink {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl OutputSink for CollectingSink {
    fn on_stdout(&mut self, chunk: &[u8]) {
        self.stdout.extend_from_slice(chunk);
    }
    fn on_stderr(&mut self, chunk: &[u8]) {
        self.stderr.extend_from_slice(chunk);
    }
}
