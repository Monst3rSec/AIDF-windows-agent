//! Run context: who is collecting what, where it goes, and the run log.
use crate::util;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LOG_NAME: &str = "Collection.log";

pub struct Ctx {
    pub case: String,
    pub investigator: String,
    pub host: String,
    /// Run directory: everything this run collects lives under it.
    pub out: PathBuf,
    /// Directory holding optional third-party tools (WinPmem).
    pub tools: PathBuf,
    /// Event-log lookback window.
    pub days: u32,
    pub admin: bool,
    /// Permit state-changing live-response collectors (memory driver, packet trace).
    pub live: bool,
    /// Permit bulk raw-artifact copies (hives, EVTX, prefetch, ...).
    pub raw: bool,
    /// Per-command timeout.
    pub timeout: Duration,
    /// Per-file ceiling for raw copies and for embedding in the sealed package.
    pub max_copy_mb: u64,
    pub started: u64,
}

impl Ctx {
    pub fn log(&self, level: &str, msg: &str) {
        let line = format!("{} [{level}] {msg}", util::iso(util::now()));
        println!("{line}");
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(self.out.join(LOG_NAME)) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// `raw/<collector>` under the run directory, created on demand.
    pub fn raw_dir(&self, collector: &str) -> PathBuf {
        let d = self.out.join("raw").join(collector);
        let _ = fs::create_dir_all(&d);
        d
    }

    /// Path relative to the run directory, with forward slashes (stable across platforms).
    pub fn rel(&self, p: &Path) -> String {
        rel(&self.out, p)
    }
}

pub fn rel(base: &Path, p: &Path) -> String {
    p.strip_prefix(base).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            let out = std::process::Command::new("hostname").output().ok()?;
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "UNKNOWN".into())
}
