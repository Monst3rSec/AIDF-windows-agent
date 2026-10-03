//! Probes: the handful of ways the collector gathers evidence. Every collector in the
//! catalog is just a list of these, which is what keeps the whole tool small.
use crate::ctx::Ctx;
use crate::{reg, util};
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_FILES: usize = 5000;
const MAX_HASH_BYTES: u64 = 256 << 20;
const MAX_TEXT_BYTES: u64 = 2 << 20;
const MAX_TEXT_FILES: usize = 200;
const MAX_TEXT_LINES: usize = 5000;
const MAX_OUTPUT: u64 = 256 << 20;

type Strs = &'static [&'static str];

pub enum Probe {
    /// Registry dump: (name, key templates, depth).
    Reg(&'static str, Strs, u8),
    /// Registry key names and last-write times only - never the values.
    RegNames(&'static str, Strs),
    /// Built-in Windows command: (name, exe, args). `{raw}` in an argument marks raw output.
    Cmd(&'static str, &'static str, Strs),
    /// PowerShell/CIM query returning JSON: (name, script body).
    Ps(&'static str, &'static str),
    /// File metadata listing: (name, roots, globs, depth, hash).
    Files(&'static str, Strs, Strs, u8, bool),
    /// Contents of small text files: (name, roots, globs, depth).
    Text(&'static str, Strs, Strs, u8),
    /// Raw copy into the evidence set: (name, roots, globs, depth).
    Copy(&'static str, Strs, Strs, u8),
    /// Custom native collection.
    Native(&'static str, fn(&Ctx, &str) -> Result<Value, String>),
}

impl Probe {
    pub fn name(&self) -> &'static str {
        match self {
            Probe::Reg(n, ..) | Probe::RegNames(n, ..) | Probe::Cmd(n, ..) | Probe::Ps(n, ..) => n,
            Probe::Files(n, ..) | Probe::Text(n, ..) | Probe::Copy(n, ..) | Probe::Native(n, ..) => n,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Probe::Reg(..) => "registry",
            Probe::RegNames(..) => "registry-names",
            Probe::Cmd(..) => "command",
            Probe::Ps(..) => "powershell",
            Probe::Files(..) => "file-list",
            Probe::Text(..) => "file-text",
            Probe::Copy(..) => "raw-copy",
            Probe::Native(..) => "native",
        }
    }

    /// Raw probes write bulk artifacts under `raw/` and are skipped by `--no-raw`.
    pub fn is_raw(&self) -> bool {
        match self {
            Probe::Copy(..) => true,
            Probe::Cmd(_, _, args) => args.iter().any(|a| a.contains("{raw}")),
            _ => false,
        }
    }
}

/// Resolve a bare executable name to its System32 path, so a planted binary earlier on
/// PATH (or in the working directory) of a compromised host is never run instead.
pub fn sys(exe: &str) -> String {
    if exe.contains(['\\', '/']) {
        return exe.to_string();
    }
    if let Ok(root) = std::env::var("SystemRoot") {
        for sub in ["Sysnative", "System32", "System32\\WindowsPowerShell\\v1.0", "System32\\wbem"] {
            let p = Path::new(&root).join(sub).join(exe);
            if p.is_file() {
                return p.to_string_lossy().into_owned();
            }
        }
    }
    exe.to_string()
}

/// Run a command with a hard timeout. Returns (exit code, decoded stdout).
pub fn exec(exe: &str, args: &[String], timeout: Duration) -> Result<(i32, String), String> {
    let path = sys(exe);
    let mut child = Command::new(&path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{exe}: {e}"))?;
    let out = child.stdout.take().ok_or("no stdout")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out.take(MAX_OUTPUT).read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{exe}: timed out after {}s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(40)),
            Err(e) => return Err(format!("{exe}: {e}")),
        }
    };
    let bytes = reader.join().unwrap_or_default();
    Ok((status.code().unwrap_or(-1), util::text(&bytes)))
}

const PS_PRELUDE: &str = "$ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';\
[Console]::OutputEncoding=[Text.Encoding]::UTF8;$since=(Get-Date).AddDays(-{days});\
function T($d){if($d){([datetime]$d).ToUniversalTime().ToString('o')}};\
function Ev($log,$ids,$max=2000,$len=600){Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids;StartTime=$since} -MaxEvents $max|\
ForEach-Object{$m=([string]$_.Message -replace '\\s+',' ');[pscustomobject]@{Time=T $_.TimeCreated;Id=$_.Id;Log=$log;\
Provider=$_.ProviderName;UserSid=[string]$_.UserId;Record=$_.RecordId;Message=$m.Substring(0,[Math]::Min($len,$m.Length))}}};";

/// The full one-line script for a body: prelude, body, JSON serialisation.
pub fn ps_script(body: &str, days: u32) -> String {
    let body = body.split_whitespace().collect::<Vec<_>>().join(" ");
    format!(
        "{}ConvertTo-Json -InputObject @(& {{ {} }}) -Depth 6 -Compress",
        PS_PRELUDE.replace("{days}", &days.to_string()),
        body
    )
}

fn ps(ctx: &Ctx, body: &str) -> Result<Value, String> {
    let args: Vec<String> = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
        .iter()
        .map(|s| s.to_string())
        .chain([ps_script(body, ctx.days)])
        .collect();
    let (code, out) = exec("powershell.exe", &args, ctx.timeout)?;
    let out = out.trim().trim_start_matches('\u{feff}');
    if out.is_empty() {
        return if code == 0 {
            Ok(json!([]))
        } else {
            Err(format!("powershell exited {code} with no output"))
        };
    }
    serde_json::from_str(out).map_err(|e| {
        let head: String = out.chars().take(160).collect();
        format!("unparseable powershell output ({e}): {head}")
    })
}

fn matches(globs: Strs, path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    globs.is_empty() || globs.iter().any(|g| util::wild(g, &name))
}

/// Visit every file under the expanded roots that matches one of the globs.
fn each_file(roots: Strs, globs: Strs, depth: u8, f: &mut dyn FnMut(&Path, &fs::Metadata) -> bool) {
    for root in roots.iter().flat_map(|r| util::expand(r)) {
        if !util::walk(&root, depth, &mut |p, m| !matches(globs, p) || f(p, m)) {
            return;
        }
    }
}

fn file_meta(p: &Path, m: &fs::Metadata) -> Map<String, Value> {
    let mut e = Map::new();
    e.insert("Path".into(), json!(p.to_string_lossy()));
    e.insert("Size".into(), json!(m.len()));
    e.insert("Created".into(), json!(util::time_iso(m.created())));
    e.insert("Modified".into(), json!(util::time_iso(m.modified())));
    e
}

fn files(roots: Strs, globs: Strs, depth: u8, hash: bool) -> Value {
    let mut out = Vec::new();
    each_file(roots, globs, depth, &mut |p, m| {
        let mut e = file_meta(p, m);
        if hash && m.len() <= MAX_HASH_BYTES {
            e.insert("SHA256".into(), json!(util::sha256_file(p).ok()));
        }
        out.push(Value::Object(e));
        out.len() < MAX_FILES
    });
    json!(out)
}

fn texts(roots: Strs, globs: Strs, depth: u8) -> Value {
    let mut out = Vec::new();
    each_file(roots, globs, depth, &mut |p, m| {
        let mut e = file_meta(p, m);
        if m.len() > MAX_TEXT_BYTES {
            e.insert("Skipped".into(), json!("larger than 2 MB - not read"));
        } else {
            match fs::read(p) {
                Ok(b) => {
                    let t = util::text(&b);
                    let lines: Vec<&str> = t.lines().take(MAX_TEXT_LINES).collect();
                    e.insert("Truncated".into(), json!(t.lines().count() > lines.len()));
                    e.insert("Lines".into(), json!(lines));
                }
                Err(err) => {
                    e.insert("Error".into(), json!(err.to_string()));
                }
            }
        }
        out.push(Value::Object(e));
        out.len() < MAX_TEXT_FILES
    });
    json!(out)
}

/// Where a source file lands under the raw directory: its full path, minus the drive colon.
pub fn raw_dest(dir: &Path, src: &Path) -> std::path::PathBuf {
    let rel: String = src.to_string_lossy().replace(':', "").replace('\\', "/");
    dir.join(rel.trim_start_matches('/'))
}

fn copy(ctx: &Ctx, collector: &str, name: &str, roots: Strs, globs: Strs, depth: u8) -> Value {
    let dir = ctx.raw_dir(collector).join(name);
    let limit = ctx.max_copy_mb << 20;
    let mut out = Vec::new();
    each_file(roots, globs, depth, &mut |p, m| {
        let mut e = file_meta(p, m);
        if m.len() > limit {
            e.insert("Status".into(), json!(format!("skipped - larger than {} MB", ctx.max_copy_mb)));
        } else {
            let dest = raw_dest(&dir, p);
            let res = dest.parent().map_or(Ok(()), fs::create_dir_all).and_then(|_| fs::copy(p, &dest));
            match res {
                Ok(_) => {
                    e.insert("Status".into(), json!("copied"));
                    e.insert("Evidence".into(), json!(ctx.rel(&dest)));
                }
                Err(err) => {
                    e.insert("Status".into(), json!(format!("failed - {err}")));
                }
            }
        }
        out.push(Value::Object(e));
        out.len() < MAX_FILES
    });
    json!(out)
}

fn cmd(ctx: &Ctx, collector: &str, exe: &str, args: Strs) -> Result<Value, String> {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let args: Vec<String> = args
        .iter()
        .map(|a| {
            let mut a = a.replace("{drive}", &drive);
            if a.contains("{raw}") {
                a = a.replace("{raw}", &ctx.raw_dir(collector).to_string_lossy());
            }
            a
        })
        .collect();
    // Probes overlap, but Windows allows only one shadow-copy creation at a time.
    static VSS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one_snapshot_at_a_time = args
        .iter()
        .any(|a| a == "/vss")
        .then(|| VSS.lock().unwrap_or_else(|e| e.into_inner()));
    let (code, out) = exec(exe, &args, ctx.timeout)?;
    let lines: Vec<&str> = out.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect();
    Ok(json!({ "Command": format!("{exe} {}", args.join(" ")), "ExitCode": code, "Output": lines }))
}

pub fn run(p: &Probe, ctx: &Ctx, collector: &str) -> Result<Value, String> {
    match *p {
        Probe::Reg(..) | Probe::RegNames(..) if !cfg!(windows) => Err("registry probes run on Windows only".into()),
        Probe::Reg(_, keys, depth) => Ok(merge(keys.iter().map(|k| reg::dump(k, depth, false)))),
        Probe::RegNames(_, keys) => Ok(merge(keys.iter().map(|k| reg::dump(k, 1, true)))),
        Probe::Cmd(_, exe, args) => cmd(ctx, collector, exe, args),
        Probe::Ps(_, body) => ps(ctx, body),
        Probe::Files(_, roots, globs, depth, hash) => Ok(files(roots, globs, depth, hash)),
        Probe::Text(_, roots, globs, depth) => Ok(texts(roots, globs, depth)),
        Probe::Copy(name, roots, globs, depth) => Ok(copy(ctx, collector, name, roots, globs, depth)),
        Probe::Native(_, f) => f(ctx, collector),
    }
}

fn merge(parts: impl Iterator<Item = Value>) -> Value {
    let mut all = Map::new();
    for part in parts {
        if let Value::Object(m) = part {
            all.extend(m);
        }
    }
    Value::Object(all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_is_one_line_and_quote_free() {
        let s = ps_script("Get-Thing |\n  Select-Object A,B", 7);
        assert!(!s.contains('\n') && !s.contains('"'));
        assert!(s.contains("AddDays(-7)") && s.contains("Get-Thing | Select-Object A,B"));
    }

    #[test]
    fn raw_destination_keeps_source_path() {
        let d = raw_dest(Path::new("out"), Path::new("C:\\Windows\\Prefetch\\A.pf"));
        assert_eq!(d, Path::new("out").join("C/Windows/Prefetch/A.pf"));
    }

    #[test]
    fn missing_command_is_an_error_not_a_panic() {
        let e = exec("aidf-no-such-binary", &[], Duration::from_secs(2));
        assert!(e.is_err());
    }
}
