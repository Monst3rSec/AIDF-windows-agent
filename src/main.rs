//! aidf - AIDF Windows Agent: a single-binary Windows DFIR evidence collector.
mod catalog;
mod collect;
mod ctx;
mod native;
mod probe;
mod reg;
mod util;

use ctx::{Ctx, VERSION};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const HELP: &str = "\
aidf - Windows DFIR evidence collector

USAGE
  aidf                       Same as `aidf collect`: double-click to collect. Asks for
                             elevation, stores evidence next to the exe, waits for Enter.
  aidf collect [options]     Collect evidence from this host (run elevated)
  aidf verify <dir>          Re-hash a collected evidence set against its manifest
  aidf list                  Show the collection plan
  aidf version

COLLECT OPTIONS
  --out <dir>            Base output directory        [DFIR_OUTPUT, default: folder of aidf.exe]
  --case <id>            Case number                  [DFIR_CASE, default CASE-<utc stamp>]
  --investigator <name>  Investigator                 [DFIR_INV, default current user]
  --days <n>             Event-log lookback in days   [DFIR_DAYS, default 30]
  --phase <a,b>          Only these phases or collectors (see `aidf list`)
  --skip <a,b>           Skip collectors whose name contains any of these
  --live                 Also run state-changing collectors: RAM dump, packet capture
  --no-raw               Skip bulk raw copies (hives, EVTX, prefetch, ...)
  --no-package           Do not seal the evidence into a zip
  --tools <dir>          Directory holding winpmem*.exe  [default <exe dir>\\Tools]
  --max-mb <n>           Per-file ceiling for raw copies and packaging  [default 1024]
  --timeout <sec>        Per-command timeout          [default 300]
  --jobs <n>             Probes run at once; 1 = strictly sequential  [default: CPU cores, 4 to 8]

Collection is read-only unless --live is given.";

struct Args(Vec<String>);

impl Args {
    fn flag(&mut self, name: &str) -> bool {
        let before = self.0.len();
        self.0.retain(|a| a != name);
        self.0.len() != before
    }

    fn value(&mut self, name: &str) -> Option<String> {
        let i = self.0.iter().position(|a| a == name)?;
        self.0.remove(i);
        (i < self.0.len()).then(|| self.0.remove(i))
    }

    fn list(&mut self, name: &str) -> Vec<String> {
        let v = self.value(name).unwrap_or_default();
        v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn collect(mut a: Args) -> Result<ExitCode, String> {
    let started = util::now();
    let host = ctx::hostname();
    // Evidence lands next to the executable unless told otherwise.
    let exe_dir = exe_dir();
    let base = a
        .value("--out")
        .or_else(|| env("DFIR_OUTPUT"))
        .map(PathBuf::from)
        .unwrap_or_else(|| exe_dir.clone());
    let num = |v: Option<String>, name: &str, default: u64| match v {
        None => Ok(default),
        Some(s) => s.parse::<u64>().map_err(|_| format!("{name} expects a number, got '{s}'")),
    };
    let default_jobs = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(4, 8) as u64;
    let ctx = Ctx {
        case: a
            .value("--case")
            .or_else(|| env("DFIR_CASE"))
            .unwrap_or_else(|| format!("CASE-{}", util::stamp(started))),
        investigator: a
            .value("--investigator")
            .or_else(|| env("DFIR_INV"))
            .or_else(|| env("USERNAME"))
            .or_else(|| env("USER"))
            .unwrap_or_else(|| "unknown".into()),
        out: base.join(format!("{host}_{}", util::stamp(started))),
        tools: a.value("--tools").map(PathBuf::from).unwrap_or_else(|| exe_dir.join("Tools")),
        days: num(a.value("--days").or_else(|| env("DFIR_DAYS")), "--days", 30)? as u32,
        admin: reg::is_admin(),
        live: a.flag("--live"),
        raw: !a.flag("--no-raw"),
        timeout: Duration::from_secs(num(a.value("--timeout"), "--timeout", 300)?),
        max_copy_mb: num(a.value("--max-mb").or_else(|| env("DFIR_PACKAGE_MAXMB")), "--max-mb", 1024)?,
        jobs: num(a.value("--jobs").or_else(|| env("AIDF_JOBS")), "--jobs", default_jobs)?.clamp(1, 32) as usize,
        started,
        host,
    };
    let (phases, skip, seal) = (a.list("--phase"), a.list("--skip"), !a.flag("--no-package"));
    if let Some(unknown) = a.0.first() {
        return Err(format!("unknown option '{unknown}' (see `aidf help`)"));
    }
    let plan = collect::plan(&phases, &skip);
    if plan.is_empty() {
        return Err("nothing to collect: --phase/--skip matched no collector (see `aidf list`)".into());
    }
    collect::collect(&ctx, &plan, seal).map_err(|e| format!("collection failed: {e}"))?;
    Ok(ExitCode::SUCCESS)
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Keep a double-clicked console window open until the user has read the result.
fn pause() {
    use std::io::Write;
    print!("\nPress Enter to close...");
    let _ = std::io::stdout().flush();
    let _ = std::io::stdin().read_line(&mut String::new());
}

/// Started with no arguments (double-click): relaunch elevated through the UAC prompt.
/// Returns true when the elevated copy was started and this process should just exit.
fn relaunch_elevated() -> bool {
    if !cfg!(windows) || reg::is_admin() {
        return false;
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    let script = format!(
        "Start-Process -FilePath '{}' -ArgumentList 'collect','--pause' -Verb RunAs",
        exe.to_string_lossy().replace('\'', "''")
    );
    let args = ["-NoProfile", "-Command", script.as_str()].map(String::from);
    println!("Administrator rights are needed for a complete collection - requesting elevation...");
    matches!(probe::exec("powershell.exe", &args, Duration::from_secs(120)), Ok((0, _)))
}

fn list() {
    println!("{:<3} {:<24} {:<15} {:<6} MITRE ATT&CK", "#", "COLLECTOR", "PHASE", "PROBES");
    for (i, c) in catalog::CATALOG.iter().enumerate() {
        let name = if c.live {
            format!("{} (--live)", c.name)
        } else {
            c.name.to_string()
        };
        println!("{:<3} {:<24} {:<15} {:<6} {}", i + 1, name, c.phase, c.probes.len(), c.mitre);
    }
    let probes: usize = catalog::CATALOG.iter().map(|c| c.probes.len()).sum();
    println!(
        "\n{} collectors, {probes} probes, run in this order (most volatile first).",
        catalog::CATALOG.len()
    );
}

fn main() -> ExitCode {
    let mut argv: Vec<String> = std::env::args().skip(1).collect();
    // No arguments (double-click or bare `aidf`): collect, next to the exe, and wait.
    let bare = argv.is_empty();
    if bare {
        if relaunch_elevated() {
            return ExitCode::SUCCESS;
        }
        if cfg!(windows) {
            println!("Elevation was declined or unavailable - collecting without Administrator rights.");
        }
        argv = vec!["collect".into(), "--pause".into()];
    }
    let cmd = argv.remove(0);
    let mut rest = Args(argv);
    let pause_at_end = rest.flag("--pause");
    let argv = rest.0;
    let result = match cmd.as_str() {
        "collect" => collect(Args(argv)),
        "verify" => match argv.first() {
            None => Err("verify needs the evidence directory (or its Evidence_Manifest.json)".into()),
            Some(dir) => match collect::verify(&PathBuf::from(dir)) {
                Ok(true) => Ok(ExitCode::SUCCESS),
                Ok(false) => Ok(ExitCode::from(1)),
                Err(e) => Err(format!("cannot verify {dir}: {e}")),
            },
        },
        "list" => {
            list();
            Ok(ExitCode::SUCCESS)
        }
        "version" | "--version" | "-V" => {
            println!("aidf {VERSION}");
            Ok(ExitCode::SUCCESS)
        }
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!("unknown command '{other}' (see `aidf help`)")),
    };
    let code = result.unwrap_or_else(|e| {
        eprintln!("aidf: {e}");
        ExitCode::from(2)
    });
    if pause_at_end {
        pause();
    }
    code
}
