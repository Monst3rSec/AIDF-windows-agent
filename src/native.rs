//! Collections that need more than a declarative probe.
use crate::ctx::Ctx;
use crate::probe::exec;
use crate::{reg, util};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

fn strs(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Every named pipe currently open (C2 frameworks and lateral-movement tools use them).
pub fn named_pipes(_: &Ctx, _: &str) -> Result<Value, String> {
    let dir = fs::read_dir(r"\\.\pipe\").map_err(|e| format!("\\\\.\\pipe\\: {e}"))?;
    let mut names: Vec<String> = dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    Ok(json!(names))
}

/// Export the key event logs as raw .evtx through the event log service (`wevtutil epl`),
/// which yields a consistent copy of a log that is locked on disk.
pub fn evtx_export(ctx: &Ctx, collector: &str) -> Result<Value, String> {
    const LOGS: &[&str] = &[
        "Security",
        "System",
        "Application",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-WMI-Activity/Operational",
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-WinRM/Operational",
        "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        "Microsoft-Windows-SMBServer/Security",
        "Microsoft-Windows-SmbClient/Security",
        "Microsoft-Windows-AppLocker/EXE and DLL",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-NTLM/Operational",
        "Microsoft-Windows-DNS-Client/Operational",
        "Microsoft-Windows-Kernel-PnP/Configuration",
        "Microsoft-Windows-Partition/Diagnostic",
        "Microsoft-Windows-VHDMP/Operational",
        "Microsoft-Windows-Shell-Core/Operational",
        "Microsoft-Windows-AppXDeployment-Server/Operational",
        "Microsoft-Windows-Backup",
        "Directory Service",
        "DFS Replication",
    ];
    let dir = ctx.raw_dir(collector);
    let mut out = Vec::new();
    for log in LOGS {
        let file = dir.join(format!("{}.evtx", log.replace(['/', '\\', ' '], "-")));
        let args = vec![
            "epl".to_string(),
            log.to_string(),
            file.to_string_lossy().into_owned(),
            "/ow:true".into(),
        ];
        let status = match exec("wevtutil.exe", &args, ctx.timeout) {
            Ok((0, _)) if file.is_file() => "exported".to_string(),
            Ok((code, _)) => format!("not exported (wevtutil exit {code} - log absent or access denied)"),
            Err(e) => format!("failed - {e}"),
        };
        let size = fs::metadata(&file).map(|m| m.len()).ok();
        out.push(json!({ "Log": log, "Status": status, "Evidence": ctx.rel(&file), "Size": size }));
    }
    Ok(json!(out))
}

/// Save the system hives and every loaded user hive through the registry backup API
/// (`reg save`), which yields a consistent copy of a hive that is locked on disk.
pub fn hive_export(ctx: &Ctx, collector: &str) -> Result<Value, String> {
    if !ctx.admin {
        return Err("requires Administrator (registry backup privilege)".into());
    }
    let mut hives: Vec<(String, String)> = ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
        .iter()
        .map(|h| (format!("HKLM\\{h}"), h.to_string()))
        .collect();
    for sid in reg::user_sids() {
        hives.push((format!("HKU\\{sid}"), format!("NTUSER_{sid}.DAT")));
        hives.push((format!("HKU\\{sid}_Classes"), format!("UsrClass_{sid}.dat")));
    }
    let dir = ctx.raw_dir(collector);
    let mut out = Vec::new();
    for (key, name) in hives {
        let file = dir.join(&name);
        let args = vec!["save".to_string(), key.clone(), file.to_string_lossy().into_owned(), "/y".into()];
        let status = match exec("reg.exe", &args, ctx.timeout) {
            Ok((0, _)) if file.is_file() => "saved".to_string(),
            Ok((code, _)) => format!("not saved (reg exit {code})"),
            Err(e) => format!("failed - {e}"),
        };
        let size = fs::metadata(&file).map(|m| m.len()).ok();
        out.push(json!({ "Key": key, "Status": status, "Evidence": ctx.rel(&file), "Size": size }));
    }
    Ok(json!(out))
}

/// Physical memory capture with WinPmem. LIVE: loads a signed kernel driver.
/// The tool is never downloaded on the target: the investigator supplies it in the tools
/// directory, and `DFIR_WINPMEM_SHA256` pins the exact binary that may be run.
pub fn ram_dump(ctx: &Ctx, collector: &str) -> Result<Value, String> {
    if !ctx.admin {
        return Err("requires Administrator (kernel driver load)".into());
    }
    let tool: PathBuf = fs::read_dir(&ctx.tools)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            let n = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
            n.starts_with("winpmem") && n.ends_with(".exe")
        })
        .ok_or_else(|| format!("no winpmem*.exe in {} - supply it to capture memory", ctx.tools.display()))?;
    let tool_hash = util::sha256_file(&tool).map_err(|e| e.to_string())?;
    let pin = std::env::var("DFIR_WINPMEM_SHA256").ok().map(|p| p.trim().to_lowercase());
    if let Some(p) = &pin {
        if *p != tool_hash {
            return Err(format!("WinPmem SHA256 {tool_hash} does not match pinned {p} - capture aborted"));
        }
    }
    let dump = ctx.raw_dir(collector).join("memory.raw");
    let started = util::now();
    let hours = env_u64("AIDF_RAM_TIMEOUT_MIN", 120);
    let run = exec(
        &tool.to_string_lossy(),
        &[dump.to_string_lossy().into_owned()],
        Duration::from_secs(hours * 60),
    );
    let size = fs::metadata(&dump).map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return Err(format!(
            "WinPmem produced no dump ({})",
            run.err().unwrap_or_else(|| "see tool output".into())
        ));
    }
    Ok(json!({
        "Tool": tool.to_string_lossy(),
        "ToolSHA256": tool_hash,
        "ToolHashPinned": pin.is_some(),
        "ExitCode": run.map(|(c, _)| c).ok(),
        "Started": util::iso(started),
        "Finished": util::iso(util::now()),
        "Evidence": ctx.rel(&dump),
        "Size": size,
        "Note": "Dump is hashed in Evidence_Manifest.json. Analyse with Volatility 3.",
    }))
}

/// Timed packet capture with the built-in `netsh trace`. LIVE: starts an ETW/NDIS trace.
/// Runs last - it is a forward-in-time window, not a snapshot.
pub fn packet_capture(ctx: &Ctx, collector: &str) -> Result<Value, String> {
    if !ctx.admin {
        return Err("requires Administrator (netsh trace)".into());
    }
    let secs = env_u64("AIDF_PCAP_SECS", 60);
    let max_mb = env_u64("AIDF_PCAP_MAXMB", 512);
    let dir = ctx.raw_dir(collector);
    let etl = dir.join("capture.etl");
    let start = strs(&[
        "trace",
        "start",
        "capture=yes",
        "report=disabled",
        "filemode=single",
        "overwrite=yes",
    ]);
    let args: Vec<String> = start
        .into_iter()
        .chain([format!("tracefile={}", etl.display()), format!("maxsize={max_mb}")])
        .collect();
    let (code, out) = exec("netsh.exe", &args, Duration::from_secs(120))?;
    if code != 0 {
        return Err(format!("netsh trace start failed (exit {code}): {}", out.trim()));
    }
    let started = util::now();
    std::thread::sleep(Duration::from_secs(secs));
    // Stopping merges the trace and can take minutes; it must not be cut short.
    let stop = exec("netsh.exe", &strs(&["trace", "stop"]), Duration::from_secs(1800));
    let pcap = dir.join("capture.pcapng");
    let conv = exec(
        "pktmon.exe",
        &[
            "etl2pcap".into(),
            etl.to_string_lossy().into_owned(),
            "--out".into(),
            pcap.to_string_lossy().into_owned(),
        ],
        Duration::from_secs(600),
    );
    Ok(json!({
        "Method": "netsh trace capture=yes",
        "Started": util::iso(started),
        "DurationSec": secs,
        "StopExitCode": stop.map(|(c, _)| c).ok(),
        "Evidence": ctx.rel(&etl),
        "Size": fs::metadata(&etl).map(|m| m.len()).ok(),
        "Pcapng": pcap.is_file().then(|| ctx.rel(&pcap)),
        "PcapConversion": match conv { Ok((0, _)) => "pktmon etl2pcap ok".to_string(), Ok((c, _)) => format!("pktmon exit {c}"), Err(e) => e },
        "Note": "If no pcapng was produced, convert capture.etl offline with etl2pcapng.",
    }))
}
