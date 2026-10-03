//! Orchestration: run the plan, write hashed evidence, build the manifest, seal the package.
use crate::catalog::{Collector, CATALOG};
use crate::ctx::{self, Ctx, LOG_NAME, VERSION};
use crate::{probe, util};
use serde_json::{json, Map, Value};
use std::fs::{self, File};
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = "Evidence_Manifest.json";
pub const MANIFEST_HASH: &str = "Evidence_Manifest.json.sha256";

/// Write-then-rename, so a crash never leaves a half-written evidence file behind.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    File::create(&tmp)?.write_all(bytes)?;
    fs::rename(&tmp, path)
}

fn write_json(path: &Path, v: &Value) -> io::Result<()> {
    write_atomic(path, &serde_json::to_vec_pretty(v).map_err(io::Error::other)?)
}

/// Which collectors a run selects. `phases` empty = all; `skip` matches name substrings.
pub fn plan<'a>(phases: &[String], skip: &[String]) -> Vec<&'a Collector> {
    let has = |list: &[String], s: &str| list.iter().any(|x| x.eq_ignore_ascii_case(s));
    CATALOG
        .iter()
        .filter(|c| phases.is_empty() || has(phases, c.phase) || has(phases, c.name))
        .filter(|c| !skip.iter().any(|s| c.name.to_lowercase().contains(&s.to_lowercase())))
        .collect()
}

fn custody(ctx: &Ctx) -> Value {
    json!({
        "CaseNumber": ctx.case,
        "Investigator": ctx.investigator,
        "Hostname": ctx.host,
        "CollectedAtUTC": util::iso(util::now()),
        "Tool": "aidf",
        "ToolVersion": VERSION,
        "IsAdmin": ctx.admin,
    })
}

/// Run one collector and write `<Name>.json`. Returns its row for the manifest.
fn run_collector(ctx: &Ctx, c: &Collector) -> Value {
    let started = util::now();
    let (mut data, mut errors, mut skipped) = (Map::new(), Vec::new(), Vec::new());
    for p in c.probes {
        if p.is_raw() && !ctx.raw {
            skipped.push(json!({ "Probe": p.name(), "Reason": "raw copies disabled (--no-raw)" }));
            continue;
        }
        // A panicking probe must not take the rest of the collection down with it.
        let res = catch_unwind(AssertUnwindSafe(|| probe::run(p, ctx, c.name))).unwrap_or_else(|_| Err("probe panicked".into()));
        match res {
            Ok(v) => {
                data.insert(p.name().into(), v);
            }
            Err(e) => {
                ctx.log("WARN", &format!("{}.{}: {e}", c.name, p.name()));
                errors.push(json!({ "Probe": p.name(), "Kind": p.kind(), "Error": e }));
            }
        }
    }
    let status = match (data.len(), errors.len()) {
        (_, 0) => "Success",
        (0, _) => "Failed",
        _ => "Partial",
    };
    let evidence = json!({
        "ChainOfCustody": custody(ctx),
        "Collector": c.name,
        "Phase": c.phase,
        "Mitre": c.mitre,
        "Started": util::iso(started),
        "Finished": util::iso(util::now()),
        "Status": status,
        "Errors": errors,
        "Skipped": skipped,
        "Data": data,
    });
    let file = ctx.out.join(format!("{}.json", c.name));
    let status = match write_json(&file, &evidence) {
        Ok(()) => status.to_string(),
        Err(e) => format!("Failed (write: {e})"),
    };
    json!({
        "Collector": c.name,
        "Phase": c.phase,
        "Status": status,
        "DurationSec": util::now() - started,
        "Probes": c.probes.len(),
        "Errors": errors.len(),
    })
}

/// Record the collector's own footprint so its processes and files can be told apart
/// from attacker activity when the evidence is triaged.
fn footprint(ctx: &Ctx) {
    let exe = std::env::current_exe().ok();
    let v = json!({
        "Note": "Processes and files below belong to the collector itself - exclude them when triaging.",
        "ChainOfCustody": custody(ctx),
        "PID": std::process::id(),
        "Executable": exe.as_ref().map(|p| p.to_string_lossy()),
        "ExecutableSHA256": exe.as_ref().and_then(|p| util::sha256_file(p).ok()),
        "CommandLine": std::env::args().collect::<Vec<_>>(),
        "RunAs": format!("{}\\{}", std::env::var("USERDOMAIN").unwrap_or_default(), std::env::var("USERNAME").unwrap_or_default()),
        "OutputPath": ctx.out.to_string_lossy(),
        "ChildProcesses": "powershell.exe and built-in Windows tools, each resolved from System32",
    });
    let _ = write_json(&ctx.out.join("Collector_Footprint.json"), &v);
}

/// Clock provenance: where this host gets its time and how far off it is.
fn time_source() -> Value {
    let out = probe::exec(
        "w32tm.exe",
        &["/query".into(), "/status".into()],
        std::time::Duration::from_secs(20),
    );
    let text = out.map(|(_, t)| t).unwrap_or_default();
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim_start_matches(':').trim().to_string()))
            .unwrap_or_else(|| "Unknown".into())
    };
    json!({ "Source": field("Source"), "PhaseOffset": field("Phase Offset"), "Stratum": field("Stratum") })
}

fn evidence_files(root: &Path, exclude: &[&str]) -> Vec<(String, PathBuf, u64)> {
    let mut files = Vec::new();
    util::walk(root, 32, &mut |p, m| {
        let rel = ctx::rel(root, p);
        if !exclude.contains(&rel.as_str()) && !rel.ends_with(".tmp") {
            files.push((rel, p.to_path_buf(), m.len()));
        }
        true
    });
    files.sort();
    files
}

/// Hash every file in the run directory into the manifest, then hash the manifest itself.
fn manifest(ctx: &Ctx, results: &[Value], ntp: Value) -> io::Result<(usize, u64)> {
    let mut total = 0;
    let files: Vec<Value> = evidence_files(&ctx.out, &[MANIFEST, MANIFEST_HASH, LOG_NAME])
        .into_iter()
        .map(|(rel, path, size)| {
            total += size;
            let meta = fs::metadata(&path).ok();
            json!({
                "RelativePath": rel,
                "SizeBytes": size,
                "SHA256": util::sha256_file(&path).ok(),
                "Modified": meta.and_then(|m| util::time_iso(m.modified())),
            })
        })
        .collect();
    let count = |s: &str| {
        results
            .iter()
            .filter(|r| r["Status"].as_str().is_some_and(|x| x.starts_with(s)))
            .count()
    };
    let doc = json!({
        "ManifestVersion": "2.0",
        "ChainOfCustody": {
            "CaseNumber": ctx.case,
            "Investigator": ctx.investigator,
            "Hostname": ctx.host,
            "Domain": std::env::var("USERDOMAIN").unwrap_or_default(),
            "CollectionStartUTC": util::iso(ctx.started),
            "CollectionEndUTC": util::iso(util::now()),
            "TimeSource": ntp,
            "Tool": "aidf",
            "ToolVersion": VERSION,
            "IsAdmin": ctx.admin,
            "LiveResponse": ctx.live,
            "RawArtifacts": ctx.raw,
            "LookbackDays": ctx.days,
        },
        "ExecutionSummary": {
            "Collectors": results.len(),
            "Success": count("Success"),
            "Partial": count("Partial"),
            "Failed": count("Failed"),
            "RuntimeSec": util::now() - ctx.started,
        },
        "CollectorResults": results,
        "TotalFiles": files.len(),
        "TotalSizeBytes": total,
        "EvidenceFiles": files,
    });
    let path = ctx.out.join(MANIFEST);
    write_json(&path, &doc)?;
    let hash = util::sha256_file(&path)?;
    write_json(
        &ctx.out.join(MANIFEST_HASH),
        &json!({ "File": MANIFEST, "SHA256": hash, "GeneratedUTC": util::iso(util::now()) }),
    )?;
    ctx.log("INFO", &format!("Manifest SHA256: {hash}"));
    Ok((files.len(), total))
}

/// Seal the run directory into one hashed zip next to it. Files over the size ceiling are
/// referenced, not embedded - they are already hashed individually in the manifest.
fn package(ctx: &Ctx) -> io::Result<PathBuf> {
    use zip::write::SimpleFileOptions;
    let name = format!("Evidence_Package_{}_{}.zip", ctx.host, util::stamp(ctx.started));
    let path = ctx.out.parent().unwrap_or(&ctx.out).join(name);
    let limit = ctx.max_copy_mb << 20;
    let mut zip = zip::ZipWriter::new(File::create(&path)?);
    let mut referenced = Vec::new();
    for (rel, file, size) in evidence_files(&ctx.out, &[]) {
        if size > limit {
            referenced.push(json!({ "RelativePath": rel, "SizeBytes": size }));
            continue;
        }
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(size >= u32::MAX as u64);
        let Ok(mut src) = File::open(&file) else { continue };
        zip.start_file(rel, opts).map_err(io::Error::other)?;
        io::copy(&mut src, &mut zip)?;
    }
    zip.finish().map_err(io::Error::other)?;
    let hash = util::sha256_file(&path)?;
    write_json(
        &PathBuf::from(format!("{}.sha256", path.display())),
        &json!({
            "Package": path.file_name().map(|n| n.to_string_lossy()),
            "SHA256": hash,
            "GeneratedUTC": util::iso(util::now()),
            "CaseNumber": ctx.case,
            "EmbeddedMaxMBPerFile": ctx.max_copy_mb,
            "ReferencedNotEmbedded": referenced,
        }),
    )?;
    ctx.log("INFO", &format!("Sealed package: {} (SHA256 {hash})", path.display()));
    Ok(path)
}

pub fn collect(ctx: &Ctx, plan: &[&Collector], seal: bool) -> io::Result<()> {
    fs::create_dir_all(&ctx.out)?;
    ctx.log("INFO", &format!("aidf {VERSION} - collection started"));
    ctx.log(
        "INFO",
        &format!("Case {} | Investigator {} | Host {}", ctx.case, ctx.investigator, ctx.host),
    );
    ctx.log(
        "INFO",
        &format!("Output {} | Lookback {} days | Admin {}", ctx.out.display(), ctx.days, ctx.admin),
    );
    if !cfg!(windows) {
        ctx.log("WARN", "Not running on Windows: collectors will record errors instead of evidence.");
    } else if !ctx.admin {
        ctx.log(
            "WARN",
            "Not elevated: Security log, hives, SAM/SECURITY and other users' data will be incomplete.",
        );
    }
    let ntp = time_source();
    footprint(ctx);

    let mut results = Vec::new();
    for (i, c) in plan.iter().enumerate() {
        if c.live && !ctx.live {
            ctx.log(
                "INFO",
                &format!("[{}/{}] {} skipped - changes system state, needs --live", i + 1, plan.len(), c.name),
            );
            results.push(json!({ "Collector": c.name, "Phase": c.phase, "Status": "Skipped (needs --live)", "DurationSec": 0, "Probes": c.probes.len(), "Errors": 0 }));
            continue;
        }
        ctx.log("INFO", &format!("[{}/{}] {} ({})", i + 1, plan.len(), c.name, c.phase));
        let r = run_collector(ctx, c);
        let level = if r["Status"] == "Success" { "OK" } else { "WARN" };
        ctx.log(
            level,
            &format!("{}: {} in {}s", c.name, r["Status"].as_str().unwrap_or("?"), r["DurationSec"]),
        );
        results.push(r);
    }

    ctx.log("INFO", "Hashing evidence into the manifest");
    let (files, bytes) = manifest(ctx, &results, ntp)?;
    let pkg = if seal {
        package(ctx).map_err(|e| ctx.log("WARN", &format!("Packaging failed: {e}"))).ok()
    } else {
        None
    };
    let n = |s: &str| {
        results
            .iter()
            .filter(|r| r["Status"].as_str().is_some_and(|x| x.starts_with(s)))
            .count()
    };
    ctx.log(
        "INFO",
        &format!(
            "Complete: {} ok, {} partial, {} failed, {} skipped | {files} files, {:.1} MB | {}s",
            n("Success"),
            n("Partial"),
            n("Failed"),
            n("Skipped"),
            bytes as f64 / 1_048_576.0,
            util::now() - ctx.started
        ),
    );
    println!("\n  Evidence : {}", ctx.out.display());
    println!("  Manifest : {}", ctx.out.join(MANIFEST).display());
    if let Some(p) = pkg {
        println!("  Package  : {}", p.display());
    }
    Ok(())
}

/// Re-hash every file the manifest lists. Returns true only if the evidence set is intact:
/// the manifest matches its own recorded hash and every listed file is present and unchanged.
pub fn verify(target: &Path) -> io::Result<bool> {
    let manifest = if target.is_dir() {
        target.join(MANIFEST)
    } else {
        target.to_path_buf()
    };
    let root = manifest.parent().unwrap_or(Path::new(".")).to_path_buf();
    let doc: Value = serde_json::from_slice(&fs::read(&manifest)?).map_err(io::Error::other)?;

    let sidecar = root.join(MANIFEST_HASH);
    let self_check = match fs::read(&sidecar).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
        None => "NO SIDECAR",
        Some(s) => {
            let recorded = s["SHA256"].as_str().unwrap_or_default();
            if util::sha256_file(&manifest)?.eq_ignore_ascii_case(recorded) {
                "MATCH"
            } else {
                "TAMPERED"
            }
        }
    };

    let (mut ok, mut bad, mut missing) = (0, Vec::new(), Vec::new());
    let mut listed = std::collections::HashSet::new();
    for f in doc["EvidenceFiles"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let rel = f["RelativePath"].as_str().unwrap_or_default();
        listed.insert(rel.to_string());
        match util::sha256_file(&root.join(rel)) {
            Err(_) => missing.push(rel.to_string()),
            Ok(h) if f["SHA256"].as_str().is_some_and(|r| r.eq_ignore_ascii_case(&h)) => ok += 1,
            Ok(_) => bad.push(rel.to_string()),
        }
    }
    // Files present but not in the manifest were added after collection.
    let unlisted: Vec<String> = evidence_files(&root, &[MANIFEST, MANIFEST_HASH, LOG_NAME])
        .into_iter()
        .map(|(rel, ..)| rel)
        .filter(|rel| !listed.contains(rel))
        .collect();

    let intact = self_check == "MATCH" && bad.is_empty() && missing.is_empty() && !listed.is_empty();
    println!("Manifest         : {}", manifest.display());
    println!("Case             : {}", doc["ChainOfCustody"]["CaseNumber"].as_str().unwrap_or("?"));
    println!("Manifest hash    : {self_check}");
    println!("Files matched    : {ok} of {}", listed.len());
    for (label, list) in [("MISMATCH", &bad), ("MISSING", &missing), ("UNLISTED", &unlisted)] {
        for f in list {
            println!("  {label:9}: {f}");
        }
    }
    println!("Verdict          : {}", if intact { "VERIFIED" } else { "FAILED" });
    Ok(intact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_ctx(tag: &str) -> Ctx {
        let out = std::env::temp_dir().join(format!("aidf_{tag}_{}", std::process::id())).join("run");
        let _ = fs::remove_dir_all(out.parent().unwrap());
        Ctx {
            case: "TEST-1".into(),
            investigator: "tester".into(),
            host: "HOST".into(),
            tools: out.join("tools"),
            out,
            days: 1,
            admin: false,
            live: false,
            raw: true,
            timeout: Duration::from_secs(5),
            max_copy_mb: 1,
            started: util::now(),
        }
    }

    #[test]
    fn plan_filters_by_phase_name_and_skip() {
        assert_eq!(plan(&[], &[]).len(), CATALOG.len());
        assert!(plan(&["network".into()], &[]).iter().all(|c| c.phase == "Network"));
        assert_eq!(plan(&["Prefetch".into()], &[]).len(), 1);
        assert!(plan(&[], &["eventlog".into()]).iter().all(|c| !c.name.starts_with("EventLog")));
    }

    #[test]
    fn collection_is_hashed_sealed_and_tamper_evident() {
        let ctx = test_ctx("e2e");
        // Named_Pipes fails off-Windows; the run must still finish and record the failure.
        collect(&ctx, &plan(&["Named_Pipes".into(), "RAM_Dump".into()], &[]), true).unwrap();
        let ev: Value = serde_json::from_slice(&fs::read(ctx.out.join("Named_Pipes.json")).unwrap()).unwrap();
        assert_eq!(ev["ChainOfCustody"]["CaseNumber"], "TEST-1");
        assert!(!ctx.out.join("RAM_Dump.json").exists(), "live collector ran without --live");
        assert!(verify(&ctx.out).unwrap());

        let pkg: Vec<_> = fs::read_dir(ctx.out.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert!(pkg.iter().any(|n| n.to_string_lossy().ends_with(".zip")));
        assert!(pkg.iter().any(|n| n.to_string_lossy().ends_with(".zip.sha256")));

        // Changing one byte of evidence, or the manifest, must fail verification.
        fs::write(ctx.out.join("Named_Pipes.json"), b"{}").unwrap();
        assert!(!verify(&ctx.out).unwrap());
        collect(&ctx, &plan(&["Named_Pipes".into()], &[]), false).unwrap();
        assert!(verify(&ctx.out).unwrap());
        let m = ctx.out.join(MANIFEST);
        fs::write(&m, fs::read_to_string(&m).unwrap().replace("TEST-1", "TEST-2")).unwrap();
        assert!(!verify(&ctx.out).unwrap());
        fs::remove_dir_all(ctx.out.parent().unwrap()).unwrap();
    }

    #[test]
    fn file_probes_list_read_and_copy() {
        use crate::probe::{run, Probe};
        let ctx = test_ctx("files");
        let src = ctx.out.parent().unwrap().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.log"), b"line1\nline2\n").unwrap();
        fs::write(src.join("sub/b.log"), b"deep").unwrap();
        fs::write(src.join("c.bin"), vec![0u8; 2 << 20]).unwrap();
        let root: &'static str = Box::leak(src.to_string_lossy().into_owned().into_boxed_str());
        let roots: &'static [&'static str] = Box::leak(vec![root].into_boxed_slice());

        let listed = run(&Probe::Files("L", roots, &["*.log"], 0, true), &ctx, "T").unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 1, "depth 0 must not descend");
        assert_eq!(listed[0]["SHA256"].as_str().unwrap().len(), 64);
        let deep = run(&Probe::Files("L", roots, &["*.log"], 1, false), &ctx, "T").unwrap();
        assert_eq!(deep.as_array().unwrap().len(), 2);

        let text = run(&Probe::Text("X", roots, &["a.log"], 0), &ctx, "T").unwrap();
        assert_eq!(text[0]["Lines"], json!(["line1", "line2"]));

        let copied = run(&Probe::Copy("C", roots, &[], 1), &ctx, "T").unwrap();
        let status = |name: &str| {
            let hit = copied
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["Path"].as_str().unwrap().ends_with(name))
                .unwrap();
            hit["Status"].as_str().unwrap().to_string()
        };
        assert_eq!(status("a.log"), "copied");
        assert!(
            status("c.bin").starts_with("skipped"),
            "file over the size ceiling must not be copied"
        );
        let ev = copied[0]["Evidence"].as_str().unwrap_or_default();
        assert!(ev.is_empty() || ev.starts_with("raw/T/C/"));
        fs::remove_dir_all(ctx.out.parent().unwrap()).unwrap();
    }
}
