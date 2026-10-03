//! Small dependency-free helpers: UTC time formatting, hashing, wildcard and path expansion.
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Unix seconds -> (year, month, day, hour, minute, second), UTC.
fn civil(secs: u64) -> (i64, i64, i64, u64, u64, u64) {
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719_468;
    let (era, doe) = (z.div_euclid(146_097), z.rem_euclid(146_097));
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// ISO-8601 UTC, e.g. `2026-10-03T09:15:00Z`.
pub fn iso(secs: u64) -> String {
    let (y, m, d, h, mi, s) = civil(secs);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Filename-safe UTC stamp, e.g. `20261003_091500`.
pub fn stamp(secs: u64) -> String {
    let (y, m, d, h, mi, s) = civil(secs);
    format!("{y:04}{m:02}{d:02}_{h:02}{mi:02}{s:02}")
}

/// Windows FILETIME (100ns ticks since 1601) -> ISO-8601 UTC.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn filetime_iso(ft: u64) -> Option<String> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    (EPOCH_DIFF..EPOCH_DIFF * 3)
        .contains(&ft)
        .then(|| iso((ft - EPOCH_DIFF) / 10_000_000))
}

pub fn time_iso(t: io::Result<SystemTime>) -> Option<String> {
    t.ok()?.duration_since(UNIX_EPOCH).ok().map(|d| iso(d.as_secs()))
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Case-insensitive wildcard match supporting `*` and `?`.
pub fn wild(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, usize::MAX, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ni;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Replace `%VAR%` with its environment value. `None` if a variable is unset.
fn env_expand(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut parts = s.split('%');
    out.push_str(parts.next()?);
    while let Some(var) = parts.next() {
        match parts.next() {
            Some(rest) => {
                out.push_str(&std::env::var(var).ok()?);
                out.push_str(rest);
            }
            None => {
                out.push('%');
                out.push_str(var);
            }
        }
    }
    Some(out)
}

/// Expand a path template into the existing paths it names.
/// Supports `%ENV%`, `{users}` (every profile directory) and `*`/`?` in any path segment.
pub fn expand(template: &str) -> Vec<PathBuf> {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let Some(s) = env_expand(&template.replace("{users}", &format!("{drive}\\Users\\*"))) else {
        return vec![];
    };
    let norm = s.replace('\\', "/");
    let mut parts = norm.split('/').filter(|p| !p.is_empty());
    let mut cur: Vec<PathBuf> = if norm.starts_with('/') {
        vec![PathBuf::from("/")]
    } else {
        match parts.next() {
            Some(f) if f.ends_with(':') => vec![PathBuf::from(format!("{f}\\"))],
            Some(f) => vec![PathBuf::from(f)],
            None => return vec![],
        }
    };
    for part in parts {
        let mut next = Vec::new();
        for base in &cur {
            if part.contains(['*', '?']) {
                for e in fs::read_dir(base).into_iter().flatten().flatten() {
                    if wild(part, &e.file_name().to_string_lossy()) {
                        next.push(e.path());
                    }
                }
            } else {
                next.push(base.join(part));
            }
        }
        cur = next;
    }
    cur.retain(|p| p.symlink_metadata().is_ok());
    cur.sort();
    cur
}

/// Depth-limited walk over regular files. Never follows symlinks or junctions.
/// The callback returns `false` to stop the walk.
pub fn walk(root: &Path, depth: u8, f: &mut dyn FnMut(&Path, &Metadata) -> bool) -> bool {
    let Ok(meta) = root.symlink_metadata() else { return true };
    if meta.file_type().is_symlink() {
        return true;
    }
    if meta.is_file() {
        return f(root, &meta);
    }
    for e in fs::read_dir(root).into_iter().flatten().flatten() {
        let p = e.path();
        let Ok(m) = p.symlink_metadata() else { continue };
        if m.file_type().is_symlink() {
            continue;
        }
        if m.is_dir() {
            if depth > 0 && !walk(&p, depth - 1, f) {
                return false;
            }
        } else if !f(&p, &m) {
            return false;
        }
    }
    true
}

/// Decode command output or a text file: honours UTF-16/UTF-8 BOMs and BOM-less UTF-16LE.
pub fn text(b: &[u8]) -> String {
    let utf16 = |b: &[u8], be: bool| {
        let u: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| {
                if be {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&u)
    };
    match b {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, false),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, true),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ if b.len() >= 4 && b[1] == 0 && b[3] == 0 && b[0] != 0 => utf16(b, false),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formats() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso(1_790_932_500), "2026-10-02T09:15:00Z");
        assert_eq!(stamp(1_790_932_500), "20261002_091500");
        assert_eq!(filetime_iso(116_444_736_000_000_000).as_deref(), Some("1970-01-01T00:00:00Z"));
        assert_eq!(filetime_iso(0), None);
    }

    #[test]
    fn wildcard() {
        assert!(wild("*.pf", "CMD.EXE-1234.PF"));
        assert!(wild("PowerShell_transcript*.txt", "powershell_transcript.HOST.abc.txt"));
        assert!(wild("$I*", "$IABC123.exe"));
        assert!(wild("ERRORLOG*", "ERRORLOG"));
        assert!(!wild("*.lnk", "file.lnk.bak"));
        assert!(wild("?.txt", "a.txt") && !wild("?.txt", "ab.txt"));
    }

    #[test]
    fn decodes_utf16() {
        let le: Vec<u8> = "wsl".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(text(&le), "wsl");
        assert_eq!(text(&[0xFF, 0xFE, b'a', 0]), "a");
        assert_eq!(text(b"plain"), "plain");
    }

    #[test]
    fn expands_wildcard_segments() {
        let dir = std::env::temp_dir().join(format!("aidf_expand_{}", std::process::id()));
        fs::create_dir_all(dir.join("u1/x")).unwrap();
        fs::create_dir_all(dir.join("u2/x")).unwrap();
        fs::write(dir.join("u1/x/a.txt"), b"1").unwrap();
        let hits = expand(&format!("{}/*/x", dir.display()));
        assert_eq!(hits.len(), 2);
        let mut seen = 0;
        walk(&dir, 3, &mut |_, _| {
            seen += 1;
            true
        });
        assert_eq!(seen, 1);
        assert!(expand("%AIDF_SURELY_UNSET_VAR%\\x").is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
