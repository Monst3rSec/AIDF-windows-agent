//! Native, read-only registry reader. Windows only; other platforms get a stub so the
//! rest of the collector still builds and its tests run anywhere.
use serde_json::Value;

/// Dump every key a template resolves to, `depth` levels deep.
/// `HKCU\...` is read from every loaded user hive, and `*` matches any one key segment.
/// With `names_only`, values are not read (used where the data itself is secret material).
#[cfg(windows)]
pub fn dump(template: &str, depth: u8, names_only: bool) -> Value {
    imp::dump(template, depth, names_only)
}

#[cfg(not(windows))]
pub fn dump(template: &str, _depth: u8, _names_only: bool) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(template.to_string(), Value::Null);
    Value::Object(m)
}

/// SIDs of the user hives currently loaded under HKEY_USERS.
#[cfg(windows)]
pub fn user_sids() -> Vec<String> {
    imp::user_sids()
}

#[cfg(not(windows))]
pub fn user_sids() -> Vec<String> {
    vec![]
}

/// True when the process token is elevated (it can open the NetworkService hive).
#[cfg(windows)]
pub fn is_admin() -> bool {
    use winreg::{enums::*, RegKey};
    RegKey::predef(HKEY_USERS).open_subkey_with_flags("S-1-5-20", KEY_READ).is_ok()
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
            _ => c,
        })
        .collect()
}

#[cfg(windows)]
mod imp {
    use super::rot13;
    use crate::util::{filetime_iso, wild};
    use serde_json::{json, Map, Value};
    use winreg::{enums::*, RegKey, RegValue};

    /// Per-key cap on values and subkeys, so one pathological key cannot bloat the evidence.
    const MAX: usize = 4000;
    /// Always read the native 64-bit view, also from a 32-bit build.
    const FLAGS: u32 = KEY_READ | KEY_WOW64_64KEY;

    pub fn user_sids() -> Vec<String> {
        RegKey::predef(HKEY_USERS)
            .enum_keys()
            .flatten()
            .filter(|s| !s.ends_with("_Classes"))
            .filter(|s| s.starts_with("S-1-5-21-") || s.starts_with("S-1-12-1-") || s == "S-1-5-18")
            .collect()
    }

    fn resolve(template: &str) -> Vec<(String, RegKey)> {
        let (hive, rest) = template.split_once('\\').unwrap_or((template, ""));
        let mut cur: Vec<(String, RegKey)> = match hive.to_ascii_uppercase().as_str() {
            "HKLM" => vec![("HKLM".into(), RegKey::predef(HKEY_LOCAL_MACHINE))],
            "HKU" => vec![("HKU".into(), RegKey::predef(HKEY_USERS))],
            "HKCR" => vec![("HKCR".into(), RegKey::predef(HKEY_CLASSES_ROOT))],
            "HKCU" => user_sids()
                .into_iter()
                .filter_map(|sid| {
                    let k = RegKey::predef(HKEY_USERS).open_subkey_with_flags(&sid, FLAGS).ok()?;
                    Some((format!("HKU\\{sid}"), k))
                })
                .collect(),
            _ => vec![],
        };
        for seg in rest.split('\\').filter(|s| !s.is_empty()) {
            let mut next = Vec::new();
            for (path, key) in &cur {
                if seg.contains('*') {
                    for name in key.enum_keys().flatten().take(MAX) {
                        if wild(seg, &name) {
                            if let Ok(k) = key.open_subkey_with_flags(&name, FLAGS) {
                                next.push((format!("{path}\\{name}"), k));
                            }
                        }
                    }
                } else if let Ok(k) = key.open_subkey_with_flags(seg, FLAGS) {
                    next.push((format!("{path}\\{seg}"), k));
                }
            }
            cur = next;
        }
        cur
    }

    fn wide(b: &[u8]) -> String {
        let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&u)
    }

    fn le64(b: &[u8]) -> u64 {
        u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))
    }

    fn value(path_lower: &str, name: &str, v: &RegValue) -> Value {
        let b = &v.bytes;
        match v.vtype {
            REG_SZ | REG_EXPAND_SZ | REG_LINK => {
                let s = wide(b).trim_end_matches('\0').to_string();
                if name.eq_ignore_ascii_case("DefaultPassword") && !s.is_empty() {
                    return json!("[PRESENT - redacted by collector]");
                }
                json!(s)
            }
            REG_MULTI_SZ => json!(wide(b).split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>()),
            REG_DWORD if b.len() >= 4 => json!(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            REG_DWORD_BIG_ENDIAN if b.len() >= 4 => json!(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
            REG_QWORD if b.len() >= 8 => json!(le64(b)),
            _ => {
                // BAM: value data starts with the last-execution FILETIME.
                if path_lower.contains("\\bam\\") && b.len() >= 8 {
                    if let Some(t) = filetime_iso(le64(b)) {
                        return json!({ "LastExecuted": t });
                    }
                }
                // UserAssist (Win7+): run count at offset 4, last-run FILETIME at offset 60.
                if path_lower.contains("\\userassist\\") && b.len() >= 68 {
                    return json!({
                        "RunCount": u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
                        "LastRun": filetime_iso(le64(&b[60..])),
                    });
                }
                let hex: String = b.iter().take(256).map(|x| format!("{x:02x}")).collect();
                json!(format!("hex({}):{hex}", b.len()))
            }
        }
    }

    fn node(path: &str, key: &RegKey, depth: u8, names_only: bool) -> Value {
        let mut m = Map::new();
        let lower = path.to_lowercase();
        if let Ok(info) = key.query_info() {
            let t = info.get_last_write_time_system();
            m.insert(
                "@LastWrite".into(),
                json!(format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
                )),
            );
        }
        if !names_only {
            for (name, val) in key.enum_values().flatten().take(MAX) {
                let shown = if name.is_empty() {
                    "(Default)".to_string()
                } else if lower.contains("\\userassist\\") {
                    rot13(&name)
                } else {
                    name.clone()
                };
                m.insert(shown, value(&lower, &name, &val));
            }
        }
        for sub in key.enum_keys().flatten().take(MAX) {
            let child = if depth == 0 {
                Value::Null
            } else {
                match key.open_subkey_with_flags(&sub, FLAGS) {
                    Ok(k) => node(&format!("{path}\\{sub}"), &k, depth - 1, names_only),
                    Err(e) => json!(format!("<{e}>")),
                }
            };
            m.insert(format!("{sub}\\"), child);
        }
        Value::Object(m)
    }

    pub fn dump(template: &str, depth: u8, names_only: bool) -> Value {
        let mut out = Map::new();
        for (path, key) in resolve(template) {
            let n = node(&path, &key, depth, names_only);
            out.insert(path, n);
        }
        if out.is_empty() {
            // Absence is evidence too: record that the key was looked for and not found.
            out.insert(template.to_string(), Value::Null);
        }
        Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rot13_roundtrip() {
        assert_eq!(super::rot13("P:\\Jvaqbjf\\abgrcnq.rkr"), "C:\\Windows\\notepad.exe");
    }
}
