# AIDF Windows Agent

`aidf` is a single-binary Windows DFIR evidence collector written in Rust. Drop one
executable on a host, run one command, and walk away with a hashed, sealed evidence set.

It is a Rust re-creation of the collection half of
[windows-dfir-toolkit](https://github.com/subashjaganathan/windows-dfir-toolkit)
(63 PowerShell scripts, about 17,000 lines) as one program of about 2,400 lines:
43 collectors, 221 probes, run in RFC 3227 order of volatility.

`aidf` collects evidence. It does not analyse it: there is no IOC matching, scoring,
timeline or report. See [PROJECT.md](PROJECT.md) for scope and design.

## Quick start

**Double-click `aidf.exe`** (or run it with no arguments). It asks for elevation through
the UAC prompt, runs the full collection, stores the evidence in the folder the exe is in,
and waits for Enter before the window closes. If elevation is declined it still collects,
with less coverage.

From an elevated prompt, with case details:

```
aidf.exe collect --case IR-2026-001 --investigator "A. Analyst"
```

Output goes next to the executable, in `<HOST>_<UTC stamp>\` (change with `--out`):

| Item | What it is |
|------|------------|
| `<Collector>.json` | One evidence file per collector, with chain-of-custody header |
| `raw\<Collector>\...` | Raw artifacts: registry hives, `.evtx`, prefetch, task XML, ... |
| `Evidence_Manifest.json` | SHA-256 of every file, plus per-collector results |
| `Evidence_Manifest.json.sha256` | SHA-256 of the manifest itself |
| `Collection.log` | Run log |
| `..\Evidence_Package_<HOST>_<stamp>.zip` + `.sha256` | The sealed package for hand-off |

Prove later that nothing changed (works on Windows, macOS and Linux):

```
aidf verify E:\HOST_20261003_091500
```

## Commands

```
aidf                       Same as `aidf collect`, elevating and pausing (double-click)
aidf collect [options]     Collect evidence from this host
aidf verify <dir>          Re-hash an evidence set against its manifest (exit 1 if not intact)
aidf list                  Show the collection plan
```

| Option | Meaning | Default |
|--------|---------|---------|
| `--out <dir>` | Base output directory (`DFIR_OUTPUT`) | folder of `aidf.exe` |
| `--case <id>` | Case number (`DFIR_CASE`) | `CASE-<stamp>` |
| `--investigator <name>` | Investigator (`DFIR_INV`) | current user |
| `--days <n>` | Event-log lookback (`DFIR_DAYS`) | 30 |
| `--phase <a,b>` | Only these phases or collectors | all |
| `--skip <a,b>` | Skip collectors whose name contains any of these | none |
| `--live` | Also run state-changing collectors (RAM dump, packet capture) | off |
| `--no-raw` | Skip bulk raw copies | off |
| `--no-package` | Do not build the zip | off |
| `--tools <dir>` | Where `winpmem*.exe` lives | `<exe dir>\Tools` |
| `--max-mb <n>` | Per-file ceiling for raw copies and packaging (`DFIR_PACKAGE_MAXMB`) | 1024 |
| `--timeout <sec>` | Per-command timeout | 300 |
| `--jobs <n>` | Probes run at once (`AIDF_JOBS`); `1` = strictly sequential | CPU cores, 4 to 8 |

Live-capture tuning: `DFIR_WINPMEM_SHA256` (pin the WinPmem binary), `AIDF_PCAP_SECS`
(capture length, default 60), `AIDF_PCAP_MAXMB` (default 512).

## Speed

Collection is overlapped: all 221 probes go into one queue in order of volatility and run
on several threads at once, so a slow event-log query no longer holds up the registry or
file-system work. Each collector's file is written as soon as its last probe returns.
Manifest hashing is parallel too. `RAM_Dump` and `Packet_Capture` never overlap with
anything. Use `--jobs 1` for a strictly sequential run on a fragile host.

## Forensic safety

- Read-only unless `--live` is given. Only `RAM_Dump` (loads the WinPmem driver) and
  `Packet_Capture` (starts a `netsh` trace) change system state.
- Nothing is downloaded on the target and the collector makes no network connections.
- Secrets are not collected: no Wi-Fi keys, no LSA secret values, no browser credential or
  cookie stores, no cloud credential file contents, and `DefaultPassword` is redacted.
- Every helper binary is run from `System32` by full path, never resolved through `PATH`.
- The collector records its own footprint (`Collector_Footprint.json`) so its processes
  can be excluded during triage.

Admissibility is decided by a court, not a tool. The hashes and metadata here support a
chain of custody; they do not replace the documented human handling of the evidence.

## Build

```
./build.sh            # test, then build host + Windows x64, x86, arm64 into dist/
./build.sh windows    # the three Windows flavours
./build.sh check      # type-check all Windows flavours (no linker needed)
./build.sh setup      # one-time: install the cross toolchain on macOS / Linux
```

On macOS and Linux the Windows flavours are cross-compiled with `cargo-xwin`, which links
with the lld inside the Rust toolchain and downloads the MSVC CRT and Windows SDK
libraries on first use (about 1 GB in the user cache; using them means accepting
Microsoft's Visual Studio Build Tools licence). On Windows, run `build.sh` from Git Bash
with the Visual Studio C++ Build Tools installed. Binaries link the CRT statically, so
they run on a host with no runtime installed.

Tip: run the collector from removable or network media so evidence is written there and
not onto the disk under investigation.

## Documents

- [PROJECT.md](PROJECT.md) - scope, architecture, evidence format, mapping to the original
- [ADLC.md](ADLC.md) - the development life cycle this project follows
- [TRACKER.md](TRACKER.md) - work items and their verification status
- [CLAUDE.md](CLAUDE.md) - working notes for AI coding agents

## License

MIT. Original PowerShell toolkit by Subash J (MIT).
