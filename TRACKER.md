# Tracker

Work items for the AIDF Windows Agent. Process and verification levels (V0-V4) are defined
in [ADLC.md](ADLC.md). Dates are UTC.

## Current state (2026-10-03)

Version 0.1.0. The collector is written and builds. It has **not yet run on a real Windows
host**: Windows-only code is at V1 (compiles and links for x64, x86, arm64; binaries are
in `dist/`), portable logic is at V2 (15 unit tests pass on macOS). The next step is T-201.

## Phase 1 - Discover

| ID | Item | Status | Level |
|----|------|--------|-------|
| T-001 | Read the original toolkit: orchestrator, shared module, launcher, verifier, tests | Done | - |
| T-002 | Read all 59 collection scripts for their data sources (registry keys, commands, event IDs, paths) | Done | - |
| T-003 | Skim reporting scripts (report, timeline, IOC) | Done, then descoped | - |

## Phase 2 - Plan and scope

| ID | Item | Status | Level |
|----|------|--------|-------|
| T-010 | Plan: one binary, declarative catalog of probes, manifest, package, verify | Done | - |
| T-011 | Owner decision: remove IOC matching | Done | - |
| T-012 | Owner decision: collector only - no rules, scoring, report or timeline | Done | - |
| T-013 | Owner request: `build.sh` covering Windows and all flavours (read as x64, x86, arm64) | Done | - |

## Phase 3 and 4 - Design and build

| ID | Item | Status | Level |
|----|------|--------|-------|
| T-101 | `util.rs`: UTC time, SHA-256, wildcards, path expansion, UTF-16 decoding | Done | V2 |
| T-102 | `probe.rs`: Files, Text, Copy probes | Done | V2 |
| T-103 | `probe.rs`: command runner with timeout and System32 path pinning | Done | V2 (runner), V1 (System32 pinning) |
| T-104 | `probe.rs`: PowerShell probe (prelude, JSON round trip) | Done | V1 |
| T-105 | `reg.rs`: native registry dump, all user hives, wildcards, BAM/UserAssist decoding, password redaction | Done | V1 |
| T-106 | `native.rs`: named pipes, EVTX export, hive export | Done | V1 |
| T-107 | `native.rs`: RAM dump (WinPmem, hash pin) and packet capture (`netsh trace`), behind `--live` | Done | V1 |
| T-108 | `catalog.rs`: 43 collectors, 221 probes, volatility order | Done | V2 (structure), V1 (content) |
| T-109 | `collect.rs`: run loop, panic isolation, atomic writes, footprint, time source | Done | V2 |
| T-110 | `collect.rs`: manifest, self-hash, sealed zip package | Done | V2 |
| T-111 | `collect.rs`: `verify` with MISMATCH / MISSING / UNLISTED and tamper detection | Done | V2 |
| T-112 | `main.rs`: CLI, `DFIR_*` environment compatibility | Done | V2 |
| T-113 | `build.sh`: host + Windows x64/x86/arm64, test, check, setup, checksums | Done | Full run on macOS produced all three `.exe` (cargo-xwin) |
| T-116 | Bare `aidf` / double-click: elevate via UAC, collect, store next to the exe, pause | Done | V2 (default run and output location on macOS), V1 (UAC relaunch) |
| T-117 | Default output directory is the folder of the executable | Done | V2 |
| T-114 | CI: Windows build of all flavours, on-runner collect + verify smoke test | Written | V0 - never executed |
| T-115 | Docs: README, PROJECT, ADLC, TRACKER, CLAUDE | Done | - |

## Phase 5 - Verify (open)

| ID | Item | Status | Acceptance |
|----|------|--------|------------|
| T-201 | First run on real Windows (push to GitHub to trigger CI, or run by hand) | **Next** | CI smoke test green; core collectors not `Failed` |
| T-202 | Review every `Ps` probe's output on Windows 10/11 and Server | Open | Each probe returns data or a recorded, understood error |
| T-203 | Confirm event property indexes for 4624 / 4625 / 4769 on a real log | Open | Fields land in the right columns |
| T-204 | Confirm `HKCU` expansion and `*` registry wildcards on a multi-user host | Open | Each loaded hive appears under `HKU\<SID>` |
| T-205 | Run as a non-admin: degrade cleanly | Open | Run completes; failures are recorded, none fatal |
| T-209 | Double-click on Windows: UAC prompt, elevated window collects and pauses; declined UAC still collects | Open | Both paths behave as described |
| T-206 | Measure runtime and output size on a typical workstation and a server | Open | Recorded here |
| T-208 | `--live` on a test VM: RAM dump and packet capture | Open | Dump and capture produced and hashed |

## Backlog

| ID | Item | Note |
|----|------|------|
| T-301 | Raw `$MFT`, `$UsnJrnl`, `$LogFile` by reading the volume device | Not ported; original relied on robocopy/esentutl fallbacks |
| T-302 | Pagefile / hiberfil raw capture through VSS | Not ported; metadata only |
| T-303 | Alternate data streams (Zone.Identifier / Mark-of-the-Web) | Not ported |
| T-304 | Replace `Ps` probes with native code: processes, services, TCP table, event log (`EvtQuery`) | Removes the PowerShell dependency step by step |
| T-305 | Embed a version resource and application manifest | Elevation is handled at runtime (T-116) |
| T-306 | Code-sign release binaries | - |
| T-307 | Scheduled-task and prefetch parsing natively | Currently raw copy plus cmdlet view |
| T-308 | `--remote` style fleet execution | Not planned |

## Descoped (owner decision 2026-10-03)

IOC matching, VirusTotal enrichment, detection rules, risk scoring, HTML report, timeline,
autoruns correlation summary, offline analyzer.

## Decision log

| Date | Decision | By |
|------|----------|----|
| 2026-10-03 | Recreate the toolkit in Rust as one binary with a declarative catalog | Owner / agent |
| 2026-10-03 | Add `build.sh`; cover Windows x64, x86, arm64 | Owner |
| 2026-10-03 | Remove IOC; focus on evidence collection; collector program only | Owner |
| 2026-10-03 | Bare run / double-click collects by default; evidence is stored next to the exe | Owner |
| 2026-10-03 | Cross-compile with cargo-xwin (zig and mingw did not fit: low disk, no arm64) | Agent |
| 2026-10-03 | Keep `aidf verify` (integrity of the collected set, not analysis) | Agent - owner to confirm |
| 2026-10-03 | No per-file hash sidecars: one manifest, itself hashed | Agent |
| 2026-10-03 | Never download tools on the target; never collect secrets | Agent |
| 2026-10-03 | Keep PowerShell as a data source for CIM/event-log probes in 0.1 | Agent |
