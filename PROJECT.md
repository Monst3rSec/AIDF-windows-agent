# Project: AIDF Windows Agent

## Purpose

Collect forensic evidence from a live Windows host with one small executable, in a way
that can be verified afterwards.

## Origin

A Rust re-creation of [windows-dfir-toolkit](https://github.com/subashjaganathan/windows-dfir-toolkit)
v1.0: 63 PowerShell scripts, an orchestrator, a C# self-extracting launcher and a
reporting pipeline. The brief was "smaller, sharper", then narrowed by the owner on
2026-10-03 to **collector only**.

## Scope

In scope:

- Evidence collection in RFC 3227 order of volatility
- Per-file SHA-256, an evidence manifest, a sealed zip package
- Verification of a collected set against its manifest
- Windows 10 1607+, Windows 11, Server 2016+ on x64, x86 and arm64

Out of scope (owner decision, 2026-10-03):

- IOC matching and VirusTotal enrichment
- Detection rules, risk scoring, "suspicious" flags
- HTML report and timeline
- Any analysis of what was collected

Analysis belongs on an analyst workstation with a separate tool. Evidence files are plain
JSON plus raw artifacts, so any tool can consume them.

## Architecture

```
main.rs      CLI: collect | verify | list
collect.rs   run the plan, write evidence, manifest, package, verify
catalog.rs   THE PLAN: 43 collectors, each a list of probes, in collection order
probe.rs     the 8 probe kinds and how each runs
reg.rs       native read-only registry access (winreg); stub off Windows
native.rs    collections that need code: pipes, EVTX export, hive export, RAM, pcap
ctx.rs       run context and log
util.rs      UTC time, SHA-256, wildcards, path expansion, text decoding
```

The central idea: the original has 63 scripts that each repeat the same boilerplate around
a few lines that matter. Here those few lines are data. A collector is a row in
`catalog.rs`; adding evidence means adding a row, not a file.

### Probe kinds

| Probe | Does | Native? |
|-------|------|---------|
| `Reg` | Dump registry keys to a depth, with key last-write times | yes |
| `RegNames` | Key names and last-write times only, never values | yes |
| `Files` | File metadata, optional SHA-256 | yes |
| `Text` | Contents of small text files (UTF-8/UTF-16) | yes |
| `Copy` | Raw copy into `raw/` | yes |
| `Native` | Custom Rust (pipes, EVTX/hive export, RAM, pcap) | yes, drives built-in tools |
| `Cmd` | Run a built-in Windows command, keep its output | built-in exe |
| `Ps` | PowerShell/CIM query returning JSON | `powershell.exe` |

### Execution model

`collect.rs` flattens the plan into one queue of (collector, probe) tasks in catalog order
and runs it on `--jobs` threads. Order of *starting* therefore still follows volatility;
order of *finishing* does not, so each collector's `Started`/`Finished` times overlap with
its neighbours. Results are reassembled in catalog order, so evidence files are laid out
the same whatever the timing. Live collectors run alone: `RAM_Dump` before the queue,
`Packet_Capture` after it. Shadow-copy commands (`esentutl /vss`) are serialised because
Windows allows one snapshot creation at a time.

Path templates accept `%ENV%`, `{users}` (every profile) and `*` in any segment. Registry
templates accept `*` segments, and `HKCU\...` is read from every loaded user hive, not
just the hive of whoever ran the tool.

### Why PowerShell is still used

About a third of the probes (`Ps`) query CIM/WMI, the event log, Defender, scheduled tasks
and similar through `powershell.exe`. Windows exposes these through COM and WMI interfaces
that would need thousands of lines of unsafe FFI to reach directly. The Rust program owns
orchestration, integrity, registry, file system and raw artifacts; PowerShell is a data
source it shells out to, with a timeout, from `System32`, with no scripts on disk.
Replacing `Ps` probes with native code is tracked in [TRACKER.md](TRACKER.md).

## Evidence format

`<Collector>.json`:

```json
{
  "ChainOfCustody": { "CaseNumber": "", "Investigator": "", "Hostname": "",
                      "CollectedAtUTC": "", "Tool": "aidf", "ToolVersion": "", "IsAdmin": true },
  "Collector": "Processes", "Phase": "Execution", "Mitre": "T1055 T1036 T1059",
  "Started": "", "Finished": "", "Status": "Success | Partial | Failed",
  "Errors":  [ { "Probe": "", "Kind": "", "Error": "" } ],
  "Skipped": [ { "Probe": "", "Reason": "" } ],
  "Data":    { "<ProbeName>": "<probe output>" }
}
```

All timestamps are UTC ISO-8601. A registry key that does not exist is recorded as `null`:
absence is evidence. A probe that fails is recorded in `Errors` and never stops the run.

`Evidence_Manifest.json` lists every file under the run directory with its SHA-256, plus
chain of custody, time source (`w32tm`), and one result row per collector. The manifest's
own hash is in `Evidence_Manifest.json.sha256`. `aidf verify` reports `MISMATCH`,
`MISSING` and `UNLISTED` (added after collection) files.

## Differences from the original, and why

| Original | aidf | Reason |
|----------|------|--------|
| 63 scripts + launcher that unpacks them to `%TEMP%` | one exe, nothing unpacked | smaller footprint on the target |
| `.hash.json` sidecar per file | one manifest, itself hashed | half the files, same guarantee |
| Reads `HKCU` of the admin running it | reads every loaded user hive | the admin's hive is rarely the interesting one |
| Tools resolved through `PATH` | full `System32` path | a compromised host may have a planted binary |
| Downloads WinPmem/etl2pcapng from GitHub on the target | never downloads | no network traffic from the target; investigator supplies the tool |
| `netsh wlan ... key=clear` | profile names only | do not harvest secrets |
| Firewall rules via slow cmdlets | read from the registry policy store | faster, no cmdlet dependency |
| Event fields parsed from localized message text | read from event properties | works on non-English Windows |
| Flat output directory shared by runs | one directory per run | runs never mix |
| Output to `C:\IR_Collection` | output next to the exe | run from a USB stick and the evidence lands on the stick, not the suspect disk |
| Launcher self-elevates | bare `aidf` (double-click) self-elevates via UAC, collects, pauses | same one-click use, no unpacking |
| Scripts run strictly one after another | probes overlap on 4 to 8 threads, started in volatility order | much shorter wall-clock time; `--jobs 1` restores sequential |
| "Suspicious" flags inside collectors | none | collection only (owner decision) |
| Report, timeline, IOC, VirusTotal | none | collection only (owner decision) |

## Mapping: original scripts to collectors

| Original script(s) | Collector |
|--------------------|-----------|
| RAM_Dump | RAM_Dump (`--live`) |
| Pagefile_Hiberfil | Pagefile (configuration and metadata; raw VSS copy not ported) |
| Named_Pipes | Named_Pipes |
| Running_Processes | Processes |
| Loaded_DLLs | Loaded_Modules |
| ARP_Entries, DNS_Cache, Network_Connections | Network_State |
| Network_Advanced | Network_Config, Network_State |
| Lateral_Movement | Sessions, Network_Config, Services |
| System_Info, Patch_Level | System_Info |
| Security_EventLog | EventLog_Security |
| System_EventLog | EventLog_System |
| PowerShell_EventLog, PS_Transcript_Collection | EventLog_PowerShell |
| EventLogs_Raw_Export | EventLog_Raw |
| Registry_RunKeys, Registry_Deep_Persistence, GPO_Cache_Scripts, ThreatHunting (COM) | Autoruns_Registry |
| Scheduled_Tasks, Scheduled_Task_XML | Scheduled_Tasks |
| Windows_Services | Services |
| Startup_Folder | Startup_Folders |
| WMI_Persistence | WMI_Persistence |
| Firewall_Rules | Firewall |
| AV_EDR_Status, Defender_Scan_History | Defender_AV |
| Anti_Forensics | Anti_Forensics |
| Local_Users_Groups | Local_Accounts |
| Logon_Sessions_Deep | Logon_Sessions |
| Credential_Artifacts, LSA_Secrets_Metadata | Credentials |
| Certificate_Store | Certificates |
| Registry_Execution_Artifacts, ThreatHunting (UAC, software) | Execution_Artifacts |
| Registry_Hive_Export | Registry_Hives |
| Collect_Prefetch | Prefetch |
| FileSystem_Artifacts | User_Activity |
| SRUM_PowerShell_History | SRUM, EventLog_PowerShell, User_Activity |
| MFT_USN_Collection, Backup_VSS_Deep | NTFS (metadata; raw `$MFT` not ported) |
| USB_Device_History | USB_Devices |
| Browser_Artifacts | Browser, Web_Server |
| Email_Office_Artifacts, Office365_Exchange | Email_Office |
| Cloud_Artifacts | Cloud |
| AI_Attack_Detection | AI_Tooling (inventory only) |
| IIS_WebShell_Detection | Web_Server (file inventory with hashes, logs) |
| SQL_Server_Artifacts | SQL_Server |
| AppX_UWP_Apps | Windows_Apps |
| WSL_HyperV_Artifacts | Virtualization |
| TPM_SecureBoot_BitLocker, WindowsHello_ModernAuth | Platform_Security |
| ActiveDirectory_Artifacts, LAPS_Status, Kerberoasting_Evidence, DCSync_Detection, NTDS_Location | Active_Directory |
| Network_Packet_Capture | Packet_Capture (`--live`) |
| Verify-Evidence | `aidf verify` |
| Run_IR_Collection, DFIR_Common, Launcher.cs, Build-Exe | `main.rs`, `collect.rs`, `build.sh` |
| IOC_Match, IOC_ThreatIntel, Generate_IR_Report, Timeline_Builder, Autoruns_Master_Summary, Analyze-Evidence | not ported (out of scope) |

## Known limits

See [TRACKER.md](TRACKER.md) for status. The important ones:

- Not yet run on a real Windows host. It builds for all three Windows targets and its
  portable logic is unit-tested; the first Windows run is the CI smoke test.
- Raw `$MFT`, `$UsnJrnl` and pagefile capture are not implemented.
- Alternate data streams (Zone.Identifier) are not collected.
