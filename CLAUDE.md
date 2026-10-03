# CLAUDE.md

Guidance for AI coding agents working in this repository.

## What this is

`aidf`: a single-binary Windows DFIR **evidence collector** in Rust. Collection only - no
IOC matching, detection, scoring, report or timeline. Do not add analysis features; the
owner removed them on purpose (see PROJECT.md, "Scope").

## Process

Follow [ADLC.md](ADLC.md). Before coding, find or add the item in [TRACKER.md](TRACKER.md).
After coding, set its status and verification level (V0-V4). Never claim a level you did
not reach: Windows-only code built on macOS/Linux is V1 at most.

## Commands

```
./build.sh test      # unit tests (run this after every change)
./build.sh check     # type-check Windows x64, x86, arm64 - no linker needed
./build.sh host      # native build into dist/
./build.sh windows   # all Windows flavours (one-time: ./build.sh setup installs cargo-xwin)
./build.sh           # tests + host + all Windows flavours into dist/
cargo run -- list    # print the collection plan
cargo run -- collect --out /tmp/ir --phase Named_Pipes   # pipeline smoke run off Windows
```

`cargo` must be the rustup one (`~/.cargo/bin`) for Windows targets; `build.sh` handles it.

## Layout

- `src/catalog.rs` - the collection plan. Most changes are a new row here.
- `src/probe.rs` - probe kinds and how they run.
- `src/reg.rs` - native registry (Windows) with a non-Windows stub.
- `src/native.rs` - collectors that need custom code.
- `src/collect.rs` - run loop, manifest, package, verify.
- `src/main.rs`, `src/ctx.rs`, `src/util.rs` - CLI, context, helpers.

## Rules that are easy to break

- **Catalog order is collection order**, most volatile first. Tests assert the anchors.
- **`Ps` bodies: no double quotes, no `#`.** They travel as one command-line argument and
  are collapsed to one line. Separate statements with `;`. A test enforces this.
- **`Ps` output must be JSON-safe:** wrap dates in `T ...` (UTC ISO-8601) and cast enums
  with `[string]`. Raw `DateTime` serialises as `/Date(...)/` in PowerShell 5.1.
- **Read event fields from `$_.Properties[n]`,** not from message text (localised).
- **No secrets.** Use `RegNames` or `Files` (metadata) for credential stores; never `Text`,
  `Copy` or `Reg` on them.
- **State-changing collectors use `live(...)`** and only run with `--live`.
- **A probe returns `Err`, it never panics or exits.** Errors are evidence of what could
  not be collected.
- **Anything writing files puts them under `ctx.raw_dir(collector)`** so the manifest
  hashes them; put `{raw}` in a `Cmd` argument to get that path.
- **Bare `aidf` means "collect here".** No arguments = elevate, collect next to the exe,
  pause. Do not turn the no-argument path back into help.
- **Run helpers by bare name** (`"netsh.exe"`); `probe::sys` pins them to `System32`.
- Keep it portable: everything except `reg.rs`'s `imp` module must compile and test on
  macOS/Linux. Gate Windows-only code with `#[cfg(windows)]`.
- Dependencies are deliberately few (`serde_json`, `sha2`, `zip`, `winreg`). Ask before
  adding one.

## Adding a collector

1. Add a row to `CATALOG` in the right volatility position, with phase and MITRE IDs.
2. Prefer `Reg`/`Files`/`Copy`/`Text`, then `Cmd`, then `Ps`.
3. Add it to the mapping table in PROJECT.md if it ports an original script.
4. `./build.sh test && ./build.sh check`, then update TRACKER.md.
