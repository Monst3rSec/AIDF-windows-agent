# ADLC - AI-Driven Development Life Cycle

How work on this project moves from an idea to a release when an AI coding agent does
most of the building and a human owner decides. Every change, large or small, passes
through the same seven phases. Each phase has one output and one gate.

## Roles

- **Owner** (human): sets scope, approves plans, makes every decision that affects what
  evidence is collected or what changes on a target host, and approves releases.
- **Agent** (AI): reads, plans, builds, tests and reports. Reports what was verified and
  what was not, in those words.

## Phases

| # | Phase | The agent does | Output | Gate to pass |
|---|-------|----------------|--------|--------------|
| 1 | Discover | Reads the source material and the code that exists | Findings in the tracker item | The problem is restated correctly |
| 2 | Plan | Breaks work into tracker items with acceptance criteria | Items in [TRACKER.md](TRACKER.md) | Owner agrees with scope |
| 3 | Design | Decides the approach; records it if it changes architecture or evidence format | Section in [PROJECT.md](PROJECT.md) | Fits the design rules below |
| 4 | Build | Implements the smallest change that meets the criteria | Code and tests | `./build.sh test` passes |
| 5 | Verify | Proves it works at the highest level available | Verification level in the tracker | Level recorded honestly |
| 6 | Release | Builds all flavours and checksums | `dist/` and `SHA256SUMS` | Owner approves |
| 7 | Learn | Records what a real run revealed | New tracker items | Nothing known is left unwritten |

Scope can change mid-flight. When the owner changes it, the agent updates PROJECT.md and
TRACKER.md first, then the code.

## Verification levels

A tracker item is `Done` only with a level attached. Higher is stronger.

| Level | Meaning |
|-------|---------|
| V0 | Written, not compiled |
| V1 | Type-checks for the Windows targets (`./build.sh check`) |
| V2 | Unit-tested on the build host |
| V3 | Runs on a real Windows host in CI (smoke test) |
| V4 | Output reviewed on a real Windows host by a person |

Never report a higher level than was reached. Windows-only code built on macOS or Linux
tops out at V1 until CI or a person runs it.

## Design rules (the Design gate)

1. **Collect, do not judge.** No detection logic, scoring or "suspicious" flags.
2. **Read-only by default.** Anything that changes the target is `live` and needs `--live`.
3. **No secrets.** Do not collect passwords, keys, tokens or cookie stores. Names and
   timestamps of such stores are fine.
4. **No network from the target.** Nothing is downloaded or uploaded.
5. **One failure never stops the run.** Probes return errors; errors are recorded.
6. **Everything is hashed.** Any file written under the run directory lands in the manifest.
7. **Most volatile first.** New collectors go in the right place in the catalog order.
8. **Data over code.** Prefer a new catalog row to a new function; prefer a native probe
   to `Cmd`, and `Cmd` to `Ps`.

## Definition of done

- Acceptance criteria in the tracker item are met.
- Tests cover the portable logic; catalog tests pass.
- `./build.sh test` and `./build.sh check` pass.
- PROJECT.md is updated if architecture, evidence format or the script mapping changed.
- The tracker item shows status and verification level.
