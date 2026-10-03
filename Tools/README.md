# Tools

Optional third-party binaries used only by `--live` collectors. `aidf` never downloads
anything on a target; the investigator supplies the tool.

| File | Used by | Source |
|------|---------|--------|
| `winpmem_mini_x64.exe` (any `winpmem*.exe`) | `RAM_Dump` | https://github.com/Velocidex/WinPmem/releases |

Place this folder next to `aidf.exe`, or point at it with `--tools <dir>`.
Set `DFIR_WINPMEM_SHA256` to pin the exact binary: a mismatch aborts the capture.
