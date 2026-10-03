#!/usr/bin/env bash
# Build aidf for every Windows flavour (x64, x86, arm64) and for the build host.
#
#   ./build.sh              test, then build every flavour into dist/
#   ./build.sh windows      all three Windows flavours
#   ./build.sh x64|x86|arm64   one Windows flavour
#   ./build.sh host         native build for this machine (runs `aidf verify` anywhere)
#   ./build.sh test         unit tests
#   ./build.sh check        type-check all Windows flavours (needs no linker)
#   ./build.sh setup        install the cross toolchain (rustup targets + cargo-xwin)
#   ./build.sh clean
#
# Works on Windows (Git Bash / MSYS2, MSVC toolchain), macOS and Linux (cross-compiles).
set -euo pipefail
cd "$(dirname "$0")"

# Cross targets need the rustup-managed toolchain, not a distro/Homebrew cargo.
if [ -x "$HOME/.cargo/bin/rustup" ]; then PATH="$HOME/.cargo/bin:$PATH"; fi
command -v cargo >/dev/null || { echo "cargo not found - install Rust from https://rustup.rs" >&2; exit 1; }

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DIST=dist
FLAVOURS="x64 x86 arm64"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) ON_WINDOWS=1 ;;
  *) ON_WINDOWS=0 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf '\n== %s\n' "$*"; }

arch_of() {
  case "$1" in
    x64) echo x86_64 ;; x86) echo i686 ;; arm64) echo aarch64 ;;
    *) echo "unknown flavour '$1' (expected: $FLAVOURS)" >&2; exit 2 ;;
  esac
}

# How this machine can link a Windows binary: msvc | xwin | zig | mingw | none
linker_for() {
  local arch; arch=$(arch_of "$1")
  if [ "$ON_WINDOWS" = 1 ]; then echo msvc
  elif have cargo-xwin; then echo xwin
  elif have cargo-zigbuild && have zig; then echo zig
  elif [ "$arch" != aarch64 ] && have "${arch}-w64-mingw32-gcc"; then echo mingw
  else echo none; fi
}

target_for() {
  local arch; arch=$(arch_of "$1")
  case "$2" in
    msvc|xwin) echo "${arch}-pc-windows-msvc" ;;
    zig) if [ "$arch" = aarch64 ]; then echo aarch64-pc-windows-gnullvm; else echo "${arch}-pc-windows-gnu"; fi ;;
    *) echo "${arch}-pc-windows-gnu" ;;
  esac
}

add_target() { if have rustup; then rustup target add "$1" >/dev/null 2>&1 || true; fi; }

publish() {  # publish <built file> <dist name>
  mkdir -p "$DIST"
  cp "$1" "$DIST/$2"
  echo "   -> $DIST/$2 ($(wc -c < "$DIST/$2" | tr -d ' ') bytes)"
}

build_windows() {
  local flavour=$1 linker target
  linker=$(linker_for "$flavour")
  say "windows-$flavour ($linker)"
  if [ "$linker" = none ]; then
    echo "   skipped: no Windows linker for $flavour on this machine - run ./build.sh setup" >&2
    SKIPPED="$SKIPPED $flavour"
    return 0
  fi
  target=$(target_for "$flavour" "$linker")
  add_target "$target"
  case "$linker" in
    # Static CRT: the exe must run on a target with no Visual C++ runtime installed.
    msvc) RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "$target" ;;
    # XWIN_ARCH: fetch the MSVC CRT + Windows SDK libraries for every flavour, not just x64.
    xwin) XWIN_ARCH="x86,x86_64,aarch64" RUSTFLAGS="-C target-feature=+crt-static -A linker_messages" \
            cargo xwin build --release --target "$target" ;;
    zig)  cargo zigbuild --release --target "$target" ;;
    mingw)
      local arch var; arch=$(arch_of "$flavour")
      var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER"
      env "$var=${arch}-w64-mingw32-gcc" cargo build --release --target "$target" ;;
  esac
  publish "target/$target/release/aidf.exe" "aidf-$VERSION-windows-$flavour.exe"
}

build_host() {
  say "host ($(rustc -vV | sed -n 's/^host: //p'))"
  cargo build --release
  local ext=""; [ "$ON_WINDOWS" = 1 ] && ext=".exe"
  publish "target/release/aidf$ext" "aidf-$VERSION-$(rustc -vV | sed -n 's/^host: //p')$ext"
}

run_tests() { say "tests"; cargo test --quiet; }

check_windows() {
  for f in $FLAVOURS; do
    local target; target="$(arch_of "$f")-pc-windows-msvc"
    say "check windows-$f ($target)"
    add_target "$target"
    cargo check --quiet --target "$target"
  done
}

setup() {
  say "setup"
  have rustup || { echo "rustup is required for cross targets: https://rustup.rs" >&2; exit 1; }
  for f in $FLAVOURS; do rustup target add "$(arch_of "$f")-pc-windows-msvc"; done
  if [ "$ON_WINDOWS" = 1 ]; then echo "Windows host: install the Visual Studio C++ Build Tools (and the ARM64 build tools for arm64)."
  else
    # cargo-xwin links with the lld that ships inside the Rust toolchain and fetches the
    # MSVC CRT + Windows SDK libraries on first use (about 1 GB under the user cache dir).
    cargo install cargo-xwin --locked
  fi
}

checksums() {
  [ -d "$DIST" ] || return 0
  say "checksums"
  ( cd "$DIST" && rm -f SHA256SUMS && { if have sha256sum; then sha256sum aidf-*; else shasum -a 256 aidf-*; fi; } | tee SHA256SUMS )
}

SKIPPED=""
case "${1:-all}" in
  all)     run_tests; build_host; for f in $FLAVOURS; do build_windows "$f"; done; checksums ;;
  windows) for f in $FLAVOURS; do build_windows "$f"; done; checksums ;;
  x64|x86|arm64) build_windows "$1"; checksums ;;
  host)    build_host; checksums ;;
  test)    run_tests ;;
  check)   check_windows ;;
  setup)   setup ;;
  clean)   cargo clean; rm -rf "$DIST" ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac

if [ -n "$SKIPPED" ]; then
  echo
  echo "NOT BUILT:$SKIPPED (no Windows linker here). Run ./build.sh setup, or build on Windows / in CI." >&2
  exit 3
fi
