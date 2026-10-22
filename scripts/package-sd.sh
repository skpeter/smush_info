#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NRO="$ROOT/target/aarch64-skyline-switch/release/libsmush_info.nro"
DIST="$ROOT/dist"
ZIP="$ROOT/smush_info-sd.zip"
PLUGIN_DIR="$DIST/atmosphere/contents/01006A800016E000/romfs/skyline/plugins"

if [[ ! -f "$NRO" ]]; then
  echo "missing $NRO; cargo skyline build --release first" >&2
  exit 1
fi

rm -rf "$DIST" "$ZIP"
mkdir -p "$PLUGIN_DIR" "$DIST/ultimate/smush_info"
cp "$NRO" "$PLUGIN_DIR/libsmush_info.nro"
cp "$ROOT/package/overrides.toml" "$DIST/ultimate/smush_info/overrides.toml"
(cd "$DIST" && zip -r "$ZIP" .)
echo "wrote $ZIP"
