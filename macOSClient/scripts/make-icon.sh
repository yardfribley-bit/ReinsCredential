#!/bin/bash
# Build ReinsCredential.icns from the 1024 PNG master. macOS only (sips, iconutil).
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

root="$(cd "$(dirname "$0")/../.." && pwd)"
master="${REINS_ICON_MASTER:-$root/brand/ReinsCredential-AppIcon-1024.png}"
destination="${1:-$root/macOSClient/dist/ReinsCredential.icns}"
[[ -f "$master" ]] || { echo "missing icon master: $master" >&2; exit 1; }

work="$(mktemp -d "${TMPDIR:-/tmp}/reins-icon.XXXXXX")"
trap 'rm -rf "$work"' EXIT
iconset="$work/ReinsCredential.iconset"
mkdir -p "$iconset"

render() {
  local pixels="$1"
  local name="$2"
  /usr/bin/sips -z "$pixels" "$pixels" "$master" --out "$iconset/$name" >/dev/null
}

render 16 icon_16x16.png
render 32 icon_16x16@2x.png
render 32 icon_32x32.png
render 64 icon_32x32@2x.png
render 128 icon_128x128.png
render 256 icon_128x128@2x.png
render 256 icon_256x256.png
render 512 icon_256x256@2x.png
render 512 icon_512x512.png
render 1024 icon_512x512@2x.png

mkdir -p "$(dirname "$destination")"
/usr/bin/iconutil -c icns "$iconset" -o "$destination"
[[ -s "$destination" ]] || { echo "iconutil produced an empty icns" >&2; exit 1; }
echo "Wrote $destination"
