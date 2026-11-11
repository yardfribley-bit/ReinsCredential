#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
client_dir="$(cd "$(dirname "$0")/.." && pwd)"
/usr/bin/swift build --package-path "$client_dir" -c release --product ReinsDashboard "$@"
bin_dir="$(/usr/bin/swift build --package-path "$client_dir" -c release --show-bin-path "$@")"
app_dir="$client_dir/dist/ReinsCredential.app"
mkdir -p "$app_dir/Contents/MacOS"
cp "$bin_dir/ReinsDashboard" "$app_dir/Contents/MacOS/ReinsDashboard"
cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>ReinsCredential</string>
  <key>CFBundleDisplayName</key><string>ReinsCredential</string>
  <key>CFBundleIdentifier</key><string>io.github.yardfribley-bit.ReinsCredential</string>
  <key>CFBundleExecutable</key><string>ReinsDashboard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
/usr/bin/codesign --force --sign - "$app_dir"
printf 'Built local app: %s\n' "$app_dir"
