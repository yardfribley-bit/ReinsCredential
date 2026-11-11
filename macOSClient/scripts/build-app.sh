#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
client_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$client_dir/.." && pwd)"
cxx_arch=()
arguments=("$@")
for ((i=0; i<${#arguments[@]}; i++)); do
  if [[ "${arguments[i]}" == --arch ]]; then
    ((i+=1))
    [[ $i -lt ${#arguments[@]} ]] || { echo 'Missing --arch value' >&2; exit 1; }
    cxx_arch+=(-arch "${arguments[i]}")
  fi
done
/usr/bin/swift build --package-path "$client_dir" -c release --product ReinsDashboard "$@"
/usr/bin/swift build --package-path "$client_dir" -c release --product ReinsRuntime "$@"
bin_dir="$(/usr/bin/swift build --package-path "$client_dir" -c release --show-bin-path "$@")"
mkdir -p "$client_dir/dist"
staging="$(mktemp -d "$client_dir/dist/.build-app.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
app_dir="$staging/ReinsCredential.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Helpers" "$app_dir/Contents/Library/LaunchAgents"
cp "$bin_dir/ReinsDashboard" "$app_dir/Contents/MacOS/ReinsDashboard"
cp "$bin_dir/ReinsRuntime" "$app_dir/Contents/MacOS/ReinsRuntime"
sources=(main.cpp ProcessCache.cpp DarwinProcessSource.cpp EvidenceStore.cpp FileMonitor.cpp AgentMonitor.cpp ContentMatcher.cpp)
for ((i=0; i<${#sources[@]}; i++)); do sources[i]="$repo_dir/${sources[i]}"; done
/usr/bin/clang++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror -pthread -mmacosx-version-min=13.0 \
  ${cxx_arch[@]+"${cxx_arch[@]}"} "${sources[@]}" -framework CoreServices -lz -o "$app_dir/Contents/Helpers/agent-monitor"
cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>ReinsCredential</string>
  <key>CFBundleDisplayName</key><string>ReinsCredential</string>
  <key>CFBundleIdentifier</key><string>io.github.yardfribley-bit.ReinsCredential</string>
  <key>CFBundleExecutable</key><string>ReinsDashboard</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.2.0</string>
  <key>CFBundleVersion</key><string>2</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
if [[ "${REINS_SIGNING_IDENTITY:--}" == - ]]; then
  /usr/libexec/PlistBuddy -c 'Add :ReinsLocalLaunchAgent bool true' "$app_dir/Contents/Info.plist"
fi
cat > "$app_dir/Contents/Library/LaunchAgents/io.github.yardfribley-bit.ReinsCredential.runtime.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.github.yardfribley-bit.ReinsCredential.runtime</string>
  <key>BundleProgram</key><string>Contents/MacOS/ReinsRuntime</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>ExitTimeOut</key><integer>15</integer>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PLIST
identity="${REINS_SIGNING_IDENTITY:--}"
/usr/bin/codesign --force --sign "$identity" "$app_dir/Contents/Helpers/agent-monitor"
/usr/bin/codesign --force --sign "$identity" "$app_dir/Contents/MacOS/ReinsRuntime"
/usr/bin/codesign --force --sign "$identity" "$app_dir"
/usr/bin/codesign --verify --deep --strict "$app_dir"
rm -rf "$client_dir/dist/ReinsCredential.app"
mv "$app_dir" "$client_dir/dist/ReinsCredential.app"
printf 'Built local app: %s\n' "$client_dir/dist/ReinsCredential.app"
