#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
client_dir="$(cd "$(dirname "$0")/.." && pwd)"
app="$client_dir/dist/ReinsCredential.app"
[[ -d "$app" ]] || { echo 'Run scripts/build-app.sh first.' >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$app"
staging="$(mktemp -d "$client_dir/dist/.package.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
/usr/bin/ditto "$app" "$staging/ReinsCredential.app"
ln -s /Applications "$staging/Applications"
cp "$client_dir/INSTALL.md" "$staging/INSTALL.md"
cp "$client_dir/INSTALL.zh-CN.md" "$staging/安装说明.md"
/usr/bin/hdiutil create -volname ReinsCredential -srcfolder "$staging" -ov -format UDZO "$client_dir/dist/ReinsCredential-0.2.0-local.dmg"
/usr/bin/ditto -c -k --keepParent "$app" "$client_dir/dist/ReinsCredential-0.2.0-local.zip"
# File names only, so `shasum -a 256 -c SHA256SUMS.txt` works in the download folder.
(
  cd "$client_dir/dist"
  /usr/bin/shasum -a 256 ReinsCredential-0.2.0-local.dmg ReinsCredential-0.2.0-local.zip > SHA256SUMS.txt
)
