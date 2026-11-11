#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
client_dir="$(cd "$(dirname "$0")/.." && pwd)"
source_app="$client_dir/dist/ReinsCredential.app"
destination="$HOME/Applications/ReinsCredential.app"
[[ -d "$source_app" ]] || { echo 'Run scripts/build-app.sh first.' >&2; exit 1; }
[[ ! -e "$destination" ]] || { echo 'Existing installation found. Stop monitoring and quit the old app before replacing it in Finder.' >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$source_app"
mkdir -p "$HOME/Applications"
/usr/bin/ditto "$source_app" "$destination"
/usr/bin/codesign --verify --deep --strict "$destination"
printf 'Installed: %s\n' "$destination"
if [[ "${1:-}" != --no-open ]]; then /usr/bin/open "$destination"; fi
