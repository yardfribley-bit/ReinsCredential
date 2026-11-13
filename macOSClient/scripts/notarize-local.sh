#!/bin/bash
# Notarize a packaged disk image when Apple credentials are in the environment.
# Missing credentials are a local/ad-hoc build, not an error. This script never
# reads a keychain item and never installs a CA.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

client_dir="$(cd "$(dirname "$0")/.." && pwd)"
dmg="$client_dir/dist/ReinsCredential-0.2.0-local.dmg"
[[ -f "$dmg" ]] || { echo "Run scripts/package-local.sh first." >&2; exit 1; }

if [[ -z "${APPLE_ID:-}" || -z "${APPLE_TEAM_ID:-}" || -z "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
  echo "Notarization credentials are not set. The package keeps its current signature."
  exit 0
fi

/usr/bin/xcrun notarytool submit "$dmg" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_SPECIFIC_PASSWORD" \
  --wait
/usr/bin/xcrun stapler staple "$dmg"
echo "Notarized: $dmg"
