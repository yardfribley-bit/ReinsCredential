#!/bin/bash
# Remove this product's app and its per-user LaunchAgent.
# Evidence and configuration stay unless --delete-evidence is passed.
# --dry-run prints the actions and does not call launchctl or delete files.
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

delete_evidence=0
dry_run=0
for arg in "$@"; do
  case "$arg" in
    --delete-evidence) delete_evidence=1 ;;
    --dry-run) dry_run=1 ;;
    -h|--help)
      echo "usage: uninstall-local.sh [--dry-run] [--delete-evidence]"
      exit 0
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

label="io.github.yardfribley-bit.ReinsCredential.runtime.local"
plist="$HOME/Library/LaunchAgents/${label}.plist"
domain="gui/$(id -u)/${label}"
support="$HOME/Library/Application Support/ReinsCredential"
apps=("$HOME/Applications/ReinsCredential.app" "/Applications/ReinsCredential.app")

act() {
  if [[ "$dry_run" -eq 1 ]]; then
    printf 'would:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

echo "stop LaunchAgent ${label}"
if [[ "$dry_run" -eq 1 ]]; then
  act /bin/launchctl bootout "$domain"
  act /bin/rm -f "$plist"
elif [[ -e "$plist" ]]; then
  /bin/launchctl bootout "$domain" >/dev/null 2>&1 || true
  /bin/rm -f "$plist"
fi

for app in "${apps[@]}"; do
  echo "remove app ${app}"
  if [[ "$dry_run" -eq 1 ]]; then
    act /bin/rm -rf "$app"
  elif [[ -d "$app" ]]; then
    /bin/rm -rf "$app"
  fi
done

if [[ "$delete_evidence" -eq 1 ]]; then
  echo "delete evidence directory ${support}"
  act /bin/rm -rf "$support"
else
  echo "kept evidence directory"
fi
