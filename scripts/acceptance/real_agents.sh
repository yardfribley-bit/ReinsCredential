#!/bin/bash
# Fake-secret acceptance entry. Does not install, merge, or edit agent configs.
# See scripts/acceptance/README.md before --mode owner.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
if [[ -x /usr/bin/python3 ]]; then
  py=/usr/bin/python3
else
  py="$(command -v python3)"
fi
if [[ "${1:-}" == "--mode" && "${2:-}" == "ci" ]]; then
  "$py" scripts/acceptance/self_check.py
fi
exec "$py" scripts/acceptance/harness.py "$@"
