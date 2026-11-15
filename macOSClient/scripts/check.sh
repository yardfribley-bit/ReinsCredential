#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
client_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_dir="$(cd "$client_dir/.." && pwd)"
test_dir="$(mktemp -d "${TMPDIR:-/tmp/}reins-swift-tests.XXXXXX")"
trap 'rm -rf "$test_dir"' EXIT
/usr/bin/clang++ -std=c++17 -Wall -Wextra -Wpedantic -Werror -pthread \
  -I "$repo_dir" "$client_dir/Tests/Interop/emit_evidence.cpp" \
  "$repo_dir/EvidenceStore.cpp" -framework CoreServices -o "$test_dir/emit-evidence"
"$test_dir/emit-evidence" > "$test_dir/backend.jsonl"
REINS_BACKEND_FIXTURE="$test_dir/backend.jsonl" /usr/bin/swift test --package-path "$client_dir" "$@"
bin="$(/usr/bin/swift build --package-path "$client_dir" --show-bin-path)"
smoke_dir="$(mktemp -d "${TMPDIR:-/tmp/}reins-ui-smoke.XXXXXX")"
"$bin/ReinsDashboard" --smoke-test "$smoke_dir" --smoke-evidence "$smoke_dir/fixture.jsonl" &
smoke_pid=$!
for _ in $(seq 1 90); do
  if ! kill -0 "$smoke_pid" 2>/dev/null; then break; fi
  sleep 1
done
if kill -0 "$smoke_pid" 2>/dev/null; then
  kill "$smoke_pid" 2>/dev/null || true
  echo "dashboard smoke timed out" >&2
  exit 1
fi
wait "$smoke_pid"
python3 - "$smoke_dir/ui-smoke.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert report.get("status") == "rendered", report
assert report.get("sidebar_rows", 0) >= 1, report
assert report.get("list_rows", 0) >= 1, report
assert report.get("sidebar_pixels", 0) >= 40, report
assert report.get("list_pixels", 0) >= 40, report
assert report.get("inspector_pixels", 0) >= 40, report
print("PASS dashboard smoke", report["sidebar_rows"], report["list_rows"])
PY
rm -rf "$smoke_dir"
