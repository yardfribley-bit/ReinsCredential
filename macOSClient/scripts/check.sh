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
