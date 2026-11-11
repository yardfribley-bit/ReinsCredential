# Working on ReinsCredential

## Purpose and evidence boundaries

ReinsCredential collects macOS user-space observations about local processes,
sensitive files and explicitly routed content transfers. Read `ACCEPTANCE_REPORT.md`
for the current end-to-end acceptance baseline. A passing component test does not
mean complete agent discovery or exfiltration detection has been achieved.

- FSEvents reports filesystem changes, not reads or an actor PID. Leave its actor
  absent. Never infer a file's actor from the nearest process in time.
- A process identity is PID **plus start seconds and microseconds**. A process
  lifetime may also contain multiple exec images; preserve observed history.
- An open descriptor does not prove a read. A socket peer does not prove payload
  transfer. Keep observation, correlation, local send and remote receipt distinct.
- Agent names/bundle matches are candidate classification, not authentication.
- The explicit content gateway is not transparent system-wide TLS inspection.
- Append-only application I/O alone does not establish tamper-proof or legal evidence.

## Code map

| Area | Entry and responsibility |
| --- | --- |
| Daemon | `main.cpp`: options, lifecycle and health records |
| Native process queries | `DarwinProcessSource.cpp`: libproc identity, FD and socket observations |
| Historical process state | `ProcessCache.h/.cpp`, `Types.h`: identities, snapshots, ancestor links |
| Process activity | `AgentMonitor.h/.cpp`: discovery and candidate/sensitive-resource observations |
| Filesystem intake | `FileMonitor.h/.cpp`, `SpscRing.h`: bounded callback queues and workers |
| Resource ownership | `SystemResources.h`: RAII for native handles |
| Evidence writer | `EvidenceStore.h/.cpp`: schema, JSON escaping, admission and persistence |
| Explicit content channel | `ContentGateway.cpp`, `ContentMatcher.cpp`: opt-in delivery/transfer evidence |
| Native client | `macOSClient/Package.swift`: EvidenceCore / RuntimeCore / ReinsDashboardApp / ReinsRuntime |
| Client model | `macOSClient/Sources/EvidenceCore/Models/Evidence.swift`: backend-to-UI decoding |
| Client input | `EvidenceLogReader.swift`: bounded, read-only JSONL snapshot importer |
| Live input | `LiveEvidenceReader.swift`: bounded actor, partial lines, inode rotation, fresh coverage |
| Background control | `RuntimeController.swift`: SMAppService, independent health, config, self-test |
| Supervisor | `ReinsRuntime/main.swift`, `OwnedChild.swift`: owned process lifecycle, backoff, archive rotation |
| Runtime storage | `RuntimeCore`: private atomic config/status, instance lock, archive retention |
| Local-build service | `RuntimeCore/LocalLaunchAgent.swift`: explicit per-user plist/launchctl for ad-hoc builds; signed builds use SMAppService |
| Installation | `macOSClient/scripts/build-app.sh`, `package-local.sh`, `install-local.sh` |
| Client state/UI | `macOSClient/Sources/ReinsDashboardApp/`: main-actor state and SwiftUI views |
| Wire contract | `schemas/evidence-v2.schema.json`: emitted C++ Schema 2; keep it in sync with `ToJson` |

## Find the relevant contract first

1. Inspect `git status --short`; preserve changes unrelated to your task.
2. Read the smallest relevant implementation, its tests and `ARCHITECTURE.md`.
3. For wire-format changes, inspect `ToJson`, the JSON schema and the Swift decoder
   together. The client Codable format uses camelCase; it is not the backend format.
4. For limitations or product claims, check `ACCEPTANCE_REPORT.md` and the matching
   test result rather than inferring capability from a type or function name.

## Implementation constraints

- Backend: C++17, RAII, no owning raw `new`/`delete`. C API pointers may be borrowed;
  native owned handles need an explicit deleter.
- The FSEvents callback must remain bounded: no logging, disk I/O, process scans or
  waiting for downstream consumers. Report drops and coverage gaps explicitly.
- Keep queue admission and successful persistence separate in API contracts.
- Client: macOS 13+, SwiftUI, semantic colors/materials, main-actor UI state. Keep
  decoding/file I/O out of views and off the UI thread. Preserve missing attribution.
- Demo fixtures must be visibly synthetic. Do not substitute them for live results.
- Do not commit local evidence logs, credentials, private process inventories,
  generated build products or test data containing real secrets.

## Build and verify

```sh
# Backend: native macOS with Xcode command-line tools
make
make check
make integration

# Client: C++ serializer interoperability + Swift model/import/store tests
macOSClient/scripts/check.sh

# Local ad-hoc signed app (no Developer ID/notarization)
macOSClient/scripts/build-app.sh
# Both architectures; execution on each architecture needs its own verification
macOSClient/scripts/build-app.sh --arch arm64 --arch x86_64
macOSClient/scripts/package-local.sh
# Real collector + isolated runtime integration; does not install a LaunchAgent
python3 macOSClient/scripts/runtime-check.py
```

`make acceptance` deliberately returns failure while full behavior acceptance
contains known misses. Do not weaken this gate to make a report green. Native
process/FSEvents tests may need execution outside a development sandbox; distinguish
permission/tooling failures from product test results.

`make shutdown-probe` is also a strict capability gate with a known failure:
an immediately stopped stream may miss a completed write. Do not add a test sleep
or claim that FlushSync is a filesystem barrier. See BACKEND_AUDIT_REPORT.md.
Read macOSClient/PRODUCT_TEST_REPORT.md for installed-product results; the older
macOSClient/TEST_REPORT.md describes the historical snapshot-only release.

For a UI-only change, run the client checks and affected rendering probes; do not
invoke real agents or transmit content unnecessarily. For backend behavior changes,
run the relevant fault/race/integration tests. Record exact commands, platform,
pass/fail/skip counts and untested scopes in the matching report.

## Shipping a change

Describe the trigger, resulting behavior and evidence of validation. Keep reports
dated; preserve earlier failures as historical results. Stage only intended files.
Do not claim production readiness, complete detection or cross-architecture runtime
coverage from compilation or unit tests alone.
