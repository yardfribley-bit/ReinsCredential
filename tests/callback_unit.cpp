#include "FileMonitor.h"
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <unistd.h>

namespace agentsec {
// The injected values follow the C API's borrowed-array contract. This calls
// the production callback and consumes its actual preallocated rings.
struct FileMonitorTestAccess {
    static void Inject(FileMonitor& monitor, const std::string& path,
                       FSEventStreamEventFlags flags, FSEventStreamEventId id) {
        char* names[] = {const_cast<char*>(path.c_str())};
        FileMonitor::Callback(nullptr, &monitor, 1, names, &flags, &id);
    }
    static std::vector<RawFileEvent> Drain(FileMonitor& monitor, bool process) {
        std::vector<RawFileEvent> events;
        for (auto& ring : monitor.rings_) {
            RawFileEvent event;
            while (ring->TryPop(event)) {
                events.push_back(event);
                if (process) monitor.Process(event);
            }
        }
        return events;
    }
    static bool IsFullyStopped(const FileMonitor& monitor) {
        if (monitor.stream_ || monitor.dispatch_ || !monitor.stopping_.load()) return false;
        for (const auto& thread : monitor.workers_) if (thread.joinable()) return false;
        return true;
    }
};
} // namespace agentsec

namespace {
struct TemporaryDirectory {
    TemporaryDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() / "agentsec-callback-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) throw std::runtime_error("mkdtemp failed");
        path = std::filesystem::canonical(pattern);
    }
    ~TemporaryDirectory() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    std::filesystem::path path;
};
size_t Count(const std::string& text, const std::string& token) {
    size_t count = 0, offset = 0;
    while ((offset = text.find(token, offset)) != std::string::npos) { ++count; offset += token.size(); }
    return count;
}
} // namespace

int main() {
    using namespace agentsec;
    TemporaryDirectory temporary;
    const auto log = (temporary.path / "evidence.jsonl").string();
    EvidenceStore::Config config; config.sync_each_record = false;
    EvidenceStore store(log, config);
    FileMonitor monitor({temporary.path.string()}, store, 1);
    const auto file = (temporary.path / "synthetic.env").string();
    FileMonitorTestAccess::Inject(monitor, file, kFSEventStreamEventFlagItemIsFile, 1);
    assert(FileMonitorTestAccess::Drain(monitor, true).empty());

    const FSEventStreamEventFlags gaps[] = {
        kFSEventStreamEventFlagMustScanSubDirs, kFSEventStreamEventFlagUserDropped,
        kFSEventStreamEventFlagKernelDropped, kFSEventStreamEventFlagRootChanged,
        kFSEventStreamEventFlagEventIdsWrapped, kFSEventStreamEventFlagMount,
        kFSEventStreamEventFlagUnmount};
    FSEventStreamEventId id = 10;
    for (const auto flag : gaps) FileMonitorTestAccess::Inject(monitor, file, flag, id++);
    const auto gap_events = FileMonitorTestAccess::Drain(monitor, true);
    assert(gap_events.size() == 7 && monitor.Stats().source_gaps == 7);
    for (size_t i = 0; i < gap_events.size(); ++i) {
        assert(gap_events[i].flags == gaps[i] && gap_events[i].source_id == 10 + i);
        assert(gap_events[i].observed_us > 0);
        assert(std::string(gap_events[i].path.data(), gap_events[i].path_size) == file);
    }
    std::cout << "PASS: callback preserves source ID, path and timestamp; all seven OS gap/topology flags captured\n";

    const FSEventStreamEventFlags changes[] = {kFSEventStreamEventFlagItemCreated,
        kFSEventStreamEventFlagItemModified, kFSEventStreamEventFlagItemRemoved,
        kFSEventStreamEventFlagItemRenamed};
    for (const auto flag : changes) FileMonitorTestAccess::Inject(monitor, file, flag, id++);
    assert(FileMonitorTestAccess::Drain(monitor, true).size() == 4);
    FileMonitorTestAccess::Inject(monitor, "/outside-test-root/synthetic.env", changes[0], id++);
    assert(FileMonitorTestAccess::Drain(monitor, true).size() == 1);
    FileMonitorTestAccess::Inject(monitor, file, gaps[0] | changes[1], id++);
    assert(FileMonitorTestAccess::Drain(monitor, true).size() == 1);

    // The maximum valid payload is PATH_MAX - 1. At PATH_MAX, preserve a loss
    // count instead of publishing a truncated or unterminated filename.
    const std::string boundary(PATH_MAX - 1, 'b'), oversized(PATH_MAX, 'x');
    FileMonitorTestAccess::Inject(monitor, boundary, changes[0], id++);
    const auto boundary_events = FileMonitorTestAccess::Drain(monitor, false);
    assert(boundary_events.size() == 1 && boundary_events[0].path_size == PATH_MAX - 1);
    assert(std::string(boundary_events[0].path.data(), boundary_events[0].path_size) == boundary);
    FileMonitorTestAccess::Inject(monitor, oversized, gaps[0], id++);
    assert(FileMonitorTestAccess::Drain(monitor, false).empty());
    assert(monitor.Stats().oversized_paths == 1 && monitor.Stats().source_gaps == 9);
    std::cout << "PASS: PATH_MAX boundary, oversized-path loss and independent gap accounting\n";

    const auto first = id;
    for (size_t i = 0; i < 1023; ++i) FileMonitorTestAccess::Inject(monitor, file, changes[1], id++);
    FileMonitorTestAccess::Inject(monitor, file, gaps[6], id++);
    FileMonitorTestAccess::Inject(monitor, file, changes[1], id++);
    const auto overflow = monitor.Stats();
    assert(overflow.queue_dropped == 2 && overflow.source_gaps == 10);
    const auto full_events = FileMonitorTestAccess::Drain(monitor, false);
    assert(full_events.size() == 1023);
    for (size_t i = 0; i < full_events.size(); ++i) assert(full_events[i].source_id == first + i);
    FileMonitorTestAccess::Inject(monitor, file, changes[1], id++);
    assert(FileMonitorTestAccess::Drain(monitor, false).size() == 1);
    monitor.Stop(); monitor.Stop(); monitor.Check();
    assert(FileMonitorTestAccess::IsFullyStopped(monitor));
    std::cout << "PASS: callback capacity 1023, exact overflow counts, gap retained on full ring, reuse after drain\n";

    // Force a deterministic filesystem failure after CFArray allocation and
    // before scheduling. This does not simulate partial worker creation or an
    // OS FSEventStreamStart failure; those remain separate fault-injection work.
    FileMonitor invalid({(temporary.path / oversized).string()}, store, 1);
    bool failed = false;
    try { invalid.Start(); } catch (const std::filesystem::filesystem_error&) { failed = true; }
    assert(failed && FileMonitorTestAccess::IsFullyStopped(invalid));
    failed = false;
    try { invalid.Start(); } catch (const std::logic_error&) { failed = true; }
    assert(failed); invalid.Stop();
    std::cout << "PASS: filesystem startup exception unwinds resources; failed instance rejects restart; Stop is idempotent\n";

    store.Close();
    std::ifstream input(log);
    const std::string records((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    assert(Count(records, "\"type\":\"sensor_gap\"") == 8);
    assert(Count(records, "\"type\":\"filesystem_change\"") == 5);
    assert(Count(records, "\"actor_process\":null") == 13);
    assert(records.find("/outside-test-root/") == std::string::npos);
    assert(records.find("\"source_flags\":64") != std::string::npos);
    assert(records.find("\"source_flags\":128") != std::string::npos);
    assert(store.Rejected() == 0);
    std::cout << "PASS: asynchronous JSONL contains topology gaps and sensitive changes; filtering and unknown actor preserved\n";
}
