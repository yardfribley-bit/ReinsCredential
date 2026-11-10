#include "FileMonitor.h"
#include <cstring>
#include <set>
#include <stdexcept>

namespace agentsec {
namespace {
constexpr auto GapFlags = kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped |
    kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagRootChanged | kFSEventStreamEventFlagEventIdsWrapped;
constexpr auto ChangeFlags = kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemModified |
    kFSEventStreamEventFlagItemRemoved | kFSEventStreamEventFlagItemRenamed;
static_assert(std::atomic<uint64_t>::is_always_lock_free, "callback counters must be lock-free");
} // namespace
FileMonitor::FileMonitor(std::vector<std::string> sensitive, EvidenceStore& store, size_t workers)
    : sensitive_(std::move(sensitive)), store_(store) {
    if (sensitive_.empty() || workers == 0 || workers > 8) throw std::invalid_argument("invalid file monitor configuration");
    rings_.reserve(workers); workers_.reserve(workers);
    for (size_t i = 0; i < workers; ++i) rings_.push_back(std::make_unique<Ring>());
}
FileMonitor::~FileMonitor() { Stop(); }
void FileMonitor::Start() {
    if (ever_started_ || stopping_) throw std::logic_error("file monitor is single-start");
    ever_started_ = true;
    try {
        UniqueCF<CFMutableArrayRef> roots(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
        if (!roots) throw std::runtime_error("CFArray allocation failed");
        std::set<std::string> directories;
        for (const auto& target : sensitive_) {
            auto path = std::filesystem::path(target);
            if (!std::filesystem::is_directory(path)) path = path.parent_path();
            while (!std::filesystem::exists(path) && path != path.parent_path()) path = path.parent_path();
            directories.insert(path.string());
        }
        for (const auto& directory : directories) {
            UniqueCF<CFStringRef> value(CFStringCreateWithFileSystemRepresentation(nullptr, directory.c_str()));
            if (!value) throw std::runtime_error("invalid watch directory");
            CFArrayAppendValue(roots.get(), value.get());
        }
        dispatch_.reset(dispatch_queue_create("agentsec.files.source", DISPATCH_QUEUE_SERIAL));
        if (!dispatch_) throw std::runtime_error("dispatch queue creation failed");
        FSEventStreamContext context{0, this, nullptr, nullptr, nullptr}; // borrowed context
        stream_.reset(FSEventStreamCreate(nullptr, &Callback, &context, roots.get(),
            kFSEventStreamEventIdSinceNow, 0.1,
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot |
            kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagIgnoreSelf));
        if (!stream_) throw std::runtime_error("FSEventStreamCreate failed");
        FSEventStreamSetDispatchQueue(stream_.get(), dispatch_.get());
        stream_.get_deleter().scheduled = true;
        for (size_t i = 0; i < rings_.size(); ++i) workers_.emplace_back([this, i] { Consume(i); });
        if (!FSEventStreamStart(stream_.get())) throw std::runtime_error("FSEventStreamStart failed");
        stream_.get_deleter().started = true;
    } catch (...) { Stop(); throw; }
}
void FileMonitor::Stop() noexcept {
    if (stream_) {
        auto& deleter = stream_.get_deleter();
        if (deleter.started) { FSEventStreamStop(stream_.get()); deleter.started = false; }
        if (deleter.scheduled) { FSEventStreamInvalidate(stream_.get()); deleter.scheduled = false; }
        // Source is stopped and unscheduled. Drain any already-enqueued C callbacks
        // while this object, its rings and borrowed context are still alive.
        if (dispatch_) dispatch_sync_f(dispatch_.get(), nullptr, [](void*) {});
        stream_.reset();
    }
    dispatch_.reset();
    stopping_.store(true, std::memory_order_release);
    for (auto& worker : workers_) if (worker.joinable()) worker.join();
}
FileMonitorStats FileMonitor::Stats() const noexcept {
    return {queue_dropped_.load(), oversized_paths_.load(), source_gaps_.load()};
}
void FileMonitor::Check() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    if (error_) std::rethrow_exception(error_);
}
void FileMonitor::Callback(ConstFSEventStreamRef, void* context, size_t count, void* paths,
    const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) noexcept {
    auto& self = *static_cast<FileMonitor*>(context);
    auto names = static_cast<char**>(paths); // borrowed for the callback duration only
    for (size_t i = 0; i < count; ++i) {
        if (flags[i] & GapFlags) self.source_gaps_.fetch_add(1, std::memory_order_relaxed);
        if (!(flags[i] & (GapFlags | ChangeFlags))) continue;
        RawFileEvent event;
        event.source_id = ids[i]; event.flags = flags[i]; event.observed_us = UnixMicros();
        const auto size = strnlen(names[i], event.path.size());
        if (size == event.path.size()) { self.oversized_paths_.fetch_add(1, std::memory_order_relaxed); continue; }
        event.path_size = static_cast<uint32_t>(size);
        std::memcpy(event.path.data(), names[i], size);
        const auto lane = self.producer_lane_++ % self.rings_.size();
        if (!self.rings_[lane]->TryPush(event)) self.queue_dropped_.fetch_add(1, std::memory_order_relaxed);
    }
}
void FileMonitor::Consume(size_t index) noexcept {
    try {
        RawFileEvent event;
        for (;;) {
            if (rings_[index]->TryPop(event)) { Process(event); continue; }
            if (stopping_.load(std::memory_order_acquire)) {
                // Recheck after acquire: the producer may have published immediately
                // before Stop's release store.
                if (rings_[index]->TryPop(event)) { Process(event); continue; }
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    } catch (...) {
        std::lock_guard<std::mutex> lock(error_mutex_);
        if (!error_) error_ = std::current_exception();
    }
}
void FileMonitor::Process(const RawFileEvent& raw) {
    const std::string path(raw.path.data(), raw.path_size);
    if (raw.flags & GapFlags) {
        EvidenceRecord gap;
        gap.type = "sensor_gap"; gap.timestamp = raw.observed_us; gap.source_event_id = raw.source_id;
        gap.source_flags = raw.flags; gap.risk_level = RiskLevel::High;
        gap.detail = "FSEvents gap/root change: rescan and stream reconfiguration required; coverage incomplete";
        gap.target_resource = path; store_.Submit(std::move(gap));
    }
    if (!(raw.flags & ChangeFlags)) return;
    bool sensitive = false;
    for (const auto& root : sensitive_) if (IsWithin(path, root)) { sensitive = true; break; }
    if (!sensitive) return;
    EvidenceRecord record;
    record.type = "filesystem_change"; record.timestamp = raw.observed_us;
    record.target_resource = path; record.source_event_id = raw.source_id; record.source_flags = raw.flags;
    record.risk_level = RiskLevel::Medium;
    record.attribution = "unavailable_fsevents_has_no_actor";
    record.detail = "Observed change; no read/write actor or operation timestamp is supplied by FSEvents";
    // Deliberately never look up a process by PID here or invent an actor from timing.
    store_.Submit(std::move(record));
}
} // namespace agentsec
