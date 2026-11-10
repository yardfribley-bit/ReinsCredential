#pragma once
#include "EvidenceStore.h"
#include "SpscRing.h"
#include <array>
#include <atomic>
#include <filesystem>
#include <limits.h>
#include <memory>
#include <thread>
#include <vector>

namespace agentsec {
struct RawFileEvent {
    uint64_t source_id = 0, observed_us = 0;
    FSEventStreamEventFlags flags = 0;
    uint32_t path_size = 0;
    std::array<char, PATH_MAX> path{};
};
struct FileMonitorStats { uint64_t queue_dropped = 0, oversized_paths = 0, source_gaps = 0; };
class FileMonitor {
public:
    FileMonitor(std::vector<std::string> sensitive, EvidenceStore& store, size_t workers = 2);
    ~FileMonitor();
    FileMonitor(const FileMonitor&) = delete;
    FileMonitor& operator=(const FileMonitor&) = delete;
    void Start();
    void Stop() noexcept; // control thread only; never call from the dispatch queue
    void Check() const;
    FileMonitorStats Stats() const noexcept;
private:
    using Ring = SpscRing<RawFileEvent, 1024>;
    static void Callback(ConstFSEventStreamRef, void*, size_t, void*, const FSEventStreamEventFlags[], const FSEventStreamEventId[]) noexcept;
    void Consume(size_t index) noexcept;
    void Process(const RawFileEvent& event);
    std::vector<std::string> sensitive_;
    EvidenceStore& store_;
    std::vector<std::unique_ptr<Ring>> rings_;
    std::vector<std::thread> workers_;
    // Queue outlives stream; Stop invalidates, drains callbacks, then releases both.
    UniqueDispatch dispatch_;
    UniqueStream stream_;
    bool ever_started_ = false;
    size_t producer_lane_ = 0;
    std::atomic<bool> stopping_{false};
    std::atomic<uint64_t> queue_dropped_{0}, oversized_paths_{0}, source_gaps_{0};
    mutable std::mutex error_mutex_;
    std::exception_ptr error_;
};
} // namespace agentsec
