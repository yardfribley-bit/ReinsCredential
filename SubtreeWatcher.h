#pragma once
#include "AgentMonitor.h"
#include <atomic>
#include <memory>
#include <thread>

namespace agentsec {
// Watches agent-tree forks and execs, then samples those processes immediately.
// Access-time checks cover the bounded sensitive set. Neither signal is an upload.
class SubtreeWatcher {
public:
    struct Stats {
        uint64_t focused = 0, bursts = 0, fd_hits = 0, fork_notes = 0, exec_notes = 0;
        uint64_t dropped_bursts = 0, atime_events = 0, sweep_us = 0, running = 0;
    };
    SubtreeWatcher(std::shared_ptr<IProcessSource> source, std::vector<std::string> roots, AgentMonitor& monitor);
    ~SubtreeWatcher();
    SubtreeWatcher(const SubtreeWatcher&) = delete;
    SubtreeWatcher& operator=(const SubtreeWatcher&) = delete;
    void Start();
    void Stop() noexcept;
    void Focus(std::vector<ProcessIdentity> roots);
    Stats GetStats() const;
private:
    void Loop();
    std::shared_ptr<IProcessSource> source_;
    std::vector<std::string> roots_;
    AgentMonitor& monitor_;
    std::thread thread_;
    std::atomic<bool> stopping_{false};
    mutable std::mutex focus_mu_;
    std::vector<ProcessIdentity> focus_;
    int wake_ = -1;
    int queue_ = -1;
    std::atomic<uint64_t> bursts_{0}, fd_hits_{0}, fork_notes_{0}, exec_notes_{0}, dropped_{0}, atime_events_{0}, sweep_us_{0};
};
} // namespace agentsec
