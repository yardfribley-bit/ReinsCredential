#pragma once
#include "Types.h"
#include <atomic>
#include <condition_variable>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

namespace agentsec {
struct ProcessSample {
    std::vector<ProcessNode> processes;
    size_t unavailable = 0;
    bool enumeration_complete = true;
};
// One socket observed on a process. tx_bytes is the kernel TCP send counter
// when bytes_known is true. It is not a copy of the payload.
struct SocketFlow {
    std::string flow_id;
    std::string destination;
    bool loopback = false;
    bool udp = false;
    bool bytes_known = false;
    uint64_t tx_bytes = 0;
    int tcp_state = -1;
};
struct ActivitySample {
    bool identity_validated = false, descriptors_complete = true;
    std::set<std::string> sensitive_files, socket_peers;
    std::vector<SocketFlow> flows;
};
class IProcessSource {
public:
    // Sample and Inspect/Validate may run concurrently. Implementations must be thread-safe.
    virtual ~IProcessSource() = default;
    virtual ProcessSample Sample() = 0;
    virtual bool Validate(const ProcessNode& node) = 0;
    virtual bool ValidateParent(const ProcessNode& child, const ProcessNode& parent) = 0;
    // Default refuses. Darwin re-reads the child's ppid. A true result does not
    // invent the parent's start time when that parent could not be read.
    virtual bool ConfirmParentPid(const ProcessNode& node, pid_t ppid) { (void)node; (void)ppid; return false; }
    virtual std::optional<ProcessNode> Lookup(pid_t pid) { (void)pid; return std::nullopt; }
    virtual ActivitySample Inspect(const ProcessNode& node, const std::vector<std::string>& roots, bool include_idle_peers) = 0;
    // Flows this source saw for the pid, including sockets that have already closed.
    virtual std::vector<SocketFlow> RetainedFlows(pid_t pid) const { (void)pid; return {}; }
};
std::shared_ptr<IProcessSource> MakeDarwinProcessSource();
struct ProcessSnapshot {
    uint64_t generation = 0, observed_at_us = 0;
    size_t unavailable = 0, history_evicted = 0;
    bool enumeration_complete = true;
    std::map<ProcessIdentity, ProcessEntry> history;
    std::map<pid_t, ProcessIdentity> current;
    std::optional<ActorProcess> Resolve(const ProcessIdentity& identity) const;
};
class ProcessCache {
public:
    struct Config {
        std::chrono::milliseconds interval{500};
        std::chrono::seconds retention{300};
        size_t max_history = 32768;
    };
    ProcessCache(std::shared_ptr<IProcessSource> source, Config config);
    ~ProcessCache();
    ProcessCache(const ProcessCache&) = delete;
    ProcessCache& operator=(const ProcessCache&) = delete;
    void Start(); // initial snapshot completes before returning
    void Stop() noexcept;
    void Refresh(); // serialized; also used with a deterministic test source
    std::shared_ptr<const ProcessSnapshot> View() const noexcept;
    ActivitySample Inspect(const ProcessNode& node, const std::vector<std::string>& roots, bool include_idle_peers = false);
    bool ConfirmParentPid(const ProcessNode& node, pid_t ppid);
    std::optional<ProcessNode> Lookup(pid_t pid);
    void Check() const;
private:
    std::shared_ptr<IProcessSource> source_;
    Config config_;
    std::shared_ptr<const ProcessSnapshot> snapshot_;
    std::mutex refresh_mutex_, wait_mutex_;
    mutable std::mutex error_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stopping_{false};
    std::exception_ptr error_;
    std::thread thread_;
};
} // namespace agentsec
