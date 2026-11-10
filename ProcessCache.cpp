#include "ProcessCache.h"
#include <algorithm>
#include <stdexcept>

namespace agentsec {
std::optional<ActorProcess> ProcessSnapshot::Resolve(const ProcessIdentity& id) const {
    auto found = history.find(id);
    if (found == history.end()) return std::nullopt;
    ActorProcess actor; actor.process = found->second; actor.chain_status = "missing_parent";
    auto entry = found->second;
    std::set<ProcessIdentity> visited{id};
    for (size_t depth = 0; depth < 128; ++depth) {
        if (entry.node.identity.pid == 1 || entry.node.ppid == 0) {
            actor.chain_complete = true; actor.chain_status = "observed_chain_to_root"; break;
        }
        if (!entry.observed_parent) break;
        if (!visited.insert(*entry.observed_parent).second) { actor.chain_status = "cycle_rejected"; break; }
        auto parent = history.find(*entry.observed_parent);
        if (parent == history.end()) { actor.chain_status = "history_expired_or_evicted"; break; }
        actor.ancestors.push_back(parent->second); entry = parent->second;
        if (depth == 127) actor.chain_status = "depth_limit";
    }
    return actor;
}
ProcessCache::ProcessCache(std::shared_ptr<IProcessSource> source, Config config)
    : source_(std::move(source)), config_(config), snapshot_(std::make_shared<ProcessSnapshot>()) {
    if (!source_ || config_.interval.count() < 50 || config_.retention.count() < 0 || !config_.max_history)
        throw std::invalid_argument("invalid process cache configuration");
}
ProcessCache::~ProcessCache() { Stop(); }
void ProcessCache::Start() {
    if (thread_.joinable() || stopping_) throw std::logic_error("process cache is single-start");
    Refresh();
    thread_ = std::thread([this] {
        try {
            std::unique_lock<std::mutex> wait(wait_mutex_);
            while (!cv_.wait_for(wait, config_.interval, [this] { return stopping_.load(); })) {
                wait.unlock(); Refresh(); wait.lock();
            }
        } catch (...) { std::lock_guard<std::mutex> lock(error_mutex_); error_ = std::current_exception(); }
    });
}
void ProcessCache::Stop() noexcept {
    { std::lock_guard<std::mutex> lock(wait_mutex_); stopping_ = true; }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}
std::shared_ptr<const ProcessSnapshot> ProcessCache::View() const noexcept {
    return std::atomic_load_explicit(&snapshot_, std::memory_order_acquire);
}
void ProcessCache::Check() const {
    std::lock_guard<std::mutex> lock(error_mutex_);
    if (error_) std::rethrow_exception(error_);
}
ActivitySample ProcessCache::Inspect(const ProcessNode& node, const std::vector<std::string>& roots, bool include_idle_peers) {
    // Validate before AND after the descriptor scan. No PID-only cache query.
    if (!source_->Validate(node)) return {};
    auto activity = source_->Inspect(node, roots, include_idle_peers);
    if (!source_->Validate(node)) return {};
    activity.identity_validated = true;
    return activity;
}
void ProcessCache::Refresh() {
    std::lock_guard<std::mutex> serial(refresh_mutex_);
    const auto sample = source_->Sample(); // may throw; never publish a failed sample
    auto next = std::make_shared<ProcessSnapshot>(*View());
    ++next->generation; next->observed_at_us = UnixMicros();
    next->unavailable = sample.unavailable; next->enumeration_complete = sample.enumeration_complete;
    const auto now = MonoClock::now();
    for (auto& pair : next->history)
        if (pair.second.state == ProcessState::Observed) pair.second.state = ProcessState::NotObserved;
    next->current.clear();
    for (const auto& node : sample.processes) {
        if (!source_->Validate(node)) { ++next->unavailable; continue; }
        next->current.emplace(node.identity.pid, node.identity);
        auto found = next->history.find(node.identity);
        if (found == next->history.end()) {
            ProcessEntry entry;
            entry.node = node; entry.first_seen_us = next->observed_at_us;
            found = next->history.emplace(node.identity, std::move(entry)).first;
        }
        auto& entry = found->second;
        entry.node = node; entry.state = ProcessState::Observed;
        entry.last_seen_us = next->observed_at_us; entry.last_seen_mono = now;
    }
    for (auto& pair : next->history) {
        auto& entry = pair.second;
        if (entry.state != ProcessState::Observed) {
            auto current = next->current.find(entry.node.identity.pid);
            if (current != next->current.end() && current->second != entry.node.identity) entry.state = ProcessState::Replaced;
            continue;
        }
        // Do not rebind historical parent links after reparenting or PID reuse.
        if (entry.observed_parent || entry.node.ppid <= 0 || entry.node.identity.pid == 1) continue;
        auto current = next->current.find(entry.node.ppid);
        if (current == next->current.end()) continue;
        const auto& parent = next->history.at(current->second).node;
        const auto birth = [](const ProcessIdentity& id) { return std::make_pair(id.start_seconds, id.start_microseconds); };
        if (parent.identity == entry.node.identity || birth(parent.identity) > birth(entry.node.identity)) continue;
        if (source_->ValidateParent(entry.node, parent)) entry.observed_parent = parent.identity;
    }
    // Historical retention is bounded in time AND count. Never evict a live entry.
    std::vector<std::pair<MonoClock::time_point, ProcessIdentity>> retired;
    for (auto it = next->history.begin(); it != next->history.end();) {
        if (it->second.state != ProcessState::Observed && now - it->second.last_seen_mono > config_.retention) {
            it = next->history.erase(it); ++next->history_evicted;
        } else {
            if (it->second.state != ProcessState::Observed) retired.emplace_back(it->second.last_seen_mono, it->first);
            ++it;
        }
    }
    std::sort(retired.begin(), retired.end());
    for (const auto& pair : retired) {
        if (next->history.size() <= config_.max_history) break;
        next->history.erase(pair.second); ++next->history_evicted;
    }
    std::shared_ptr<const ProcessSnapshot> published = std::move(next);
    std::atomic_store_explicit(&snapshot_, std::move(published), std::memory_order_release);
}
} // namespace agentsec
