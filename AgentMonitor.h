#pragma once
#include "ProcessCache.h"
#include "EvidenceStore.h"
#include <atomic>
#include <functional>
#include <mutex>
#include <deque>

namespace agentsec {
struct AgentRules {
    std::vector<std::string> names;
    std::vector<std::string> bundles;
    bool include_runtimes = false;
};
std::string MatchAgent(const ProcessNode& node, const AgentRules& rules);
void AnnotateActor(ActorProcess& actor, const AgentRules& rules);
// Plain sentence for a sensitive-file event. It names the agent and tool chain
// and states that an upload was not observed.
std::string SummarizeAccess(const ActorProcess* actor, const std::string& path, const std::string& basis, const AgentRules& rules);
struct ActivityScanStats {
    uint64_t processes = 0, candidates = 0, validation_failed = 0, descriptors_partial = 0, duration_ms = 0;
    uint64_t retirement_pending = 0, retirement_retry_exhausted = 0;
    uint64_t cooccurrence_pairs_truncated = 0;
    uint64_t fast_fd_hits = 0, access_time_events = 0, inferred_accesses = 0;
};
class AgentMonitor {
public:
    using SubmitEvidence = std::function<SubmitResult(EvidenceRecord)>;
    AgentMonitor(ProcessCache& cache, EvidenceStore& store, AgentRules rules, std::vector<std::string> roots);
    AgentMonitor(ProcessCache& cache, SubmitEvidence submit, AgentRules rules, std::vector<std::string> roots);
    void Scan();
    // Classify the current snapshot and publish agent-tree identities for the fast sampler.
    void ArmFocus();
    std::vector<ProcessIdentity> FocusRoots() const;
    // A descriptor was observed on this identity. Safe to call from the sampler thread.
    void ObserveSensitive(const ProcessNode& node, const std::string& path, const std::string& basis);
    // Remember a short-lived descendant so a later access-time change can be graded.
    void NoteObservedDescendant(const ProcessNode& node, uint64_t begin_us, uint64_t end_us, std::set<std::string> fd_paths);
    void NoteAccessTime(const std::string& path, uint64_t window_begin_us, uint64_t window_end_us);
    ActivityScanStats Stats() const noexcept { return stats_; }
private:
    struct Seen {
        ActorProcess actor;
        std::string reason;
        std::set<std::string> activity; // Only successfully submitted observations.
        std::optional<ActorProcess> announced_actor;
        unsigned retirement_attempts = 0;
    };
    struct Span {
        ActorProcess actor;
        uint64_t begin_us = 0, end_us = 0;
        std::set<std::string> fd_paths;
    };
    enum class Claim : int { Stored, Duplicate, Rejected };
    bool Emit(const std::string& type, const Seen& seen, const std::string& target,
        const std::string& detail, RiskLevel risk, const std::string& attribution,
        const std::string& destination = "", const std::string& evidence_basis = "",
        const std::string& summary = "");
    std::optional<ActorProcess> Describe(const ProcessNode& node) const;
    Claim ClaimEmit(const ProcessIdentity& identity, const std::string& detail, const Seen& seen,
        const std::string& type, const std::string& target, RiskLevel risk, const std::string& attribution,
        const std::string& destination, const std::string& evidence_basis, const std::string& summary);
    ProcessCache& cache_;
    SubmitEvidence submit_;
    AgentRules rules_;
    std::vector<std::string> roots_;
    std::map<ProcessIdentity, Seen> seen_;
    std::vector<ProcessIdentity> focus_;
    std::deque<Span> spans_;
    ActivityScanStats stats_;
    uint64_t retirement_retry_exhausted_ = 0, cooccurrence_pairs_truncated_ = 0;
    std::atomic<uint64_t> fast_fd_hits_{0}, access_time_events_{0}, inferred_accesses_{0};
    mutable std::mutex mu_;
};
} // namespace agentsec
