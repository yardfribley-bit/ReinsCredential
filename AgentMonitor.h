#pragma once
#include "ProcessCache.h"
#include "EvidenceStore.h"
#include <functional>

namespace agentsec {
struct AgentRules {
    std::vector<std::string> names;
    std::vector<std::string> bundles;
    bool include_runtimes = false;
};
std::string MatchAgent(const ProcessNode& node, const AgentRules& rules);
struct ActivityScanStats {
    uint64_t processes = 0, candidates = 0, validation_failed = 0, descriptors_partial = 0, duration_ms = 0;
    uint64_t retirement_pending = 0, retirement_retry_exhausted = 0;
    uint64_t cooccurrence_pairs_truncated = 0;
};
class AgentMonitor {
public:
    using SubmitEvidence = std::function<SubmitResult(EvidenceRecord)>;
    AgentMonitor(ProcessCache& cache, EvidenceStore& store, AgentRules rules, std::vector<std::string> roots);
    AgentMonitor(ProcessCache& cache, SubmitEvidence submit, AgentRules rules, std::vector<std::string> roots);
    void Scan();
    ActivityScanStats Stats() const noexcept { return stats_; }
private:
    struct Seen {
        ActorProcess actor;
        std::string reason;
        std::set<std::string> activity; // Only successfully submitted observations.
        std::optional<ActorProcess> announced_actor;
        unsigned retirement_attempts = 0;
    };
    bool Emit(const std::string& type, const Seen& seen, const std::string& target,
        const std::string& detail, RiskLevel risk, const std::string& attribution,
        const std::string& destination = "", const std::string& evidence_basis = "");
    ProcessCache& cache_;
    SubmitEvidence submit_;
    AgentRules rules_;
    std::vector<std::string> roots_;
    std::map<ProcessIdentity, Seen> seen_;
    ActivityScanStats stats_;
    uint64_t retirement_retry_exhausted_ = 0, cooccurrence_pairs_truncated_ = 0;
};
} // namespace agentsec
