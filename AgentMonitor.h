#pragma once
#include "ProcessCache.h"
#include "EvidenceStore.h"

namespace agentsec {
struct AgentRules {
    std::vector<std::string> names;
    std::vector<std::string> bundles;
    bool include_runtimes = false;
};
std::string MatchAgent(const ProcessNode& node, const AgentRules& rules);
struct ActivityScanStats { uint64_t processes = 0, candidates = 0, validation_failed = 0, descriptors_partial = 0, duration_ms = 0; };
class AgentMonitor {
public:
    AgentMonitor(ProcessCache& cache, EvidenceStore& store, AgentRules rules, std::vector<std::string> roots);
    void Scan();
    ActivityScanStats Stats() const noexcept { return stats_; }
private:
    struct Seen { ActorProcess actor; std::string reason; std::set<std::string> activity; };
    void Emit(const std::string& type, const Seen& seen, const std::string& target,
        const std::string& detail, RiskLevel risk, const std::string& attribution);
    ProcessCache& cache_;
    EvidenceStore& store_;
    AgentRules rules_;
    std::vector<std::string> roots_;
    std::map<ProcessIdentity, Seen> seen_;
    ActivityScanStats stats_;
};
} // namespace agentsec
