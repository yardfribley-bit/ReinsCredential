#include "AgentMonitor.h"
#include <cctype>
#include <filesystem>
#include <unistd.h>
#include <future>
#include <algorithm>

namespace agentsec {
namespace {
std::string Lower(std::string text) {
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}
} // namespace
std::string MatchAgent(const ProcessNode& node, const AgentRules& rules) {
    const auto base = Lower(std::filesystem::path(node.executable).filename().string());
    const auto path = Lower(node.executable);
    for (const auto& name : rules.names) if (base == Lower(name)) return "configured_name:" + name;
    for (const auto& bundle : rules.bundles) {
        const auto component = "/" + Lower(bundle) + "/";
        if (path.find(component) != std::string::npos) return "configured_bundle:" + bundle;
    }
    for (const std::string name : {"claude", "codex", "cursor", "cursor-agent", "workbuddy", "workbuddy-ai", "codebuddy", "aider", "goose", "opencode", "gemini", "cline", "roo"})
        if (base == name) return "known_name:" + name;
    for (const std::string bundle : {"/cursor.app/", "/workbuddy ai.app/", "/workbuddy.app/", "/codebuddy.app/", "/claude.app/", "/codex.app/", "/windsurf.app/", "/trae.app/"})
        if (path.find(bundle) != std::string::npos) return "application_bundle:" + bundle;
    const bool runtime = base == "node" || base == "bun" || base == "python" || base == "python3" || base.rfind("python3.", 0) == 0;
    if (runtime && path.find("/cursor-agent/versions/") != std::string::npos) return "cursor_agent_distribution";
    if (runtime && node.arguments.size() > 1) {
        const auto entry = Lower(node.arguments[1]);
        for (const std::string bundle : {"/workbuddy ai.app/", "/workbuddy.app/", "/codebuddy.app/"})
            if (entry.find(bundle) != std::string::npos && entry.find("/cli/") != std::string::npos) return "application_cli_entrypoint:" + bundle;
        for (const std::string package : {"/@anthropic-ai/claude-code/", "/@openai/codex/", "/@google/gemini-cli/", "/@sourcegraph/amp/", "/opencode-ai/"})
            if (entry.find(package) != std::string::npos) return "package_entrypoint:" + package;
        if (node.arguments.size() > 2 && entry == "-m" && (node.arguments[2] == "aider" || node.arguments[2] == "aider.main")) return "python_module:aider";
    }
    return runtime && rules.include_runtimes ? "generic_runtime_candidate" : "";
}
AgentMonitor::AgentMonitor(ProcessCache& cache, EvidenceStore& store, AgentRules rules, std::vector<std::string> roots)
    : cache_(cache), store_(store), rules_(std::move(rules)), roots_(std::move(roots)) {}
void AgentMonitor::Emit(const std::string& type, const Seen& seen, const std::string& target,
    const std::string& detail, RiskLevel risk, const std::string& attribution) {
    EvidenceRecord record;
    record.type = type; record.actor_process = seen.actor; record.target_resource = target;
    record.detail = detail; record.risk_level = risk; record.attribution = attribution;
    store_.Submit(std::move(record));
}
void AgentMonitor::Scan() {
    const auto begin = MonoClock::now();
    const auto view = cache_.View();
    std::vector<Seen> processes;
    for (const auto& current : view->current) {
        if (current.first == ::getpid()) continue;
        auto actor = view->Resolve(current.second);
        if (!actor) continue;
        auto reason = MatchAgent(actor->process.node, rules_);
        auto previous = seen_.find(current.second);
        if (reason.empty() && previous != seen_.end()) reason = previous->second.reason;
        if (reason.empty()) for (const auto& parent : actor->ancestors) {
            auto known = seen_.find(parent.node.identity);
            if (!MatchAgent(parent.node, rules_).empty() || (known != seen_.end() && !known->second.reason.empty())) {
                reason = "observed_ancestor"; break;
            }
        }
        actor->classification = reason.empty() ? "unclassified_process" : "known_agent_candidate";
        actor->classification_reason = reason;
        processes.push_back({std::move(*actor), std::move(reason), {}});
    }
    // Bounded concurrency for all visible processes, including unknown tools.
    // No name whitelist guards sensitive-file collection.
    std::vector<ActivitySample> activities(processes.size());
    std::atomic<size_t> index{0};
    std::vector<std::future<void>> workers;
    for (size_t lane = 0; lane < std::min(size_t(4), processes.size()); ++lane)
        workers.push_back(std::async(std::launch::async, [&] {
            for (;;) {
                const auto item = index.fetch_add(1);
                if (item >= processes.size()) break;
                activities[item] = cache_.Inspect(processes[item].actor.process.node, roots_, !processes[item].reason.empty());
            }
        }));
    for (auto& worker : workers) worker.get();
    stats_ = {}; stats_.processes = processes.size();
    std::map<ProcessIdentity, Seen> next;
    for (size_t item = 0; item < processes.size(); ++item) {
        auto& seen = processes[item]; const auto& activity = activities[item];
        const auto identity = seen.actor.process.node.identity;
        const auto previous = seen_.find(identity);
        const bool known = !seen.reason.empty();
        stats_.candidates += known;
        stats_.validation_failed += !activity.identity_validated;
        stats_.descriptors_partial += !activity.descriptors_complete;
        if (previous == seen_.end() || (known && previous->second.reason.empty()))
            Emit(known ? "agent_discovered" : "process_discovered", seen, "", known ? seen.reason : "unclassified;inventory_only", RiskLevel::Low, "process_snapshot_heuristic");
        else if (previous->second.actor.process.node.executable != seen.actor.process.node.executable)
            Emit(known ? "agent_changed" : "process_changed", seen, "", "executable_path_changed_with_same_start_identity", RiskLevel::Low, "process_snapshot");
        if (!activity.identity_validated) { if (known) seen.activity.insert("identity_validation_failed"); }
        else {
            if (known && !activity.descriptors_complete) seen.activity.insert("fd_visibility_partial_or_unavailable");
            for (const auto& path : activity.sensitive_files) seen.activity.insert("sensitive_file_open:" + path);
            for (const auto& peer : activity.socket_peers) seen.activity.insert("socket_peer:" + peer);
            if (!activity.sensitive_files.empty() && !activity.socket_peers.empty())
                seen.activity.insert("risk_signal:file_and_socket_coobserved;upload_unproven");
        }
        for (const auto& detail : seen.activity) {
            if (previous != seen_.end() && previous->second.activity.count(detail)) continue;
            const bool file = detail.rfind("sensitive_file_open:", 0) == 0;
            const bool risk = detail.rfind("risk_signal:", 0) == 0;
            Emit("activity_observed", seen, file ? detail.substr(std::string("sensitive_file_open:").size()) : "", detail,
                file || risk ? RiskLevel::Medium : RiskLevel::Low,
                activity.identity_validated ? "identity_validated_descriptor_snapshot" : "validation_failed_no_activity_attributed");
        }
        next.emplace(identity, std::move(seen));
    }
    for (const auto& pair : seen_) if (!next.count(pair.first)) {
        auto retired = pair.second;
        if (auto actor = view->Resolve(pair.first)) retired.actor = std::move(*actor);
        Emit(retired.reason.empty() ? "process_no_longer_observed" : "agent_no_longer_observed", retired, "", "exit_or_visibility_loss_or_pid_replacement", RiskLevel::Low, "cache_state_transition");
    }
    seen_ = std::move(next);
    stats_.duration_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(MonoClock::now() - begin).count());
}
} // namespace agentsec
