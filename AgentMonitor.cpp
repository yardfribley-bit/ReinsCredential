#include "AgentMonitor.h"
#include <cctype>
#include <filesystem>
#include <unistd.h>
#include <future>
#include <algorithm>
#include <stdexcept>

namespace agentsec {
namespace {
std::string Lower(std::string text) {
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}
bool SameImage(const ProcessNode& a, const ProcessNode& b) {
    return a.executable == b.executable && a.arguments == b.arguments;
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
    : AgentMonitor(cache, [&store](EvidenceRecord record) { return store.Submit(std::move(record)); }, std::move(rules), std::move(roots)) {}
AgentMonitor::AgentMonitor(ProcessCache& cache, SubmitEvidence submit, AgentRules rules, std::vector<std::string> roots)
    : cache_(cache), submit_(std::move(submit)), rules_(std::move(rules)), roots_(std::move(roots)) {
    if (!submit_) throw std::invalid_argument("missing evidence sink");
}
bool AgentMonitor::Emit(const std::string& type, const Seen& seen, const std::string& target,
    const std::string& detail, RiskLevel risk, const std::string& attribution,
    const std::string& destination, const std::string& evidence_basis) {
    EvidenceRecord record;
    record.type = type; record.actor_process = seen.actor; record.target_resource = target;
    record.detail = detail; record.risk_level = risk; record.attribution = attribution;
    record.destination = destination; record.evidence_basis = evidence_basis;
    return submit_(std::move(record)) == SubmitResult::Accepted;
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
        if (reason.empty()) for (const auto& parent : actor->ancestors) {
            if (!MatchAgent(parent.node, rules_).empty()) {
                reason = "observed_ancestor"; break;
            }
        }
        actor->classification = reason.empty() ? "unclassified_process" : "known_agent_candidate";
        actor->classification_reason = reason;
        processes.push_back({std::move(*actor), std::move(reason), {}, {}, 0});
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
        if (previous != seen_.end()) seen.announced_actor = previous->second.announced_actor;
        if (!seen.announced_actor || (known && seen.announced_actor->classification_reason.empty())) {
            if (Emit(known ? "agent_discovered" : "process_discovered", seen, "", known ? seen.reason : "unclassified;inventory_only", RiskLevel::Low, "process_snapshot_heuristic"))
                seen.announced_actor = seen.actor;
        } else if (!SameImage(seen.announced_actor->process.node, seen.actor.process.node) ||
            seen.announced_actor->classification_reason != seen.reason) {
            if (Emit(known ? "agent_changed" : "process_changed", seen, "", "image_or_classification_changed_with_same_start_identity", RiskLevel::Low, "process_snapshot"))
                seen.announced_actor = seen.actor;
        }
        if (!activity.identity_validated) { if (known) seen.activity.insert("identity_validation_failed"); }
        else {
            if (known && !activity.descriptors_complete) seen.activity.insert("fd_visibility_partial_or_unavailable");
            for (const auto& path : activity.sensitive_files) seen.activity.insert("sensitive_file_open:" + path);
            for (const auto& peer : activity.socket_peers) seen.activity.insert("socket_peer:" + peer);
            if (!activity.sensitive_files.empty() && !activity.socket_peers.empty())
                seen.activity.insert("risk_signal:file_and_socket_coobserved;upload_unproven");
        }
        const auto observed_activity = std::move(seen.activity);
        seen.activity.clear();
        for (const auto& detail : observed_activity) {
            if (previous != seen_.end() && SameImage(previous->second.actor.process.node, seen.actor.process.node) && previous->second.activity.count(detail)) {
                seen.activity.insert(detail); continue;
            }
            const bool file = detail.rfind("sensitive_file_open:", 0) == 0;
            const bool risk = detail.rfind("risk_signal:", 0) == 0;
            if (Emit("activity_observed", seen, file ? detail.substr(std::string("sensitive_file_open:").size()) : "", detail,
                file || risk ? RiskLevel::Medium : RiskLevel::Low,
                activity.identity_validated ? "identity_validated_descriptor_snapshot" : "validation_failed_no_activity_attributed"))
                seen.activity.insert(detail);
        }
        // Pair only descriptors from this one validated activity sample. This
        // reports co-occurrence, not an observed read, send or remote receipt.
        // Limit pair fan-out independently of the bounded evidence store.
        if (activity.identity_validated) {
            const auto pair_count = static_cast<uint64_t>(activity.sensitive_files.size()) * activity.socket_peers.size();
            if (pair_count > 32) cooccurrence_pairs_truncated_ += pair_count - 32;
            size_t pairs = 0;
            for (const auto& path : activity.sensitive_files) {
              if (pairs == 32) break;
              for (const auto& peer : activity.socket_peers) {
                if (pairs == 32) break;
                ++pairs;
                const auto key = "cooccurrence:" + path + std::string(1, '\0') + peer;
                if (previous != seen_.end() && SameImage(previous->second.actor.process.node, seen.actor.process.node) && previous->second.activity.count(key)) {
                    seen.activity.insert(key); continue;
                }
                if (Emit("sensitive_network_cooccurrence", seen, path,
                    "Sensitive file descriptor and socket peer observed in the same sample; upload_unproven",
                    RiskLevel::Medium, "identity_validated_descriptor_snapshot", peer, "same_identity_descriptor_snapshot"))
                    seen.activity.insert(key);
              }
            }
        }
        next.emplace(identity, std::move(seen));
    }
    for (const auto& pair : seen_) if (!next.count(pair.first)) {
        auto retired = pair.second;
        if (auto actor = view->Resolve(pair.first)) {
            actor->classification = retired.actor.classification;
            actor->classification_reason = retired.reason;
            retired.actor = std::move(*actor);
        }
        if (retired.actor.process.state == ProcessState::Observed)
            retired.actor.process.state = ProcessState::NotObserved;
        if (!Emit(retired.reason.empty() ? "process_no_longer_observed" : "agent_no_longer_observed", retired, "", "exit_or_visibility_loss_or_pid_replacement", RiskLevel::Low, "cache_state_transition")) {
            // Bound retry memory even if the sink remains closed or full.
            if (++retired.retirement_attempts < 8 && stats_.retirement_pending < 1024) {
                next.emplace(pair.first, std::move(retired)); ++stats_.retirement_pending;
            } else ++retirement_retry_exhausted_;
        }
    }
    seen_ = std::move(next);
    stats_.retirement_retry_exhausted = retirement_retry_exhausted_;
    stats_.cooccurrence_pairs_truncated = cooccurrence_pairs_truncated_;
    stats_.duration_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(MonoClock::now() - begin).count());
}
} // namespace agentsec
