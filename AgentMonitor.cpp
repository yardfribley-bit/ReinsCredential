#include "AgentMonitor.h"
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <unistd.h>
#include <future>
#include <algorithm>
#include <deque>
#include <stdexcept>

namespace agentsec {
namespace {
std::string Lower(std::string text) {
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}
std::string BaseName(const std::string& path) {
    auto slash = path.find_last_of('/');
    auto base = slash == std::string::npos ? path : path.substr(slash + 1);
    return base.empty() ? path : base;
}
bool SameImage(const ProcessNode& a, const ProcessNode& b) {
    return a.executable == b.executable && a.arguments == b.arguments;
}
bool StartsWith(const std::string& text, const char* prefix) {
    const auto n = std::char_traits<char>::length(prefix);
    return text.size() >= n && text.compare(0, n, prefix) == 0;
}
std::optional<std::string> BundleComponent(const std::string& path) {
    const auto lower = Lower(path);
    auto pos = lower.rfind(".app/");
    if (pos == std::string::npos && lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".app") == 0)
        pos = lower.size() - 4;
    if (pos == std::string::npos) return std::nullopt;
    auto start = path.rfind('/', pos);
    start = start == std::string::npos ? 0 : start + 1;
    return path.substr(start, pos + 4 - start);
}
bool CollectorPath(const ProcessNode& node) {
    const auto base = BaseName(node.executable);
    if (base == "agent-monitor" || base == "agent-egress" || base == "agent-gateway" || base == "ReinsRuntime" || base == "ReinsDashboard") return true;
    return Lower(node.executable).find("/reinscredential.app/") != std::string::npos;
}
bool IsDirectAgentMatch(const std::string& reason) {
    return !reason.empty() && reason != "generic_runtime_candidate";
}
std::string FriendlyName(const ProcessNode& node, const std::string& reason) {
    const auto base = Lower(BaseName(node.executable));
    if (base == "codex") return "Codex";
    if (base == "cursor" || base == "cursor-agent") return "Cursor";
    if (base == "claude") return "Claude";
    if (base == "workbuddy" || base == "workbuddy-ai" || base == "codebuddy") return "WorkBuddy";
    if (base == "gemini") return "Gemini";
    if (base == "aider") return "Aider";
    if (base == "goose") return "Goose";
    if (base == "opencode") return "OpenCode";
    if (base == "cline") return "Cline";
    if (base == "roo") return "Roo";
    if (base == "windsurf") return "Windsurf";
    if (base == "trae") return "Trae";
    if (base == "kiro") return "Kiro";
    if (base == "grok") return "Grok";
    auto from_bundle = [](const std::string& bundle) {
        auto stem = bundle.substr(0, bundle.size() - 4);
        const auto folded = Lower(stem);
        if (folded == "chatgpt") return std::string("ChatGPT");
        if (folded == "workbuddy ai" || folded == "workbuddy") return std::string("WorkBuddy");
        if (folded == "cursor") return std::string("Cursor");
        if (folded == "claude") return std::string("Claude");
        if (folded == "codex") return std::string("Codex");
        if (folded == "windsurf") return std::string("Windsurf");
        if (folded == "trae") return std::string("Trae");
        if (folded == "kiro") return std::string("Kiro");
        if (folded == "grok" || folded == "grok bot") return std::string("Grok");
        return stem;
    };
    if (auto bundle = BundleComponent(node.executable)) return from_bundle(*bundle);
    if (auto bundle = BundleComponent(reason)) return from_bundle(*bundle);
    if (!node.name.empty()) return node.name;
    return BaseName(node.executable);
}
std::string DisplayPath(const std::string& path) {
    const char* home = std::getenv("HOME");
    if (!home || !*home) return path;
    const std::string prefix(home);
    if (path == prefix) return "~";
    if (path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0 && path[prefix.size()] == '/')
        return "~" + path.substr(prefix.size());
    return path;
}
std::string ToolLabel(const ProcessNode& node) {
    auto name = node.name.empty() ? BaseName(node.executable) : node.name;
    return Lower(name);
}
std::pair<std::string, std::string> SubjectAndVia(const ActorProcess& actor, const AgentRules& rules) {
    std::vector<const ProcessNode*> chain;
    chain.push_back(&actor.process.node);
    for (const auto& ancestor : actor.ancestors) chain.push_back(&ancestor.node);
    int subject = -1;
    for (int i = 0; i < static_cast<int>(chain.size()); ++i) {
        if (IsDirectAgentMatch(MatchAgent(*chain[static_cast<size_t>(i)], rules))) { subject = i; break; }
    }
    if (subject < 0 && actor.owning_agent) {
        for (int i = 0; i < static_cast<int>(chain.size()); ++i) {
            if (chain[static_cast<size_t>(i)]->identity == actor.owning_agent->root) { subject = i; break; }
        }
    }
    std::string name = subject >= 0 ? FriendlyName(*chain[static_cast<size_t>(subject)], MatchAgent(*chain[static_cast<size_t>(subject)], rules))
                                    : (actor.owning_agent ? actor.owning_agent->name : std::string());
    std::string via;
    for (int i = subject - 1; i >= 0; --i) {
        if (!via.empty()) via += " -> ";
        via += ToolLabel(*chain[static_cast<size_t>(i)]);
    }
    return {name, via};
}
} // namespace
bool IsCollectorProcess(const ProcessNode& node) noexcept { return CollectorPath(node); }
bool IsAppleSystemDaemon(const ProcessNode& node) noexcept {
    if (node.identity.pid == 1 || node.ppid == 0) return true;
    const auto path = Lower(node.executable);
    // Indexing and maintenance daemons open user files without acting for the user.
    return path.rfind("/system/", 0) == 0 || path.rfind("/usr/libexec/", 0) == 0 || path.rfind("/usr/sbin/", 0) == 0;
}
std::optional<std::string> OutermostAppBundle(const std::string& executable) {
    const auto lower = Lower(executable);
    auto pos = lower.find(".app/");
    if (pos == std::string::npos && lower.size() >= 4 && lower.compare(lower.size() - 4, 4, ".app") == 0)
        pos = lower.size() - 4;
    if (pos == std::string::npos || pos == 0) return std::nullopt;
    auto start = executable.rfind('/', pos - 1);
    start = start == std::string::npos ? 0 : start + 1;
    if (start >= pos) return std::nullopt;
    return executable.substr(start, pos + 4 - start);
}
std::string DisplayBundleName(const std::string& bundle) {
    if (bundle.size() < 4) return bundle;
    const auto stem = bundle.substr(0, bundle.size() - 4);
    const auto folded = Lower(stem);
    if (folded == "chatgpt") return "ChatGPT";
    if (folded == "workbuddy ai" || folded == "workbuddy" || folded == "codebuddy") return "WorkBuddy";
    if (folded == "cursor") return "Cursor";
    if (folded == "claude") return "Claude";
    if (folded == "codex") return "Codex";
    if (folded == "windsurf") return "Windsurf";
    if (folded == "trae") return "Trae";
    if (folded == "kiro") return "Kiro";
    if (folded == "grok" || folded == "grok bot") return "Grok";
    return stem;
}
void ApplyBehaviorOwner(ActorProcess& actor) {
    if (IsCollectorProcess(actor.process.node)) {
        actor.classification = "collector_self";
        actor.classification_reason = "self_process";
        actor.owning_agent.reset();
        return;
    }
    // Nearest parent first. The app that contains this process wins. A toolchain
    // ancestor such as Xcode's make is a different bundle and does not replace it.
    std::vector<const ProcessNode*> upward{&actor.process.node};
    for (const auto& parent : actor.ancestors) upward.push_back(&parent.node);
    const ProcessNode* nearest_app = nullptr;
    std::string bundle;
    for (const auto* node : upward) {
        if (IsCollectorProcess(*node) || IsAppleSystemDaemon(*node)) continue;
        if (auto found = OutermostAppBundle(node->executable)) {
            nearest_app = node;
            bundle = *found;
            break;
        }
    }
    const ProcessNode* chosen = nullptr;
    bool from_app = false;
    if (nearest_app) {
        from_app = true;
        chosen = nearest_app;
        for (const auto* node : upward) {
            if (IsCollectorProcess(*node) || IsAppleSystemDaemon(*node)) continue;
            auto found = OutermostAppBundle(node->executable);
            if (found && *found == bundle) chosen = node;
        }
    } else {
        for (auto it = upward.rbegin(); it != upward.rend(); ++it) {
            if (IsCollectorProcess(**it) || IsAppleSystemDaemon(**it)) continue;
            chosen = *it;
            break;
        }
    }
    if (!chosen) return;
    OwningAgent owner;
    owner.root = chosen->identity;
    owner.bundle = from_app ? bundle : "";
    if (from_app) owner.name = DisplayBundleName(bundle);
    else {
        const auto hint = MatchAgent(*chosen, {});
        owner.name = !hint.empty() && hint != "generic_runtime_candidate" ? FriendlyName(*chosen, hint)
            : (chosen->name.empty() ? BaseName(chosen->executable) : chosen->name);
    }
    owner.match_reason = from_app ? "outermost_app_bundle" : "top_non_system_ancestor";
    const auto hint = MatchAgent(*chosen, {});
    if (!hint.empty() && hint != "generic_runtime_candidate") owner.match_reason += ";label:" + hint;
    actor.owning_agent = owner;
    if (actor.classification == "collector_self") return;
    if (actor.classification.empty() || actor.classification == "unclassified_process")
        actor.classification = hint.empty() || hint == "generic_runtime_candidate" ? "behavior_tracked" : "known_agent_candidate";
    if (actor.classification_reason.empty()) actor.classification_reason = owner.match_reason;
}
std::string MatchAgent(const ProcessNode& node, const AgentRules& rules) {
    const auto base = Lower(BaseName(node.executable));
    const auto path = Lower(node.executable);
    for (const auto& name : rules.names) if (base == Lower(name)) return "configured_name:" + name;
    for (const auto& bundle : rules.bundles) {
        const auto component = "/" + Lower(bundle) + "/";
        if (path.find(component) != std::string::npos) return "configured_bundle:" + bundle;
    }
    for (const std::string name : {"claude", "codex", "cursor", "cursor-agent", "workbuddy", "workbuddy-ai", "codebuddy", "aider", "goose", "opencode", "gemini", "cline", "roo", "kiro", "grok"})
        if (base == name) return "known_name:" + name;
    // ChatGPT.app is the desktop host for Codex. A codex executable still matches
    // known_name first; AnnotateActor keeps the bundle as owning_agent.
    // Kiro.app and Grok.app (including the older Grok Bot.app name) are desktop
    // agents. This list is not every future app; --agent-bundle adds one without
    // treating ordinary .app processes as agents.
    for (const std::string bundle : {"/cursor.app/", "/chatgpt.app/", "/workbuddy ai.app/", "/workbuddy.app/", "/codebuddy.app/", "/claude.app/", "/codex.app/", "/windsurf.app/", "/trae.app/", "/kiro.app/", "/grok.app/", "/grok bot.app/"})
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
void AnnotateActor(ActorProcess& actor, const AgentRules& rules) {
    const bool self = IsCollectorProcess(actor.process.node) ||
        std::any_of(actor.ancestors.begin(), actor.ancestors.end(), [](const ProcessEntry& entry) { return IsCollectorProcess(entry.node); });
    if (self) {
        actor.classification = "collector_self";
        actor.classification_reason = "self_process";
        actor.owning_agent.reset();
        return;
    }
    auto reason = MatchAgent(actor.process.node, rules);
    if (!IsDirectAgentMatch(reason) && reason != "generic_runtime_candidate") {
        for (const auto& parent : actor.ancestors) {
            if (IsDirectAgentMatch(MatchAgent(parent.node, rules)) || MatchAgent(parent.node, rules) == "generic_runtime_candidate") {
                reason = "observed_ancestor";
                break;
            }
        }
    }
    std::optional<OwningAgent> bundle_owner, direct_owner;
    auto consider = [&](const ProcessNode& node) {
        if (IsCollectorProcess(node)) return;
        const auto match = MatchAgent(node, rules);
        if (!IsDirectAgentMatch(match)) return;
        OwningAgent owner;
        owner.root = node.identity;
        owner.match_reason = match;
        owner.name = FriendlyName(node, match);
        if (auto bundle = BundleComponent(node.executable)) owner.bundle = *bundle;
        const bool bundle_match = StartsWith(match, "application_bundle:") || StartsWith(match, "configured_bundle:");
        if (bundle_match && !bundle_owner) bundle_owner = owner;
        if (!direct_owner) direct_owner = owner;
    };
    for (auto it = actor.ancestors.rbegin(); it != actor.ancestors.rend(); ++it) consider(it->node);
    consider(actor.process.node);
    actor.owning_agent = bundle_owner ? bundle_owner : direct_owner;
    const bool known = !reason.empty() || actor.owning_agent.has_value();
    actor.classification = known ? "known_agent_candidate" : "unclassified_process";
    actor.classification_reason = reason;
}
std::string SummarizeAccess(const ActorProcess* actor, const std::string& path, const std::string& basis, const AgentRules& rules) {
    const auto shown = DisplayPath(path);
    if (!actor || basis == "access_time_change")
        return "The access time changed for " + shown + ". No process was identified. This is not an agent attribution, and it is not an upload.";
    if (actor->classification == "collector_self")
        return "ReinsCredential opened " + shown + ". This is the monitoring app itself, not an AI agent, and it is not an upload.";
    const auto subject_via = SubjectAndVia(*actor, rules);
    const auto& subject = subject_via.first;
    const auto& via = subject_via.second;
    if (basis == "inferred") {
        std::string sentence = subject.empty() ? "A process" : subject;
        sentence += " may have read " + shown;
        if (!via.empty()) sentence += " via " + via;
        sentence += ". Only the file's access time overlapped this process. The file was not seen open, and this is not an upload.";
        return sentence;
    }
    if (actor->owning_agent || actor->classification == "known_agent_candidate") {
        std::string sentence = subject.empty() ? "An AI agent" : subject;
        sentence += " read " + shown;
        if (!via.empty()) sentence += " via " + via;
        sentence += ". The file was open in that process. This is not an upload finding.";
        return sentence;
    }
    const auto tool = actor->process.node.name.empty() ? BaseName(actor->process.node.executable) : actor->process.node.name;
    return tool + " opened " + shown + ". This program is not labeled as an AI agent, and this is not an upload.";
}
AgentMonitor::AgentMonitor(ProcessCache& cache, EvidenceStore& store, AgentRules rules, std::vector<std::string> roots)
    : AgentMonitor(cache, [&store](EvidenceRecord record) { return store.Submit(std::move(record)); }, std::move(rules), std::move(roots)) {}
AgentMonitor::AgentMonitor(ProcessCache& cache, SubmitEvidence submit, AgentRules rules, std::vector<std::string> roots)
    : cache_(cache), submit_(std::move(submit)), rules_(std::move(rules)), roots_(std::move(roots)) {
    if (!submit_) throw std::invalid_argument("missing evidence sink");
}
bool AgentMonitor::Emit(const std::string& type, const Seen& seen, const std::string& target,
    const std::string& detail, RiskLevel risk, const std::string& attribution,
    const std::string& destination, const std::string& evidence_basis, const std::string& summary) {
    EvidenceRecord record;
    record.type = type; record.actor_process = seen.actor; record.target_resource = target;
    record.detail = detail; record.risk_level = risk; record.attribution = attribution;
    record.destination = destination; record.evidence_basis = evidence_basis; record.summary = summary;
    return submit_(std::move(record)) == SubmitResult::Accepted;
}
std::optional<ActorProcess> AgentMonitor::Describe(const ProcessNode& node) const {
    auto view = cache_.View();
    if (auto resolved = view->Resolve(node.identity)) {
        AnnotateActor(*resolved, rules_);
        return resolved;
    }
    ActorProcess actor;
    actor.process.node = node;
    actor.process.state = ProcessState::Observed;
    actor.process.first_seen_us = actor.process.last_seen_us = UnixMicros();
    actor.chain_status = "missing_parent";
    const auto birth = [](const ProcessIdentity& id) { return std::make_pair(id.start_seconds, id.start_microseconds); };
    if (node.identity.pid == 1 || node.ppid == 0) {
        actor.chain_complete = true; actor.chain_status = "observed_chain_to_root";
    } else if (node.ppid == 1 && cache_.ConfirmParentPid(node, 1)) {
        actor.chain_complete = true; actor.chain_status = "observed_chain_to_launchd";
        actor.process.launchd_parent_validated = true;
    } else if (node.ppid > 1) {
        auto parent_pid = view->current.find(node.ppid);
        if (parent_pid != view->current.end()) {
            if (auto parent = view->Resolve(parent_pid->second)) {
                if (parent->process.node.identity != node.identity && birth(parent->process.node.identity) <= birth(node.identity)) {
                    actor.process.observed_parent = parent->process.node.identity;
                    actor.ancestors.push_back(parent->process);
                    actor.ancestors.insert(actor.ancestors.end(), parent->ancestors.begin(), parent->ancestors.end());
                    actor.chain_complete = parent->chain_complete;
                    actor.chain_status = parent->chain_status;
                }
            }
        }
    }
    AnnotateActor(actor, rules_);
    return actor;
}
AgentMonitor::Claim AgentMonitor::ClaimEmit(const ProcessIdentity& identity, const std::string& detail, const Seen& seen,
    const std::string& type, const std::string& target, RiskLevel risk, const std::string& attribution,
    const std::string& destination, const std::string& evidence_basis, const std::string& summary) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& slot = seen_[identity];
    if (slot.activity.count(detail)) return Claim::Duplicate;
    if (!Emit(type, seen, target, detail, risk, attribution, destination, evidence_basis, summary)) return Claim::Rejected;
    slot.activity.insert(detail);
    if (slot.actor.process.node.identity.pid == 0) slot.actor = seen.actor;
    return Claim::Stored;
}
void AgentMonitor::ArmFocus() {
    const auto view = cache_.View();
    std::vector<ProcessIdentity> roots;
    for (const auto& current : view->current) {
        if (current.first == ::getpid()) continue;
        auto actor = view->Resolve(current.second);
        if (!actor) continue;
        AnnotateActor(*actor, rules_);
        if (actor->owning_agent && actor->classification != "collector_self") roots.push_back(actor->process.node.identity);
        if (roots.size() == 128) break;
    }
    std::lock_guard<std::mutex> lock(mu_);
    focus_ = std::move(roots);
}
std::vector<ProcessIdentity> AgentMonitor::FocusRoots() const {
    std::lock_guard<std::mutex> lock(mu_);
    return focus_;
}
void AgentMonitor::ObserveSensitive(const ProcessNode& node, const std::string& path, const std::string& basis) {
    if (basis != "fd_observed") return;
    auto actor = Describe(node);
    if (!actor || actor->classification == "collector_self") return;
    Seen seen{std::move(*actor), {}, {}, {}, 0};
    seen.reason = seen.actor.classification_reason;
    const auto detail = "sensitive_file_open:" + path;
    const auto summary = SummarizeAccess(&seen.actor, path, "fd_observed", rules_);
    if (ClaimEmit(node.identity, detail, seen, "activity_observed", path, RiskLevel::Medium,
        "identity_validated_descriptor_snapshot", "", "fd_observed", summary) == Claim::Stored)
        ++fast_fd_hits_;
}
void AgentMonitor::NoteObservedDescendant(const ProcessNode& node, uint64_t begin_us, uint64_t end_us, std::set<std::string> fd_paths) {
    auto actor = Describe(node);
    if (!actor || !actor->owning_agent || actor->classification == "collector_self") return;
    std::lock_guard<std::mutex> lock(mu_);
    spans_.push_back(Span{std::move(*actor), begin_us, end_us, std::move(fd_paths)});
    while (spans_.size() > 256) spans_.pop_front();
}
void AgentMonitor::NoteAccessTime(const std::string& path, uint64_t window_begin_us, uint64_t window_end_us) {
    std::vector<Span> hits;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto& span : spans_) {
            if (span.end_us < window_begin_us || span.begin_us > window_end_us) continue;
            if (span.fd_paths.count(path)) continue;
            bool already = false;
            auto prior = seen_.find(span.actor.process.node.identity);
            if (prior != seen_.end() && prior->second.activity.count("sensitive_file_open:" + path)) already = true;
            if (!already) hits.push_back(span);
        }
    }
    if (hits.size() == 1) {
        Seen seen{hits[0].actor, hits[0].actor.classification_reason, {}, {}, 0};
        const auto detail = "sensitive_access_inferred:" + path;
        const auto summary = SummarizeAccess(&seen.actor, path, "inferred", rules_);
        if (ClaimEmit(seen.actor.process.node.identity, detail, seen, "sensitive_access_observed", path, RiskLevel::Low,
            "single_descendant_lifetime_overlaps_access_time", "", "inferred", summary) == Claim::Stored)
            ++inferred_accesses_;
        return;
    }
    EvidenceRecord record;
    record.type = "sensitive_access_observed";
    record.target_resource = path;
    record.detail = "access_time_changed:" + path;
    record.evidence_basis = "access_time_change";
    record.attribution = hits.empty() ? "access_time_without_actor" : "access_time_ambiguous_actors";
    record.risk_level = RiskLevel::Low;
    record.summary = SummarizeAccess(nullptr, path, "access_time_change", rules_);
    if (submit_(std::move(record)) == SubmitResult::Accepted) ++access_time_events_;
}
void AgentMonitor::Scan() {
    const auto begin = MonoClock::now();
    const auto view = cache_.View();
    std::vector<Seen> processes;
    for (const auto& current : view->current) {
        if (current.first == ::getpid()) continue;
        auto actor = view->Resolve(current.second);
        if (!actor) continue;
        AnnotateActor(*actor, rules_);
        processes.push_back({std::move(*actor), {}, {}, {}, 0});
        processes.back().reason = processes.back().actor.classification_reason;
    }
    {
        std::lock_guard<std::mutex> lock(mu_);
        focus_.clear();
        for (const auto& seen : processes) {
            if (seen.actor.owning_agent && seen.actor.classification != "collector_self" && focus_.size() < 128)
                focus_.push_back(seen.actor.process.node.identity);
        }
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
                const bool peers = processes[item].actor.classification == "known_agent_candidate";
                activities[item] = cache_.Inspect(processes[item].actor.process.node, roots_, peers);
            }
        }));
    for (auto& worker : workers) worker.get();
    stats_ = {}; stats_.processes = processes.size();
    std::map<ProcessIdentity, Seen> next;
    {
        std::lock_guard<std::mutex> lock(mu_);
        for (size_t item = 0; item < processes.size(); ++item) {
            auto& seen = processes[item]; const auto& activity = activities[item];
            const auto identity = seen.actor.process.node.identity;
            const auto previous = seen_.find(identity);
            const bool known = seen.actor.classification == "known_agent_candidate";
            const bool self = seen.actor.classification == "collector_self";
            stats_.candidates += known;
            stats_.validation_failed += !activity.identity_validated;
            stats_.descriptors_partial += !activity.descriptors_complete;
            if (previous != seen_.end()) seen.announced_actor = previous->second.announced_actor;
            if (!seen.announced_actor || (known && seen.announced_actor->classification_reason.empty())) {
                const auto detail = self ? "collector_self_not_an_agent" : known ? seen.reason : "unclassified;inventory_only";
                if (Emit(known ? "agent_discovered" : self ? "process_discovered" : "process_discovered", seen, "", detail, RiskLevel::Low, "process_snapshot_heuristic"))
                    seen.announced_actor = seen.actor;
            } else if (!SameImage(seen.announced_actor->process.node, seen.actor.process.node) ||
                seen.announced_actor->classification_reason != seen.reason) {
                if (Emit(known ? "agent_changed" : "process_changed", seen, "", "image_or_classification_changed_with_same_start_identity", RiskLevel::Low, "process_snapshot"))
                    seen.announced_actor = seen.actor;
            }
            if (!activity.identity_validated) { if (known) seen.activity.insert("identity_validation_failed"); }
            else if (!self) {
                if (known && !activity.descriptors_complete) seen.activity.insert("fd_visibility_partial_or_unavailable");
                for (const auto& path : activity.sensitive_files) seen.activity.insert("sensitive_file_open:" + path);
                for (const auto& peer : activity.socket_peers) seen.activity.insert("socket_peer:" + peer);
                if (!activity.sensitive_files.empty() && !activity.socket_peers.empty())
                    seen.activity.insert("risk_signal:file_and_socket_coobserved;upload_unproven");
            }
            const auto observed_activity = std::move(seen.activity);
            seen.activity.clear();
            auto prior_activity = previous == seen_.end() ? std::set<std::string>() : previous->second.activity;
            for (const auto& detail : observed_activity) {
                if (previous != seen_.end() && SameImage(previous->second.actor.process.node, seen.actor.process.node) && prior_activity.count(detail)) {
                    seen.activity.insert(detail); continue;
                }
                if (seen_.count(identity) && seen_.at(identity).activity.count(detail)) { seen.activity.insert(detail); continue; }
                const bool file = StartsWith(detail, "sensitive_file_open:");
                const bool risk = StartsWith(detail, "risk_signal:");
                const auto target = file ? detail.substr(std::string("sensitive_file_open:").size()) : std::string();
                const auto summary = file ? SummarizeAccess(&seen.actor, target, "fd_observed", rules_) : std::string();
                if (Emit("activity_observed", seen, target, detail, file || risk ? RiskLevel::Medium : RiskLevel::Low,
                    activity.identity_validated ? "identity_validated_descriptor_snapshot" : "validation_failed_no_activity_attributed",
                    "", file ? "fd_observed" : "", summary))
                    seen.activity.insert(detail);
            }
            if (activity.identity_validated && !self) {
                const auto pair_count = static_cast<uint64_t>(activity.sensitive_files.size()) * activity.socket_peers.size();
                if (pair_count > 32) cooccurrence_pairs_truncated_ += pair_count - 32;
                size_t pairs = 0;
                for (const auto& path : activity.sensitive_files) {
                  if (pairs == 32) break;
                  for (const auto& peer : activity.socket_peers) {
                    if (pairs == 32) break;
                    ++pairs;
                    const auto key = "cooccurrence:" + path + std::string(1, '\0') + peer;
                    if (previous != seen_.end() && SameImage(previous->second.actor.process.node, seen.actor.process.node) && prior_activity.count(key)) {
                        seen.activity.insert(key); continue;
                    }
                    if (seen_.count(identity) && seen_.at(identity).activity.count(key)) { seen.activity.insert(key); continue; }
                    if (Emit("sensitive_network_cooccurrence", seen, path,
                        "Sensitive file descriptor and socket peer observed in the same sample; upload_unproven",
                        RiskLevel::Medium, "identity_validated_descriptor_snapshot", peer, "same_identity_descriptor_snapshot",
                        "A sensitive file and a network connection were both open. This is not an upload finding."))
                        seen.activity.insert(key);
                  }
                }
            }
            next.emplace(identity, std::move(seen));
        }
        for (const auto& pair : seen_) if (!next.count(pair.first)) {
            auto retired = pair.second;
            if (auto actor = view->Resolve(pair.first)) {
                AnnotateActor(*actor, rules_);
                actor->classification = retired.actor.classification;
                actor->classification_reason = retired.reason.empty() ? actor->classification_reason : retired.reason;
                if (retired.actor.owning_agent && !actor->owning_agent) actor->owning_agent = retired.actor.owning_agent;
                retired.actor = std::move(*actor);
            }
            if (retired.actor.process.state == ProcessState::Observed)
                retired.actor.process.state = ProcessState::NotObserved;
            if (!Emit(retired.actor.classification == "collector_self" || retired.reason.empty() ? "process_no_longer_observed" : "agent_no_longer_observed", retired, "", "exit_or_visibility_loss_or_pid_replacement", RiskLevel::Low, "cache_state_transition")) {
                if (++retired.retirement_attempts < 8 && stats_.retirement_pending < 1024) {
                    next.emplace(pair.first, std::move(retired)); ++stats_.retirement_pending;
                } else ++retirement_retry_exhausted_;
            }
        }
        seen_ = std::move(next);
    }
    stats_.retirement_retry_exhausted = retirement_retry_exhausted_;
    stats_.cooccurrence_pairs_truncated = cooccurrence_pairs_truncated_;
    stats_.fast_fd_hits = fast_fd_hits_.load();
    stats_.access_time_events = access_time_events_.load();
    stats_.inferred_accesses = inferred_accesses_.load();
    stats_.duration_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(MonoClock::now() - begin).count());
}
} // namespace agentsec
