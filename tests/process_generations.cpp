#include "AgentMonitor.h"
#include <cassert>
#include <iostream>

using namespace agentsec;
namespace {
ProcessNode Node(pid_t pid, uint64_t birth, pid_t parent, const std::string& executable) {
    ProcessNode node; node.identity = {pid, birth, 0}; node.ppid = parent; node.executable = executable;
    return node;
}
class Source final : public IProcessSource {
public:
    std::vector<ProcessNode> nodes;
    bool activity = false;
    bool files = true, peers = true, validate = true;
    size_t file_count = 1;
    ProcessSample Sample() override { return {nodes, 0, true}; }
    bool Validate(const ProcessNode& expected) override {
        if (!validate) return false;
        for (const auto& node : nodes) if (node.identity.pid == expected.identity.pid)
            return node.identity == expected.identity && node.executable == expected.executable && node.arguments == expected.arguments;
        return false;
    }
    bool ValidateParent(const ProcessNode& child, const ProcessNode& parent) override {
        return child.ppid == parent.identity.pid && Validate(child) && Validate(parent);
    }
    ActivitySample Inspect(const ProcessNode&, const std::vector<std::string>&, bool) override {
        ActivitySample result;
        if (activity) {
            if (files) for (size_t i = 0; i < file_count; ++i)
                result.sensitive_files.insert(file_count == 1 ? "/synthetic/secret" : "/synthetic/secret" + std::to_string(i));
            if (peers) result.socket_peers.insert("127.0.0.1:1234/protocol=6");
        }
        return result;
    }
};
struct Sink {
    bool reject = false;
    std::string reject_type;
    std::vector<EvidenceRecord> records;
    SubmitResult Submit(EvidenceRecord record) {
        if (reject || record.type == reject_type) return SubmitResult::Full;
        records.push_back(std::move(record)); return SubmitResult::Accepted;
    }
    size_t Count(const std::string& type) const {
        size_t count = 0; for (const auto& record : records) count += record.type == type; return count;
    }
};
void FrozenImageTests() {
    auto source = std::make_shared<Source>();
    // Child PID sorts before parent PID: edge freezing must not depend on map order.
    source->nodes = {Node(1, 1, 0, "/sbin/launchd"), Node(90040, 10, 1, "/ordinary/launcher"), Node(90020, 20, 90040, "/ordinary/worker")};
    ProcessCache cache(source, {}); cache.Refresh();
    const auto original = cache.View(); const auto child = source->nodes[2].identity;
    assert(original->Resolve(child)->chain_complete);
    Sink sink; AgentMonitor monitor(cache, [&](EvidenceRecord r) { return sink.Submit(std::move(r)); }, {}, {});
    monitor.Scan(); assert(monitor.Stats().candidates == 0);
    source->nodes[1].executable = "/Applications/Cursor.app/Contents/MacOS/Cursor";
    cache.Refresh(); monitor.Scan();
    assert(monitor.Stats().candidates == 1);
    assert(cache.View()->Resolve(child)->ancestors.front().node.executable == "/ordinary/launcher");
    assert(original->Resolve(child)->ancestors.front().node.executable == "/ordinary/launcher");
    source->nodes[1].executable = "/ordinary/unrelated-tool";
    cache.Refresh(); monitor.Scan(); assert(monitor.Stats().candidates == 0);
    // An actual observed agent ancestor remains historical after that parent execs.
    source->nodes[1].executable = "/usr/local/bin/codex";
    source->nodes.push_back(Node(90060, 30, 90040, "/ordinary/agent-child"));
    cache.Refresh(); monitor.Scan(); assert(monitor.Stats().candidates == 2);
    source->nodes[1].executable = "/ordinary/unrelated-tool";
    cache.Refresh(); monitor.Scan(); assert(monitor.Stats().candidates == 1);
    assert(cache.View()->Resolve(source->nodes[3].identity)->ancestors.front().node.executable == "/usr/local/bin/codex");
    // Same executable, changed interpreter entry point must also clear direct classification.
    source->nodes[1].executable = "/usr/local/bin/node";
    source->nodes[1].arguments = {"node", "/opt/node_modules/@openai/codex/cli.js"};
    cache.Refresh(); monitor.Scan(); assert(monitor.Stats().candidates == 2);
    source->nodes[1].arguments = {"node", "/ordinary/server.js"};
    cache.Refresh(); monitor.Scan(); assert(monitor.Stats().candidates == 1);
    std::cout << "PASS: parent exec cannot rewrite child image lineage; direct image/entrypoint classification resets; historical agent ancestry survives\n";
}
void LateParentAndEvictionTests() {
    auto source = std::make_shared<Source>();
    source->nodes = {Node(90040, 10, 80000, "/ordinary/launcher"), Node(90020, 20, 90040, "/ordinary/worker")};
    ProcessCache cache(source, {}); cache.Refresh();
    const auto child = source->nodes[1].identity;
    assert(!cache.View()->Resolve(child)->chain_complete);
    source->nodes.push_back(Node(80000, 1, 0, "/usr/local/bin/codex"));
    cache.Refresh();
    const auto child_chain = cache.View()->Resolve(child);
    assert(child_chain->ancestors.size() == 1 && !child_chain->chain_complete);
    Sink sink; AgentMonitor monitor(cache, [&](EvidenceRecord r) { return sink.Submit(std::move(r)); }, {}, {});
    monitor.Scan(); assert(monitor.Stats().candidates == 2); // ancestor plus parent; never retroactive child label
    auto bounded_source = std::make_shared<Source>();
    bounded_source->nodes = {Node(1, 1, 0, "/sbin/launchd"), Node(90040, 10, 1, "/usr/local/bin/codex"), Node(90020, 20, 90040, "/ordinary/worker")};
    ProcessCache::Config config; config.max_history = 2;
    ProcessCache bounded(bounded_source, config); bounded.Refresh();
    bounded_source->nodes.erase(bounded_source->nodes.begin() + 1);
    bounded_source->nodes[1].ppid = 1; bounded.Refresh();
    assert(bounded.View()->Resolve(child)->chain_status == "history_expired_or_evicted");
    // Deliberately invalid fake cycles remain finite and are never called complete.
    auto cycle_source = std::make_shared<Source>();
    cycle_source->nodes = {Node(90020, 10, 90040, "/ordinary/a"), Node(90040, 10, 90020, "/ordinary/b")};
    ProcessCache cycle(cycle_source, {}); cycle.Refresh();
    assert(!cycle.View()->Resolve(cycle_source->nodes[0].identity)->chain_complete);
    auto deep_source = std::make_shared<Source>();
    deep_source->nodes = {Node(1, 1, 0, "/sbin/launchd")};
    ProcessCache deep(deep_source, {}); deep.Refresh();
    for (pid_t i = 0; i < 140; ++i) {
        deep_source->nodes.push_back(Node(91000 + i, 2 + static_cast<uint64_t>(i), i ? 90999 + i : 1, "/ordinary/deep-child"));
        deep.Refresh();
    }
    for (const auto& pair : deep.View()->history) {
        auto pointer = pair.second.parent_at_observation; size_t depth = 0;
        while (pointer) { assert(++depth <= 128); pointer = pointer->parent_at_observation; }
    }
    std::cout << "PASS: late ancestry cannot backfill old child evidence; retention, cycle rejection, and retained graph depth remain bounded\n";
}
void RejectedEvidenceTests() {
    auto source = std::make_shared<Source>();
    source->nodes = {Node(90020, 10, 0, "/usr/local/bin/codex")}; source->activity = true;
    ProcessCache cache(source, {}); cache.Refresh();
    Sink sink; AgentMonitor monitor(cache, [&](EvidenceRecord r) { return sink.Submit(std::move(r)); }, {}, {});
    sink.reject = true; monitor.Scan(); assert(sink.records.empty());
    sink.reject = false; monitor.Scan();
    assert(sink.Count("agent_discovered") == 1 && sink.Count("activity_observed") == 3);
    const auto committed = sink.records.size(); monitor.Scan(); assert(sink.records.size() == committed);
    source->nodes[0].executable = "/ordinary/tool"; cache.Refresh();
    sink.reject_type = "process_changed"; monitor.Scan(); assert(sink.Count("process_changed") == 0);
    sink.reject_type.clear(); monitor.Scan(); assert(sink.Count("process_changed") == 1);
    // A transient queue failure must not permanently suppress a disappearance.
    source->nodes.clear(); cache.Refresh(); sink.reject = true; monitor.Scan();
    assert(monitor.Stats().processes == 0 && monitor.Stats().retirement_pending == 1);
    sink.reject = false; monitor.Scan(); assert(sink.Count("process_no_longer_observed") == 1);
    assert(sink.records.back().actor_process->process.state == ProcessState::NotObserved);
    // A permanently unavailable sink has bounded retirement retry memory.
    source->nodes = {Node(90021, 20, 0, "/ordinary/tool")}; cache.Refresh(); monitor.Scan();
    source->nodes.clear(); cache.Refresh(); sink.reject = true;
    for (int attempt = 0; attempt < 8; ++attempt) monitor.Scan();
    assert(monitor.Stats().retirement_pending == 0 && monitor.Stats().retirement_retry_exhausted == 1);
    monitor.Scan(); assert(monitor.Stats().retirement_pending == 0 && monitor.Stats().retirement_retry_exhausted == 1);
    std::cout << "PASS: rejected discovery/change/activity retry after queue recovery; dedup advances only on acceptance; retirement retries are bounded\n";
}
void IdleRescanTests() {
    auto source = std::make_shared<Source>();
    source->nodes = {Node(90020, 10, 1, "/usr/local/bin/codex")};
    source->activity = false;
    ProcessCache cache(source, {}); cache.Refresh();
    Sink sink; AgentMonitor monitor(cache, [&](EvidenceRecord r) { return sink.Submit(std::move(r)); }, {}, {});
    monitor.Scan();
    assert(monitor.Stats().descriptor_scans == 1);
    assert(monitor.Stats().candidates == 1);
    monitor.Scan();
    assert(monitor.Stats().descriptor_scans == 0);
    assert(monitor.Stats().candidates == 1);
    std::cout << "PASS: an idle known agent is not descriptor-scanned again on the next pass\n";
}
void CooccurrenceTests() {
    auto source = std::make_shared<Source>();
    source->nodes = {Node(90020, 10, 0, "/ordinary/unknown-agent")}; source->activity = true;
    ProcessCache cache(source, {}); cache.Refresh();
    Sink sink; AgentMonitor monitor(cache, [&](EvidenceRecord r) { return sink.Submit(std::move(r)); }, {}, {});
    source->peers = false; monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 0);
    source->peers = true; source->files = false; monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 0);
    source->files = true; source->validate = false; monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 0);
    source->validate = true; sink.reject_type = "sensitive_network_cooccurrence"; monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 0);
    sink.reject_type.clear(); monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 1);
    const auto& pair = sink.records.back();
    assert(pair.type == "sensitive_network_cooccurrence" && pair.target_resource == "/synthetic/secret");
    assert(pair.destination == "127.0.0.1:1234/protocol=6" && pair.evidence_basis == "same_identity_descriptor_snapshot");
    assert(pair.risk_level == RiskLevel::Medium && pair.actor_process->process.node.identity == source->nodes[0].identity);
    assert(pair.actor_process->classification == "unclassified_process" && pair.content_sha256.empty() && pair.transfer_outcome.empty());
    monitor.Scan(); assert(sink.Count("sensitive_network_cooccurrence") == 1);
    source->nodes[0].identity.start_seconds = 11; cache.Refresh(); monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 2);
    source->file_count = 40; monitor.Scan();
    assert(sink.Count("sensitive_network_cooccurrence") == 34);
    assert(monitor.Stats().cooccurrence_pairs_truncated == 8);
    source->activity = false; monitor.Scan();
    assert(monitor.Stats().cooccurrence_pairs_truncated == 8);
    std::cout << "PASS: typed file/peer pair from one validated sample, unknown agents included, file-only/peer-only/invalid identity excluded, Full retries, PID generation dedup and 32-pair cap\n";
}
} // namespace
int main() { FrozenImageTests(); LateParentAndEvictionTests(); RejectedEvidenceTests(); IdleRescanTests(); CooccurrenceTests(); }
