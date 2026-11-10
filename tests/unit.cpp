#include "AgentMonitor.h"
#include "SpscRing.h"
#include "ContentMatcher.h"
#include <zlib.h>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <csignal>

using namespace agentsec;
namespace {
ProcessNode Node(pid_t pid, uint64_t birth, pid_t parent = 0) {
    ProcessNode node; node.identity = {pid, birth, 0}; node.ppid = parent;
    node.executable = "/test/process-" + std::to_string(pid); return node;
}
class FakeSource final : public IProcessSource {
public:
    std::vector<ProcessNode> nodes;
    bool fail_sample = false, recycle_during_inspect = false;
    ProcessSample Sample() override {
        if (fail_sample) throw std::runtime_error("injected snapshot failure");
        return {nodes, 0, true};
    }
    bool Validate(const ProcessNode& expected) override {
        for (const auto& node : nodes) if (node.identity.pid == expected.identity.pid)
            return node.identity == expected.identity && node.executable == expected.executable;
        return false;
    }
    bool ValidateParent(const ProcessNode& child, const ProcessNode& parent) override {
        return child.ppid == parent.identity.pid && Validate(child) && Validate(parent);
    }
    ActivitySample Inspect(const ProcessNode& node, const std::vector<std::string>&, bool) override {
        if (recycle_during_inspect) for (auto& current : nodes)
            if (current.identity == node.identity) ++current.identity.start_seconds;
        ActivitySample result; result.sensitive_files.insert("/synthetic/secret"); result.socket_peers.insert("127.0.0.1:1234/protocol=6"); return result;
    }
};
void CacheTests() {
    auto source = std::make_shared<FakeSource>();
    auto root = Node(1, 1), parent = Node(20, 10, 1), child = Node(30, 20, 20);
    source->nodes = {root, parent, child};
    ProcessCache cache(source, {}); cache.Refresh();
    auto initial = cache.View();
    auto chain = initial->Resolve(child.identity);
    assert(chain && chain->chain_complete && chain->ancestors.size() == 2);
    assert(chain->ancestors[0].node.identity == parent.identity);
    auto replacement = Node(20, 40, 1);
    child.ppid = 1; // observed reparenting must not overwrite historical lineage
    source->nodes = {root, replacement, child}; cache.Refresh();
    auto replaced = cache.View();
    assert(replaced->history.at(parent.identity).state == ProcessState::Replaced);
    chain = replaced->Resolve(child.identity);
    assert(chain->ancestors[0].node.identity == parent.identity);
    assert(initial->history.at(parent.identity).state == ProcessState::Observed); // immutable old view
    assert(replaced->current.at(20) == replacement.identity);
    source->nodes = {root, replacement}; cache.Refresh();
    assert(cache.View()->history.at(child.identity).state == ProcessState::NotObserved);
    const auto generation = cache.View()->generation;
    source->fail_sample = true;
    bool failed = false;
    try { cache.Refresh(); } catch (const std::runtime_error&) { failed = true; }
    assert(failed && cache.View()->generation == generation);
    source->fail_sample = false; source->recycle_during_inspect = true;
    auto activity = cache.Inspect(replacement, {"/synthetic"});
    assert(!activity.identity_validated && activity.sensitive_files.empty());

    auto unknown_source = std::make_shared<FakeSource>();
    auto orphan = Node(50, 20, 20);
    unknown_source->nodes = {replacement, orphan};
    ProcessCache unknown(unknown_source, {}); unknown.Refresh();
    auto orphan_chain = unknown.View()->Resolve(orphan.identity);
    assert(orphan_chain && !orphan_chain->chain_complete && orphan_chain->ancestors.empty());

    auto bounded_source = std::make_shared<FakeSource>(); bounded_source->nodes = {root, parent, Node(30, 20, 20)};
    ProcessCache::Config config; config.max_history = 2;
    ProcessCache bounded(bounded_source, config); bounded.Refresh();
    bounded_source->nodes = {root, Node(30, 20, 1)}; bounded.Refresh();
    const auto bounded_view = bounded.View();
    assert(!bounded_view->history.count(parent.identity));
    assert(bounded_view->Resolve({30, 20, 0})->chain_status == "history_expired_or_evicted");
    auto concurrent_source = std::make_shared<FakeSource>(); concurrent_source->nodes = {root, parent};
    ProcessCache concurrent(concurrent_source, {});
    concurrent.Start();
    std::atomic<bool> stop_readers{false}; std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i) readers.emplace_back([&] {
        uint64_t last_generation = 0;
        while (!stop_readers.load()) {
            auto view = concurrent.View();
            assert(view->generation >= last_generation && view->Resolve(parent.identity)->chain_complete);
            last_generation = view->generation;
        }
    });
    for (int i = 0; i < 100; ++i) concurrent.Refresh();
    stop_readers = true;
    for (auto& reader : readers) reader.join();
    concurrent.Stop(); concurrent.Check();
    std::cout << "PASS: PID reuse, immutable snapshots, retained parent identity, visibility loss, failed samples, mid-scan reuse, missing lineage, bounded history\n";
}
void RingTests() {
    SpscRing<uint64_t, 4> small; uint64_t item = 0;
    assert(!small.TryPop(item));
    assert(small.TryPush(1) && small.TryPush(2) && small.TryPush(3));
    assert(!small.TryPush(4));
    assert(small.TryPop(item) && item == 1);
    assert(small.TryPush(4));
    for (uint64_t value = 2; value <= 4; ++value) assert(small.TryPop(item) && item == value);
    SpscRing<uint64_t, 1024> ring;
    constexpr uint64_t total = 200000;
    std::thread producer([&] { for (uint64_t i = 0; i < total; ++i) while (!ring.TryPush(i)) std::this_thread::yield(); });
    for (uint64_t expected = 0; expected < total; ++expected) {
        while (!ring.TryPop(item)) std::this_thread::yield();
        assert(item == expected);
    }
    producer.join(); assert(!ring.TryPop(item));
    std::cout << "PASS: bounded overflow, wraparound, concurrent ordering of 200000 ring events\n";
}
struct TemporaryDirectory {
    TemporaryDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() / "agentsec-unit-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) throw std::runtime_error("mkdtemp failed");
        path = pattern;
    }
    ~TemporaryDirectory() { std::error_code error; std::filesystem::remove_all(path, error); }
    std::filesystem::path path;
};
template<class F> void MustFail(F action) {
    bool failed = false;
    try { action(); } catch (const std::exception&) { failed = true; }
    assert(failed);
}
void StoreTests() {
    TemporaryDirectory directory;
    const auto log = (directory.path / "evidence.jsonl").string();
    EvidenceStore::Config config; config.capacity = 8; config.sync_each_record = false;
    {
        EvidenceStore store(log, config);
        MustFail([&] { EvidenceStore duplicate(log, config); });
        std::vector<std::thread> producers;
        for (int p = 0; p < 4; ++p) producers.emplace_back([&] {
            for (int i = 0; i < 50; ++i) {
                EvidenceRecord record; record.type = "concurrent_test"; record.target_resource = "/synthetic/secret\n\"file";
                store.SubmitCritical(std::move(record));
            }
        });
        for (auto& producer : producers) producer.join();
        store.Close(); assert(store.Submit({}) == SubmitResult::Closed);
    }
    struct stat status{}; assert(!::stat(log.c_str(), &status) && (status.st_mode & 0777) == 0600);
    { EvidenceStore reopened(log, config); EvidenceRecord record; record.type = "reopen"; reopened.SubmitCritical(record); reopened.Close(); }
    std::ifstream input(log); std::string line; size_t lines = 0; std::set<std::string> ids;
    while (std::getline(input, line)) {
        ++lines;
        const std::string marker = "\"event_id\":\"";
        const auto start = line.find(marker); assert(start != std::string::npos);
        const auto uuid = line.substr(start + marker.size(), 36);
        assert(uuid.size() == 36 && uuid[8] == '-' && ids.insert(uuid).second);
        assert(line.front() == '{' && line.back() == '}');
    }
    assert(lines == 201);
    auto symlink = directory.path / "link.jsonl";
    std::filesystem::create_symlink(log, symlink);
    MustFail([&] { EvidenceStore rejected(symlink.string(), config); });
    const auto partial = directory.path / "partial.jsonl";
    { std::ofstream file(partial); file << "{incomplete"; }
    ::chmod(partial.c_str(), 0600);
    MustFail([&] { EvidenceStore rejected(partial.string(), config); });
    assert(std::filesystem::file_size(partial) == 11);
    ::chmod(log.c_str(), 0644);
    MustFail([&] { EvidenceStore rejected(log, config); });
    EvidenceRecord escaped; escaped.event_id = NewUuid(); escaped.type = "test\n\"";
    escaped.target_resource = std::string("/path/\xff", 7);
    auto json = ToJson(escaped, "session", 1);
    assert(json.find("test\\u000a\\\"") != std::string::npos);
    assert(json.find("\\ufffd") != std::string::npos);
    assert(json.find("2f706174682fff") != std::string::npos);
    // Deterministic short-write + EFBIG fault, isolated to a child process.
    const auto limited_log = (directory.path / "limited.jsonl").string();
    const pid_t child = ::fork(); assert(child >= 0);
    if (child == 0) {
        std::signal(SIGXFSZ, SIG_IGN);
        struct rlimit limit{128, 128};
        if (::setrlimit(RLIMIT_FSIZE, &limit)) ::_exit(3);
        int result = 1;
        try {
            EvidenceStore limited(limited_log, config);
            EvidenceRecord record; record.type = "injected_write_failure"; record.detail.assign(4096, 'x');
            limited.SubmitCritical(std::move(record));
            limited.Close();
        } catch (const std::system_error& error) { if (error.code().value() == EFBIG) result = 0; }
        catch (...) { result = 2; }
        ::_exit(result);
    }
    int child_status = 0; assert(::waitpid(child, &child_status, 0) == child);
    assert(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    assert(std::filesystem::file_size(limited_log) == 128);
    MustFail([&] { EvidenceStore rejected(limited_log, config); });
    std::cout << "PASS: concurrent append, drain/reopen, UUID uniqueness, 0600 permissions, writer lock, symlink refusal, partial-tail refusal, JSON escaping, short-write failure propagation\n";
}
void ClassificationTests() {
    ProcessNode node; node.executable = "/usr/local/bin/node";
    node.arguments = {"node", "app.js", "prompt /@anthropic-ai/claude-code/"};
    AgentRules rules;
    assert(MatchAgent(node, rules).empty());
    node.arguments[1] = "/opt/node_modules/@anthropic-ai/claude-code/cli.js";
    assert(MatchAgent(node, rules).rfind("package_entrypoint:", 0) == 0);
    node.arguments = {"node", "app.js"}; rules.include_runtimes = true;
    assert(MatchAgent(node, rules) == "generic_runtime_candidate");
    rules.include_runtimes = false;
    node.executable = "/Applications/WorkBuddy AI.app/Contents/MacOS/Electron";
    assert(MatchAgent(node, rules) == "application_bundle:/workbuddy ai.app/");
    node.executable = "/Applications/WorkBuddy.app/Contents/MacOS/Electron";
    assert(MatchAgent(node, rules) == "application_bundle:/workbuddy.app/");
    node.executable = "/Applications/Unrelated.app/Contents/MacOS/Electron";
    assert(MatchAgent(node, rules).empty());
    node.executable = "/Users/example/.local/share/cursor-agent/versions/version/node";
    assert(MatchAgent(node, rules) == "cursor_agent_distribution");
    node.executable = "/usr/local/bin/node";
    node.arguments = {"node", "/Applications/WorkBuddy AI.app/Contents/Resources/app.asar.unpacked/cli/dist/codebuddy-lite-wb.mjs"};
    assert(MatchAgent(node, rules).rfind("application_cli_entrypoint:", 0) == 0);
    node.executable = "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot";
    assert(MatchAgent(node, rules).empty());
    rules.bundles = {"Grok Bot.app"};
    assert(MatchAgent(node, rules) == "configured_bundle:Grok Bot.app");
    assert(IsWithin("/x/secret", "/x") && !IsWithin("/x-other/secret", "/x") && IsWithin("/x", "/"));
    std::cout << "PASS: classification, prompt false-positive exclusion, runtime opt-in, directory boundary\n";
}
void UnknownProcessTests() {
    TemporaryDirectory directory;
    const auto log = (directory.path / "unknown.jsonl").string();
    auto source = std::make_shared<FakeSource>(); source->nodes = {Node(1, 1), Node(500, 10, 1)};
    source->nodes[1].executable = "/opt/completely-unlisted/runner";
    ProcessCache cache(source, {}); cache.Refresh();
    EvidenceStore::Config config; config.sync_each_record = false;
    EvidenceStore store(log, config);
    AgentMonitor monitor(cache, store, {}, {"/synthetic"}); monitor.Scan();
    assert(monitor.Stats().processes == 2 && monitor.Stats().candidates == 0);
    store.Close();
    std::ifstream input(log); std::string text((std::istreambuf_iterator<char>(input)), {});
    assert(text.find("\"type\":\"process_discovered\"") != std::string::npos);
    assert(text.find("\"type\":\"agent_discovered\"") == std::string::npos);
    assert(text.find("\"classification\":\"unclassified_process\"") != std::string::npos);
    assert(text.find("sensitive_file_open:/synthetic/secret") != std::string::npos);
    assert(text.find("upload_unproven") != std::string::npos);
    std::cout << "PASS: unlisted process inventory and sensitive-file/network activity without any agent-name rule\n";
}
void ContentTests() {
    const std::string secret = "TEST_ONLY_SECRET=0123456789abcdef\n";
    assert(Sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert(Base64("f") == "Zg==" && Base64("fo") == "Zm8=" && Base64("foo") == "Zm9v");
    assert(MatchContent("prefix" + secret, secret) == "exact_bytes");
    assert(MatchContent("TEST_ONLY_SECRET=0123456789abcdef\\n", secret) == "json_escaped_bytes");
    assert(MatchContent(Base64(secret), secret) == "base64_whole_value");
    assert(MatchContent("ordinary public data", secret).empty());
    assert(MatchContent("short", "short").empty());
    assert(MatchContent(secret.substr(0, 16), secret).empty());
    auto gzip = [](const std::string& input) {
        z_stream stream{};
        assert(deflateInit2(&stream, 6, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK);
        std::string result(compressBound(input.size()) + 32, '\0');
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
        stream.avail_in = static_cast<uInt>(input.size());
        stream.next_out = reinterpret_cast<Bytef*>(result.data());
        stream.avail_out = static_cast<uInt>(result.size());
        assert(deflate(&stream, Z_FINISH) == Z_STREAM_END);
        result.resize(stream.total_out); deflateEnd(&stream); return result;
    };
    assert(MatchContent(gzip(secret), secret) == "gzip:exact_bytes");
    auto corrupt = gzip(secret); corrupt.back() ^= 1;
    assert(MatchContent(corrupt, secret).empty());
    assert(MatchContent(gzip(std::string(1024 * 1024 + 1, 'x') + secret), secret).empty());
    assert(MatchContent(gzip(secret) + "trailing", secret).empty());
    EvidenceRecord evidence; evidence.destination = "https://example.invalid/ingest";
    evidence.related_event_ids = {"id\"quoted"}; evidence.content_sha256 = Sha256(secret);
    const auto json = ToJson(evidence, "test", 1);
    assert(json.find("https://example.invalid/ingest") != std::string::npos);
    assert(json.find("id\\\"quoted") != std::string::npos);
    std::cout << "PASS: SHA256/base64 vectors, raw/JSON/base64/gzip content matches, benign/partial negatives, corrupt gzip and expansion limits, structured linkage\n";
}
} // namespace
int main() {
    CacheTests(); RingTests(); StoreTests(); ClassificationTests(); UnknownProcessTests(); ContentTests();
}
