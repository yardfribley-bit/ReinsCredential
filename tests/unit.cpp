#include "AgentMonitor.h"
#include "SensitiveDefaults.h"
#include "SpscRing.h"
#include "ContentMatcher.h"
#include "EgressVerdict.h"
#include <zlib.h>
#include <algorithm>
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
    bool fail_sample = false, recycle_during_inspect = false, confirm_launchd = false;
    // Empty means every inspected process reports the synthetic file and peer.
    std::optional<std::set<pid_t>> sensitive_pids;
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
    bool ConfirmParentPid(const ProcessNode& node, pid_t ppid) override {
        return confirm_launchd && ppid == 1 && node.ppid == 1;
    }
    ActivitySample Inspect(const ProcessNode& node, const std::vector<std::string>&, bool) override {
        if (recycle_during_inspect) for (auto& current : nodes)
            if (current.identity == node.identity) ++current.identity.start_seconds;
        ActivitySample result;
        if (sensitive_pids && !sensitive_pids->count(node.identity.pid)) return result;
        result.sensitive_files.insert("/synthetic/secret");
        if (!sensitive_pids) result.socket_peers.insert("127.0.0.1:1234/protocol=6");
        return result;
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
    node.executable = "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT";
    assert(MatchAgent(node, rules) == "application_bundle:/chatgpt.app/");
    node.executable = "/Applications/AgentReins.app/Contents/MacOS/AgentReins";
    assert(MatchAgent(node, rules).empty());
    node.arguments.clear();
    node.executable = "/Applications/Kiro.app/Contents/MacOS/Kiro";
    assert(MatchAgent(node, rules) == "known_name:kiro");
    node.executable = "/Applications/Kiro.app/Contents/MacOS/Electron";
    assert(MatchAgent(node, rules) == "application_bundle:/kiro.app/");
    node.executable = "/Applications/Kiro.app/Contents/Frameworks/Kiro Helper.app/Contents/MacOS/Kiro Helper";
    assert(MatchAgent(node, rules) == "application_bundle:/kiro.app/");
    node.executable = "/Applications/Grok.app/Contents/MacOS/Grok";
    assert(MatchAgent(node, rules) == "known_name:grok");
    node.executable = "/Applications/Grok.app/Contents/MacOS/Electron";
    assert(MatchAgent(node, rules) == "application_bundle:/grok.app/");
    node.executable = "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot";
    assert(MatchAgent(node, rules) == "application_bundle:/grok bot.app/");
    node.executable = "/usr/local/bin/kiro";
    assert(MatchAgent(node, rules) == "known_name:kiro");
    node.executable = "/usr/local/bin/grok";
    assert(MatchAgent(node, rules) == "known_name:grok");
    node.executable = "/Applications/Example Agent.app/Contents/MacOS/Example Agent";
    assert(MatchAgent(node, rules).empty());
    rules.bundles = {"Example Agent.app"};
    assert(MatchAgent(node, rules) == "configured_bundle:Example Agent.app");
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
    const std::string compressible(4000, 'A');
    const auto compressed_bound = ContentLowerBound(compressible);
    assert(compressed_bound > 0 && compressed_bound < compressible.size());
    const auto incompressible_bound = ContentLowerBound(secret);
    assert(incompressible_bound > 0 && incompressible_bound <= secret.size());
    EvidenceRecord evidence; evidence.destination = "https://example.invalid/ingest";
    evidence.related_event_ids = {"id\"quoted"}; evidence.content_sha256 = Sha256(secret);
    const auto json = ToJson(evidence, "test", 1);
    assert(json.find("https://example.invalid/ingest") != std::string::npos);
    assert(json.find("id\\\"quoted") != std::string::npos);
    std::cout << "PASS: SHA256/base64 vectors, raw/JSON/base64/gzip content matches, benign/partial negatives, corrupt gzip and expansion limits, structured linkage\n";
}
ProcessNode Named(pid_t pid, uint64_t birth, pid_t parent, const std::string& executable, const std::string& name) {
    auto node = Node(pid, birth, parent); node.executable = executable; node.name = name; return node;
}
void AttributionTests() {
    const auto suffixes = DefaultSensitiveSuffixes();
    assert(std::find(suffixes.begin(), suffixes.end(), ".ssh") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".aws") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".config/gh") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".netrc") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".npmrc") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".git-credentials") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".docker/config.json") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".kube/config") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".config/gcloud") != suffixes.end());
    assert(std::find(suffixes.begin(), suffixes.end(), ".azure") != suffixes.end());

    auto source = std::make_shared<FakeSource>();
    source->nodes = {Named(70, 5, 1, "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", "ChatGPT"),
        Named(71, 6, 70, "/usr/local/bin/codex", "codex"), Named(72, 7, 71, "/bin/zsh", "zsh")};
    ProcessCache cache(source, {}); cache.Refresh();
    auto incomplete = cache.View()->Resolve(source->nodes[0].identity);
    assert(incomplete && !incomplete->chain_complete && incomplete->chain_status == "missing_parent");

    auto launchd = std::make_shared<FakeSource>();
    launchd->confirm_launchd = true;
    launchd->sensitive_pids = std::set<pid_t>{};
    launchd->nodes = {Named(80, 5, 1, "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", "ChatGPT"),
        Named(81, 6, 80, "/usr/local/bin/codex", "codex"), Named(82, 7, 81, "/bin/zsh", "zsh")};
    ProcessCache ready(launchd, {}); ready.Refresh();
    auto app = ready.View()->Resolve(launchd->nodes[0].identity);
    assert(app && app->chain_complete && app->chain_status == "observed_chain_to_launchd" && app->ancestors.empty());
    auto shell = ready.View()->Resolve(launchd->nodes[2].identity);
    assert(shell && shell->chain_complete && shell->chain_status == "observed_chain_to_launchd");
    assert(shell->ancestors.size() == 2 && shell->ancestors[0].node.identity.pid == 81);

    struct Sink { std::vector<EvidenceRecord> records; SubmitResult Submit(EvidenceRecord record) { records.push_back(std::move(record)); return SubmitResult::Accepted; } };
    Sink sink;
    AgentMonitor monitor(ready, [&](EvidenceRecord record) { return sink.Submit(std::move(record)); }, {}, {"/synthetic"});
    monitor.Scan();
    auto python = Named(83, 8, 82, "/usr/bin/python3", "python");
    monitor.ObserveSensitive(python, "/synthetic/secret", "fd_observed");
    monitor.ObserveSensitive(python, "/synthetic/secret", "fd_observed");
    const EvidenceRecord* access = nullptr;
    for (const auto& record : sink.records) if (record.type == "activity_observed" && record.target_resource == "/synthetic/secret") access = &record;
    assert(access && access->evidence_basis == "fd_observed");
    assert(access->actor_process && access->actor_process->chain_complete);
    assert(access->actor_process->chain_status == "observed_chain_to_launchd");
    assert(access->actor_process->owning_agent && access->actor_process->owning_agent->name == "ChatGPT");
    assert(access->actor_process->owning_agent->bundle == "ChatGPT.app");
    assert(access->actor_process->owning_agent->root.pid == 80);
    ProcessNode codex_inside;
    codex_inside.executable = "/Applications/ChatGPT.app/Contents/Resources/codex";
    codex_inside.name = "codex";
    assert(MatchAgent(codex_inside, {}) == "known_name:codex");
    ActorProcess hosted;
    hosted.process.node = codex_inside;
    ProcessEntry host;
    host.node = Named(80, 5, 1, "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", "ChatGPT");
    hosted.ancestors.push_back(host);
    AnnotateActor(hosted, {});
    assert(hosted.owning_agent && hosted.owning_agent->name == "ChatGPT");
    assert(hosted.owning_agent->bundle == "ChatGPT.app");
    assert(hosted.owning_agent->root.pid == 80);
    ActorProcess kiro;
    kiro.process.node = Named(100, 5, 1, "/Applications/Kiro.app/Contents/MacOS/Kiro", "Kiro");
    AnnotateActor(kiro, {});
    assert(kiro.owning_agent && kiro.owning_agent->name == "Kiro" && kiro.owning_agent->bundle == "Kiro.app");
    ActorProcess grok;
    grok.process.node = Named(101, 5, 1, "/Applications/Grok.app/Contents/MacOS/Grok", "Grok");
    AnnotateActor(grok, {});
    assert(grok.owning_agent && grok.owning_agent->name == "Grok" && grok.owning_agent->bundle == "Grok.app");
    ActorProcess grok_bot;
    grok_bot.process.node = Named(102, 5, 1, "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot", "Grok Bot");
    AnnotateActor(grok_bot, {});
    assert(grok_bot.owning_agent && grok_bot.owning_agent->name == "Grok" && grok_bot.owning_agent->bundle == "Grok Bot.app");
    assert(OutermostAppBundle("/Applications/WorkBuddy AI.app/Contents/MacOS/Electron") == std::optional<std::string>("WorkBuddy AI.app"));
    assert(OutermostAppBundle("/Applications/Grok Bot.app/Contents/Frameworks/Grok Bot Helper.app/Contents/MacOS/Grok Bot Helper") == std::optional<std::string>("Grok Bot.app"));
    assert(OutermostAppBundle("/tmp/reins/UnknownAgent.app/Contents/MacOS/x") == std::optional<std::string>("UnknownAgent.app"));
    assert(!OutermostAppBundle("/bin/zsh"));
    ActorProcess unknown_app;
    unknown_app.process.node = Named(110, 5, 1, "/tmp/reins/UnknownAgent.app/Contents/MacOS/x", "x");
    ApplyBehaviorOwner(unknown_app);
    assert(unknown_app.owning_agent && unknown_app.owning_agent->name == "UnknownAgent");
    assert(unknown_app.owning_agent->bundle == "UnknownAgent.app");
    assert(unknown_app.owning_agent->root.pid == 110);
    assert(unknown_app.owning_agent->match_reason == "outermost_app_bundle");
    ActorProcess under_toolchain;
    under_toolchain.process.node = Named(111, 6, 21, "/tmp/reins/UnknownAgent.app/Contents/MacOS/x", "x");
    ProcessEntry toolchain;
    toolchain.node = Named(21, 4, 1, "/Applications/Xcode_26.6.app/Contents/Developer/usr/bin/make", "make");
    under_toolchain.ancestors.push_back(toolchain);
    ApplyBehaviorOwner(under_toolchain);
    assert(under_toolchain.owning_agent && under_toolchain.owning_agent->bundle == "UnknownAgent.app");
    assert(under_toolchain.owning_agent->root.pid == 111);
    ActorProcess helper_chain;
    helper_chain.process.node = Named(15, 15, 14, "/bin/bash", "bash");
    auto ancestor = [](pid_t pid, pid_t ppid, uint64_t birth, const std::string& executable, const std::string& name) {
        ProcessEntry entry;
        entry.node = Named(pid, birth, ppid, executable, name);
        return entry;
    };
    helper_chain.ancestors.push_back(ancestor(14, 13, 14, "/usr/bin/python3", "Python"));
    helper_chain.ancestors.push_back(ancestor(13, 12, 13, "/bin/zsh", "zsh"));
    helper_chain.ancestors.push_back(ancestor(12, 11, 12, "/Applications/Grok Bot.app/Contents/Frameworks/Grok Bot Helper.app/Contents/MacOS/Grok Bot Helper", "Grok Bot Helper"));
    helper_chain.ancestors.push_back(ancestor(11, 1, 11, "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot", "Grok Bot"));
    ApplyBehaviorOwner(helper_chain);
    assert(helper_chain.owning_agent && helper_chain.owning_agent->bundle == "Grok Bot.app");
    assert(helper_chain.owning_agent->name == "Grok");
    assert(helper_chain.owning_agent->root.pid == 11);
    assert(helper_chain.owning_agent->match_reason.find("outermost_app_bundle") == 0);
    ActorProcess hold_upload;
    hold_upload.process.node = Named(30, 30, 31, "/private/tmp/hold-upload", "hold-upload");
    hold_upload.ancestors.push_back(ancestor(31, 32, 31, "/bin/bash", "bash"));
    hold_upload.ancestors.push_back(ancestor(32, 33, 32,
        "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python",
        "Python"));
    hold_upload.ancestors.push_back(ancestor(33, 34, 33, "/bin/zsh", "zsh"));
    hold_upload.ancestors.push_back(ancestor(34, 35, 34,
        "/Applications/Grok Bot.app/Contents/Frameworks/Grok Bot Helper.app/Contents/MacOS/Grok Bot Helper",
        "Grok Bot Helper"));
    hold_upload.ancestors.push_back(ancestor(35, 1, 35, "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot", "Grok Bot"));
    ApplyBehaviorOwner(hold_upload);
    assert(hold_upload.owning_agent && hold_upload.owning_agent->bundle == "Grok Bot.app");
    assert(hold_upload.owning_agent->name == "Grok");
    assert(hold_upload.owning_agent->root.pid == 35);
    assert(hold_upload.owning_agent->bundle != "Xcode.app");
    ActorProcess unknown_from_grok;
    unknown_from_grok.process.node = Named(40, 40, 41, "/tmp/UnknownAgent.app/Contents/MacOS/UnknownAgent", "UnknownAgent");
    unknown_from_grok.ancestors.push_back(ancestor(41, 42, 41, "/bin/zsh", "zsh"));
    unknown_from_grok.ancestors.push_back(ancestor(42, 1, 42, "/Applications/Grok Bot.app/Contents/MacOS/Grok Bot", "Grok Bot"));
    ApplyBehaviorOwner(unknown_from_grok);
    assert(unknown_from_grok.owning_agent && unknown_from_grok.owning_agent->bundle == "UnknownAgent.app");
    assert(unknown_from_grok.owning_agent->name == "UnknownAgent");
    assert(unknown_from_grok.owning_agent->root.pid == 40);
    ActorProcess cursor_app;
    cursor_app.process.node = Named(16, 16, 1, "/Applications/Cursor.app/Contents/MacOS/Cursor", "Cursor");
    ApplyBehaviorOwner(cursor_app);
    assert(cursor_app.owning_agent && cursor_app.owning_agent->bundle == "Cursor.app" && cursor_app.owning_agent->name == "Cursor");
    ActorProcess workbuddy;
    workbuddy.process.node = Named(19, 19, 1, "/Applications/WorkBuddy AI.app/Contents/MacOS/Electron", "Electron");
    ApplyBehaviorOwner(workbuddy);
    assert(workbuddy.owning_agent && workbuddy.owning_agent->bundle == "WorkBuddy AI.app" && workbuddy.owning_agent->name == "WorkBuddy");
    ActorProcess indexed;
    indexed.process.node = Named(18, 18, 17, "/bin/bash", "bash");
    indexed.ancestors.push_back(ancestor(17, 1, 17, "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds", "mds"));
    ApplyBehaviorOwner(indexed);
    assert(indexed.owning_agent && indexed.owning_agent->root.pid == 18 && indexed.owning_agent->bundle.empty());
    assert(indexed.owning_agent->match_reason == "top_non_system_ancestor");
    assert(access->summary == "Codex read /synthetic/secret via zsh -> python. The file was open in that process. This is not an upload finding.");
    assert(access->summary.find("upload finding") != std::string::npos && access->transfer_outcome.empty() && access->content_sha256.empty());
    assert(std::count_if(sink.records.begin(), sink.records.end(), [](const EvidenceRecord& record) {
        return record.type == "activity_observed" && record.target_resource == "/synthetic/secret";
    }) == 1);
    auto json = ToJson(*access, "synthetic-session", 1);
    assert(json.find("\"owning_agent\":{") != std::string::npos);
    assert(json.find("\"summary\":\"Codex read /synthetic/secret via zsh -> python.") != std::string::npos);
    assert(json.find("schema_version\":2") != std::string::npos);

    monitor.NoteObservedDescendant(python, 1'000, 2'000, {});
    monitor.NoteAccessTime("/synthetic/maybe", 1'000, 2'000);
    const EvidenceRecord* inferred = nullptr;
    for (const auto& record : sink.records) if (record.evidence_basis == "inferred") inferred = &record;
    assert(inferred && inferred->actor_process && inferred->actor_process->owning_agent);
    assert(inferred->summary.find("Codex may have read /synthetic/maybe via zsh -> python") == 0);
    assert(inferred->summary.find("not an upload") != std::string::npos);
    assert(inferred->risk_level == RiskLevel::Low);
    auto other = Named(84, 9, 82, "/bin/cat", "cat");
    monitor.NoteObservedDescendant(other, 1'000, 2'000, {});
    monitor.NoteAccessTime("/synthetic/other", 1'000, 2'000);
    const EvidenceRecord* ambiguous = nullptr;
    for (const auto& record : sink.records) if (record.target_resource == "/synthetic/other") ambiguous = &record;
    assert(ambiguous && !ambiguous->actor_process && ambiguous->evidence_basis == "access_time_change");
    assert(ambiguous->summary.find("No process was identified") != std::string::npos);
    assert(ambiguous->summary.find("not an upload") != std::string::npos);

    auto self_source = std::make_shared<FakeSource>();
    self_source->confirm_launchd = true;
    self_source->sensitive_pids = std::set<pid_t>{90};
    self_source->nodes = {Named(90, 4, 1, "/Applications/ReinsCredential.app/Contents/Helpers/agent-monitor", "agent-monitor"),
        Named(91, 5, 90, "/bin/cat", "cat")};
    ProcessCache self_cache(self_source, {}); self_cache.Refresh();
    Sink self_sink;
    AgentMonitor self_monitor(self_cache, [&](EvidenceRecord record) { return self_sink.Submit(std::move(record)); }, {}, {"/synthetic"});
    self_monitor.Scan();
    assert(self_monitor.Stats().candidates == 0);
    assert(!self_monitor.FocusRoots().size());
    for (const auto& record : self_sink.records) {
        assert(record.type != "activity_observed");
        assert(record.type != "agent_discovered");
        if (record.actor_process) {
            assert(record.actor_process->classification == "collector_self");
            assert(!record.actor_process->owning_agent);
        }
    }
    ActorProcess collector; collector.classification = "collector_self";
    collector.process.node = self_source->nodes[0];
    auto self_summary = SummarizeAccess(&collector, "/synthetic/secret", "fd_observed", {});
    assert(self_summary.find("monitoring app itself") != std::string::npos && self_summary.find("not an upload") != std::string::npos);

    auto security = std::make_shared<FakeSource>();
    security->confirm_launchd = true;
    security->sensitive_pids = std::set<pid_t>{92};
    security->nodes = {Named(92, 4, 1, "/Applications/AgentReins.app/Contents/MacOS/AgentReins", "AgentReins")};
    ProcessCache security_cache(security, {}); security_cache.Refresh();
    Sink security_sink;
    AgentMonitor security_monitor(security_cache, [&](EvidenceRecord record) { return security_sink.Submit(std::move(record)); }, {}, {"/synthetic"});
    security_monitor.Scan();
    const EvidenceRecord* security_access = nullptr;
    for (const auto& record : security_sink.records) if (record.type == "activity_observed") security_access = &record;
    assert(security_access && security_access->actor_process);
    assert(security_access->actor_process->classification == "unclassified_process");
    assert(!security_access->actor_process->owning_agent);
    assert(security_access->summary.find("AgentReins opened /synthetic/secret") == 0);
    assert(security_access->summary.find("not labeled as an AI agent") != std::string::npos);
    assert(security_access->summary.find("not an upload") != std::string::npos);
    assert(security_monitor.Stats().candidates == 0);
    std::cout << "PASS: launchd boundary, owning agent, plain-language sensitive access, self exclusion, security tool stays unclassified\n";
}
EgressObservation Http(bool match, bool ok, const std::string& destination) {
    EgressObservation item;
    item.kind = EgressObservation::Kind::HttpInspected;
    item.content_match = match;
    item.transfer_succeeded = ok;
    item.destination = destination;
    item.transfer_outcome = ok ? "upstream_http_2xx" : "connect_failed";
    return item;
}
void VerdictTests() {
    const auto uploaded = CloseAccess(true, {Http(true, true, "http://127.0.0.1:9/upload")});
    assert(uploaded.verdict == UploadVerdict::Uploaded);
    assert(uploaded.destination == "http://127.0.0.1:9/upload");
    assert(uploaded.transfer_outcome == "upstream_http_2xx");
    assert(std::string(UploadVerdictLabel(uploaded.verdict)) == "已上传");
    const auto attempted = CloseAccess(true, {Http(true, false, "http://127.0.0.1:9/upload")});
    assert(attempted.verdict == UploadVerdict::Attempted);
    assert(std::string(UploadVerdictLabel(attempted.verdict)) == "已尝试未成功");
    const auto benign = CloseAccess(true, {Http(false, true, "http://127.0.0.1:9/upload")});
    assert(benign.verdict == UploadVerdict::NotFound);
    assert(benign.transfer_outcome == "watched_http_no_registered_content");
    assert(std::string(UploadVerdictLabel(benign.verdict)) == "未发现");
    const auto idle = CloseAccess(true, {});
    assert(idle.verdict == UploadVerdict::NotFound && idle.transfer_outcome == "watched_http_egress_idle");
    EgressObservation tunnel;
    tunnel.kind = EgressObservation::Kind::OpaqueTunnel;
    tunnel.destination = "127.0.0.1:9";
    tunnel.transfer_outcome = "opaque_tunnel_body_not_visible";
    const auto hidden = CloseAccess(true, {Http(false, true, "http://127.0.0.1:9/upload"), tunnel});
    assert(hidden.verdict == UploadVerdict::NotVisible);
    assert(hidden.destination == "127.0.0.1:9");
    assert(hidden.transfer_outcome == "opaque_tunnel_body_not_visible");
    assert(std::string(UploadVerdictLabel(hidden.verdict)) == "看不到");
    const auto unwatched = CloseAccess(false, {});
    assert(unwatched.verdict == UploadVerdict::NotVisible && unwatched.transfer_outcome == "egress_not_watched");
    const auto success_beats_tunnel = CloseAccess(true, {tunnel, Http(true, true, "http://127.0.0.1:9/ok")});
    assert(success_beats_tunnel.verdict == UploadVerdict::Uploaded);
    assert(success_beats_tunnel.destination == "http://127.0.0.1:9/ok");
    const auto summary = UploadVerdictSummary(hidden, "python3", "/tmp/synthetic.env");
    assert(summary.rfind("看不到", 0) == 0);
    assert(summary.find("127.0.0.1:9") != std::string::npos);
    assert(summary.find("opaque_tunnel_body_not_visible") != std::string::npos);
    EvidenceRecord record;
    record.upload_verdict = "not_visible";
    const auto json = ToJson(record, "verdict", 1);
    assert(json.find("\"upload_verdict\":\"not_visible\"") != std::string::npos);
    EvidenceRecord blank;
    assert(ToJson(blank, "verdict", 2).find("\"upload_verdict\":\"\"") != std::string::npos);
    const ProcessIdentity canary_actor{7, 1, 0};
    const ProcessIdentity later_actor{8, 2, 0};
    assert(ProxyBodyCoversLiveActor(canary_actor, true, canary_actor, true));
    assert(!ProxyBodyCoversLiveActor(canary_actor, true, later_actor, false));
    assert(ProxyBodyCoversLiveActor(canary_actor, true, later_actor, true));
    assert(ProxyBodyCoversLiveActor(later_actor, false, later_actor, false));
    assert(!ProxyBodyCoversLiveActor(later_actor, false, canary_actor, false));
    std::cout << "PASS: upload verdicts stay uploaded, attempted, not-found, or not-visible\n";
}
} // namespace
int main() {
    CacheTests(); RingTests(); StoreTests(); ClassificationTests(); UnknownProcessTests(); ContentTests(); AttributionTests(); VerdictTests();
}
