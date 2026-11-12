#include "AgentMonitor.h"
#include "FileMonitor.h"
#include "SensitiveDefaults.h"
#include "SubtreeWatcher.h"
#include <climits>
#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {
volatile std::sig_atomic_t stopping = 0;
void SignalHandler(int) { stopping = 1; }
int Positive(const std::string& text) {
    size_t consumed = 0; const auto value = std::stol(text, &consumed);
    if (consumed != text.size() || value <= 0 || value > 86400000) throw std::invalid_argument("invalid positive integer: " + text);
    return static_cast<int>(value);
}
uint64_t PositiveBytes(const std::string& text) {
    if (text.empty() || !std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; }))
        throw std::invalid_argument("invalid byte limit: " + text);
    size_t consumed = 0;
    const auto value = std::stoull(text, &consumed);
    if (!value || consumed != text.size()) throw std::invalid_argument("invalid byte limit: " + text);
    return value;
}
void Health(agentsec::ProcessCache& cache, agentsec::FileMonitor& files, agentsec::AgentMonitor& agents, agentsec::EvidenceStore& store,
    const agentsec::SubtreeWatcher::Stats& watcher, bool final, uint64_t log_limit, bool rotation_required) {
    const auto snapshot = cache.View(); const auto stats = files.Stats();
    const auto scanned = agents.Stats();
    agentsec::EvidenceRecord record;
    record.type = final ? "shutdown_summary" : "coverage";
    record.count = stats.queue_dropped + stats.oversized_paths + stats.source_gaps + store.Rejected() +
        scanned.retirement_retry_exhausted + scanned.cooccurrence_pairs_truncated + (final ? scanned.retirement_pending : 0);
    record.risk_level = record.count ? agentsec::RiskLevel::High : agentsec::RiskLevel::Low;
    record.detail = "Best-effort coverage; absence of an observation does not prove absence of activity";
    record.metrics = {{"generation", snapshot->generation}, {"visible", snapshot->current.size()},
        {"unavailable", snapshot->unavailable}, {"history_evicted", snapshot->history_evicted},
        {"enumeration_complete", snapshot->enumeration_complete ? 1 : 0}, {"raw_queue_dropped", stats.queue_dropped},
        {"oversized_paths", stats.oversized_paths}, {"source_gaps", stats.source_gaps}, {"evidence_rejected", store.Rejected()}};
    record.metrics.insert({{"activity_processes", scanned.processes}, {"known_candidates", scanned.candidates},
        {"activity_validation_failed", scanned.validation_failed}, {"fd_scans_partial", scanned.descriptors_partial}, {"activity_scan_duration_ms", scanned.duration_ms},
        {"retirement_pending", scanned.retirement_pending}, {"retirement_retry_exhausted", scanned.retirement_retry_exhausted},
        {"cooccurrence_pairs_truncated", scanned.cooccurrence_pairs_truncated},
        {"broad_roots_skipped", stats.broad_roots_skipped},
        {"fast_fd_hits", scanned.fast_fd_hits}, {"access_time_events", scanned.access_time_events},
        {"inferred_accesses", scanned.inferred_accesses},
        {"subtree_focused", watcher.focused}, {"subtree_bursts", watcher.bursts},
        {"subtree_fd_hits", watcher.fd_hits}, {"subtree_fork_notes", watcher.fork_notes},
        {"subtree_exec_notes", watcher.exec_notes}, {"subtree_dropped_bursts", watcher.dropped_bursts},
        {"subtree_atime_events", watcher.atime_events}, {"subtree_sweep_us", watcher.sweep_us},
        {"log_bytes", store.FileBytes()},
        {"log_limit_bytes", log_limit}, {"log_rotation_required", rotation_required ? 1 : 0},
        {"shutdown_flush_not_filesystem_barrier", final ? 1 : 0}});
    store.SubmitCritical(std::move(record));
}
} // namespace
int main(int argc, char** argv) {
    using namespace agentsec;
    try {
        std::string log = "evidence.jsonl";
        ProcessCache::Config cache_config;
        AgentRules rules;
        int duration = 0; size_t workers = 2;
        uint64_t max_log_bytes = 0;
        std::optional<pid_t> query;
        std::vector<std::filesystem::path> paths;
        if (const auto home = std::getenv("HOME")) {
            for (const auto& suffix : DefaultSensitiveSuffixes()) paths.push_back(std::filesystem::path(home) / suffix);
        }
        paths.push_back(std::filesystem::current_path() / ".env");
        for (int i = 1; i < argc; ++i) {
            const std::string option = argv[i];
            if (option == "--help") {
                std::cout << "Usage: agent-monitor [--log PATH] [--duration SECONDS] [--interval-ms N] [--match BASENAME]\n"
                    "                     [--sensitive PATH] [--agent-bundle NAME.app] [--include-runtimes] [--workers 1..8] [--pid PID]\n"
                    "                     [--no-default-sensitive] [--max-log-bytes N] (rotation: exit 3; not a hard size ceiling)\n";
                return 0;
            }
            if (option == "--include-runtimes") { rules.include_runtimes = true; continue; }
            if (option == "--no-default-sensitive") { paths.clear(); continue; }
            if (i + 1 == argc) throw std::invalid_argument("missing value: " + option);
            const std::string value = argv[++i];
            if (option == "--log") log = value;
            else if (option == "--max-log-bytes") max_log_bytes = PositiveBytes(value);
            else if (option == "--duration") duration = Positive(value);
            else if (option == "--interval-ms") cache_config.interval = std::chrono::milliseconds(Positive(value));
            else if (option == "--workers") workers = static_cast<size_t>(Positive(value));
            else if (option == "--match") rules.names.push_back(value);
            else if (option == "--agent-bundle") {
                if (std::filesystem::path(value).filename() != value || value.size() < 5 || value.substr(value.size() - 4) != ".app")
                    throw std::invalid_argument("agent bundle must be a basename ending in .app");
                rules.bundles.push_back(value);
            }
            else if (option == "--sensitive") paths.emplace_back(value);
            else if (option == "--pid") query = static_cast<pid_t>(Positive(value));
            else throw std::invalid_argument("unknown option: " + option);
        }
        if (workers < 1 || workers > 8) throw std::invalid_argument("workers must be 1..8");
        std::vector<std::string> sensitive;
        for (const auto& path : paths) sensitive.push_back(std::filesystem::weakly_canonical(std::filesystem::absolute(path)).string());
        auto source = MakeDarwinProcessSource();
        if (query) {
            ProcessCache cache(source, cache_config);
            cache.Refresh(); const auto view = cache.View(); auto found = view->current.find(*query);
            if (found == view->current.end()) throw std::runtime_error("requested process is not visible");
            EvidenceRecord record; record.event_id = NewUuid(); record.timestamp = UnixMicros(); record.type = "process_query";
            record.actor_process = view->Resolve(found->second); record.attribution = "process_snapshot";
            std::cout << ToJson(record, NewUuid(), 1) << '\n'; return 0;
        }
        // Declaration order is intentional: file workers stop before the cache;
        // the store outlives every producer, including exception cleanup paths.
        EvidenceStore store(log, {});
        ProcessCache live_cache(source, cache_config);
        AgentMonitor agents(live_cache, store, rules, sensitive);
        FileMonitor files(sensitive, store, workers);
        SubtreeWatcher watcher(source, sensitive, agents);
        std::signal(SIGINT, SignalHandler); std::signal(SIGTERM, SignalHandler);
        sigset_t unblock;
        sigemptyset(&unblock);
        sigaddset(&unblock, SIGTERM);
        sigaddset(&unblock, SIGINT);
        sigprocmask(SIG_UNBLOCK, &unblock, nullptr);
        live_cache.Start();
        agents.ArmFocus();
        watcher.Start();
        watcher.Focus(agents.FocusRoots());
        files.Start();
        Health(live_cache, files, agents, store, watcher.GetStats(), false, max_log_bytes, false);
        bool rotation_required = false;
        const auto begin = MonoClock::now(); auto next_health = begin + std::chrono::seconds(5); auto next_scan = begin;
        auto next_size_check = begin;
        while (!stopping) {
            if (duration && MonoClock::now() - begin >= std::chrono::seconds(duration)) break;
            live_cache.Check(); files.Check(); store.Check();
            if (max_log_bytes && MonoClock::now() >= next_size_check) {
                if (store.FileBytes() >= max_log_bytes) { rotation_required = true; break; }
                next_size_check = MonoClock::now() + std::chrono::milliseconds(250);
            }
            if (MonoClock::now() >= next_scan) {
                agents.Scan(); watcher.Focus(agents.FocusRoots());
                next_scan = MonoClock::now() + cache_config.interval;
            }
            if (MonoClock::now() >= next_health) { Health(live_cache, files, agents, store, watcher.GetStats(), false, max_log_bytes, false); next_health = MonoClock::now() + std::chrono::seconds(5); }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        watcher.Stop(); files.Stop(); live_cache.Stop();
        files.Check(); live_cache.Check();
        // The threshold is advisory: accepted records are always drained, so
        // shutdown and one in-progress scan can take the file beyond the limit.
        if (max_log_bytes && store.FileBytes() >= max_log_bytes) rotation_required = true;
        Health(live_cache, files, agents, store, watcher.GetStats(), true, max_log_bytes, rotation_required);
        store.Close(); // errors during drain or final sync affect the exit status
        const auto stats = files.Stats();
        if (rotation_required) return 3;
        const auto activity = agents.Stats();
        return stats.queue_dropped || stats.oversized_paths || stats.source_gaps || store.Rejected() ||
            activity.retirement_retry_exhausted || activity.retirement_pending || activity.cooccurrence_pairs_truncated ? 2 : 0;
    } catch (const std::exception& error) {
        EvidenceRecord record; record.event_id = NewUuid(); record.timestamp = UnixMicros();
        record.type = "fatal_error"; record.risk_level = RiskLevel::High; record.detail = error.what();
        std::cerr << ToJson(record, "startup_or_runtime_failure", 0) << '\n'; return 1;
    }
}
