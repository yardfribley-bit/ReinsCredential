#include "AgentMonitor.h"
#include "FileMonitor.h"
#include <climits>
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
void Health(agentsec::ProcessCache& cache, agentsec::FileMonitor& files, agentsec::AgentMonitor& agents, agentsec::EvidenceStore& store, bool final) {
    const auto snapshot = cache.View(); const auto stats = files.Stats();
    agentsec::EvidenceRecord record;
    record.type = final ? "shutdown_summary" : "coverage";
    record.count = stats.queue_dropped + stats.oversized_paths + stats.source_gaps + store.Rejected();
    record.risk_level = record.count ? agentsec::RiskLevel::High : agentsec::RiskLevel::Low;
    record.detail = "Best-effort coverage; absence of an observation does not prove absence of activity";
    record.metrics = {{"generation", snapshot->generation}, {"visible", snapshot->current.size()},
        {"unavailable", snapshot->unavailable}, {"history_evicted", snapshot->history_evicted},
        {"enumeration_complete", snapshot->enumeration_complete ? 1 : 0}, {"raw_queue_dropped", stats.queue_dropped},
        {"oversized_paths", stats.oversized_paths}, {"source_gaps", stats.source_gaps}, {"evidence_rejected", store.Rejected()}};
    const auto scanned = agents.Stats();
    record.metrics.insert({{"activity_processes", scanned.processes}, {"known_candidates", scanned.candidates},
        {"activity_validation_failed", scanned.validation_failed}, {"fd_scans_partial", scanned.descriptors_partial}, {"activity_scan_duration_ms", scanned.duration_ms}});
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
        std::optional<pid_t> query;
        std::vector<std::filesystem::path> paths;
        if (const auto home = std::getenv("HOME")) paths = {std::filesystem::path(home) / ".ssh", std::filesystem::path(home) / ".aws"};
        paths.push_back(std::filesystem::current_path() / ".env");
        for (int i = 1; i < argc; ++i) {
            const std::string option = argv[i];
            if (option == "--help") {
                std::cout << "Usage: agent-monitor [--log PATH] [--duration SECONDS] [--interval-ms N] [--match BASENAME]\n"
                    "                     [--sensitive PATH] [--agent-bundle NAME.app] [--include-runtimes] [--workers 1..8] [--pid PID]\n";
                return 0;
            }
            if (option == "--include-runtimes") { rules.include_runtimes = true; continue; }
            if (i + 1 == argc) throw std::invalid_argument("missing value: " + option);
            const std::string value = argv[++i];
            if (option == "--log") log = value;
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
        std::signal(SIGINT, SignalHandler); std::signal(SIGTERM, SignalHandler);
        live_cache.Start();
        files.Start();
        Health(live_cache, files, agents, store, false);
        const auto begin = MonoClock::now(); auto next_health = begin + std::chrono::seconds(5); auto next_scan = begin;
        while (!stopping) {
            if (duration && MonoClock::now() - begin >= std::chrono::seconds(duration)) break;
            live_cache.Check(); files.Check(); store.Check();
            if (MonoClock::now() >= next_scan) { agents.Scan(); next_scan = MonoClock::now() + cache_config.interval; }
            if (MonoClock::now() >= next_health) { Health(live_cache, files, agents, store, false); next_health = MonoClock::now() + std::chrono::seconds(5); }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        files.Stop(); live_cache.Stop();
        files.Check(); live_cache.Check();
        Health(live_cache, files, agents, store, true);
        store.Close(); // errors during drain or final sync affect the exit status
        const auto stats = files.Stats();
        return stats.queue_dropped || stats.oversized_paths || stats.source_gaps || store.Rejected() ? 2 : 0;
    } catch (const std::exception& error) {
        EvidenceRecord record; record.event_id = NewUuid(); record.timestamp = UnixMicros();
        record.type = "fatal_error"; record.risk_level = RiskLevel::High; record.detail = error.what();
        std::cerr << ToJson(record, "startup_or_runtime_failure", 0) << '\n'; return 1;
    }
}
