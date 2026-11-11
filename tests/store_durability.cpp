#include "EvidenceStore.h"
#include <dlfcn.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <set>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <vector>

// Test-executable-only interposition. Production builds use the native fsync
// directly; this wrapper both counts actual file syncs and supplies an EIO fault.
namespace {
std::atomic<uint64_t> file_sync_calls{0};
std::atomic<bool> fail_file_sync{false};
std::mutex sync_gate_mutex;
std::condition_variable sync_gate_condition;
bool hold_file_sync = false, file_sync_blocked = false;
}
extern "C" int fsync(int fd) {
    using FsyncFunction = int (*)(int);
    static const auto native_fsync = reinterpret_cast<FsyncFunction>(::dlsym(RTLD_NEXT, "fsync"));
    if (!native_fsync) { errno = ENOSYS; return -1; }
    struct stat status{};
    if (!::fstat(fd, &status) && S_ISREG(status.st_mode)) {
        file_sync_calls.fetch_add(1);
        {
            std::unique_lock<std::mutex> lock(sync_gate_mutex);
            if (hold_file_sync) {
                file_sync_blocked = true; sync_gate_condition.notify_all();
                sync_gate_condition.wait(lock, [] { return !hold_file_sync; });
            }
        }
        if (fail_file_sync.load()) { errno = EIO; return -1; }
    }
    return native_fsync(fd);
}

namespace {
using namespace agentsec;
void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
struct TemporaryDirectory {
    TemporaryDirectory() {
        auto pattern = (std::filesystem::temp_directory_path() / "agentsec-durable-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) throw std::system_error(errno, std::generic_category(), "mkdtemp");
        path = pattern;
    }
    ~TemporaryDirectory() { std::error_code error; std::filesystem::remove_all(path, error); }
    std::filesystem::path path;
};
std::string ReadIndependent(const std::filesystem::path& path) {
    auto fd = OwnFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    Require(fd->value >= 0, "independent log open failed");
    std::string result;
    char buffer[4096];
    for (;;) {
        const auto count = ::read(fd->value, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::system_error(errno, std::generic_category(), "independent log read");
        if (!count) return result;
        result.append(buffer, static_cast<size_t>(count));
    }
}
std::vector<std::string> CompleteLines(const std::string& text) {
    Require(text.empty() || text.back() == '\n', "log has incomplete final line");
    std::vector<std::string> lines;
    size_t begin = 0;
    while (begin < text.size()) {
        const auto end = text.find('\n', begin);
        Require(end != std::string::npos && end > begin, "invalid JSONL boundary");
        auto line = text.substr(begin, end - begin);
        Require(line.front() == '{' && line.back() == '}', "incomplete JSON object");
        lines.push_back(std::move(line)); begin = end + 1;
    }
    return lines;
}
EvidenceRecord Record(const std::string& type) {
    EvidenceRecord record;
    record.event_id = NewUuid(); record.type = type; record.target_resource = "/synthetic/secret.env";
    return record;
}
struct PauseFileSync {
    PauseFileSync() {
        std::lock_guard<std::mutex> lock(sync_gate_mutex);
        hold_file_sync = true; file_sync_blocked = false;
    }
    ~PauseFileSync() { Resume(); }
    void WaitForWriter() {
        std::unique_lock<std::mutex> lock(sync_gate_mutex);
        Require(sync_gate_condition.wait_for(lock, std::chrono::seconds(5), [] { return file_sync_blocked; }),
            "writer did not reach test-only fsync gate");
    }
    void Resume() {
        { std::lock_guard<std::mutex> lock(sync_gate_mutex); hold_file_sync = false; }
        sync_gate_condition.notify_all();
    }
};
void DurableVisibilityAndConcurrency() {
    TemporaryDirectory directory;
    const auto path = directory.path / "evidence.jsonl";
    EvidenceStore::Config config;
    config.capacity = 8; config.sync_each_record = false;
    config.max_record_bytes = 4096; config.max_pending_bytes = 16384;
    EvidenceStore store(path.string(), config);
    auto first = Record("durable_first"); const auto first_id = first.event_id;
    const auto syncs_before = file_sync_calls.load();
    store.SubmitDurable(std::move(first));
    Require(file_sync_calls.load() > syncs_before, "durable record was not synced with normal per-record sync disabled");
    auto lines = CompleteLines(ReadIndependent(path));
    Require(lines.size() == 1 && lines.front().find(first_id) != std::string::npos,
        "durable return preceded complete independently readable record");
    Require(store.PendingBytes() == 0, "completed durable record still consumes pending bytes");

    constexpr size_t producer_count = 4, per_producer = 16;
    std::mutex failures_mutex;
    std::exception_ptr failure;
    std::vector<std::thread> producers;
    for (size_t producer = 0; producer < producer_count; ++producer) producers.emplace_back([&, producer] {
        try {
            for (size_t number = 0; number < per_producer; ++number) {
                auto record = Record("durable_concurrent");
                record.detail = std::to_string(producer) + ":" + std::to_string(number);
                store.SubmitDurable(std::move(record));
                Require(store.PendingBytes() <= config.max_pending_bytes, "pending bytes exceeded configured budget");
            }
        } catch (...) {
            std::lock_guard<std::mutex> lock(failures_mutex);
            if (!failure) failure = std::current_exception();
        }
    });
    for (auto& producer : producers) producer.join();
    if (failure) std::rethrow_exception(failure);
    Require(file_sync_calls.load() - syncs_before >= 1 + producer_count * per_producer,
        "some durable submissions completed without a file sync");
    Require(store.PendingBytes() == 0, "drained concurrent durable submissions consume pending bytes");
    lines = CompleteLines(ReadIndependent(path));
    Require(lines.size() == 1 + producer_count * per_producer, "concurrent durable records missing or duplicated");
    std::set<std::string> ids;
    const std::string marker = "\"event_id\":\"";
    for (const auto& line : lines) {
        const auto begin = line.find(marker);
        Require(begin != std::string::npos, "record lacks event ID");
        Require(ids.insert(line.substr(begin + marker.size(), 36)).second, "duplicate durable event ID");
    }
    store.Close(); store.Close();
    Require(store.Submit(Record("after_close")) == SubmitResult::Closed, "closed store accepted evidence");
    std::cout << "PASS: durable sync with default sync disabled, independent FD visibility, 64 concurrent durable records, pending byte budget, sequential repeated Close\n";
}
void EncodedLimitsAndRecovery() {
    TemporaryDirectory directory;
    const auto path = directory.path / "limits.jsonl";
    EvidenceStore::Config config;
    config.sync_each_record = false; config.max_record_bytes = 4096; config.max_pending_bytes = 8192;
    EvidenceStore store(path.string(), config);
    auto oversized = Record("oversized"); oversized.detail.assign(8192, 'x');
    Require(store.Submit(std::move(oversized)) == SubmitResult::Oversized, "oversized record was not explicitly rejected");
    Require(store.Rejected() == 1 && store.PendingBytes() == 0, "oversized rejection changed pending bytes or was not counted");
    store.SubmitDurable(Record("small_after_rejection"));

    auto arguments = Record("arguments_not_retained_in_queue");
    arguments.actor_process.emplace();
    arguments.actor_process->process.node.identity = {123, 100, 1};
    arguments.actor_process->process.node.arguments.emplace_back(8 * 1024 * 1024, 's');
    ProcessEntry ancestor; ancestor.node.identity = {122, 99, 1};
    ancestor.node.arguments.emplace_back(8 * 1024 * 1024, 'p');
    arguments.actor_process->ancestors.push_back(std::move(ancestor));
    Require(ToJson(arguments, "session", 1).size() < config.max_record_bytes,
        "test record must have large omitted arguments but small encoded output");
    store.SubmitDurable(std::move(arguments));
    Require(store.PendingBytes() == 0, "omitted arguments incorrectly consume pending bytes");
    store.Close();
    const auto text = ReadIndependent(path);
    Require(CompleteLines(text).size() == 2, "limit recovery did not preserve exactly the accepted records");
    Require(text.find("oversized") == std::string::npos && text.find(std::string(128, 's')) == std::string::npos &&
        text.find(std::string(128, 'p')) == std::string::npos, "rejected record or omitted arguments leaked into log");
    std::cout << "PASS: explicit oversized rejection, rejection accounting, small-record recovery, 16 MiB of omitted arguments accepted under encoded byte limit\n";
}
void PendingBytesIncludeInFlight() {
    TemporaryDirectory directory;
    const auto path = directory.path / "byte_budget.jsonl";
    EvidenceStore::Config config;
    config.capacity = 64; config.max_record_bytes = 2048; config.max_pending_bytes = 2048;
    EvidenceStore store(path.string(), config);
    // Declared after store so unwinding always releases the writer before Join.
    PauseFileSync pause;
    Require(store.Submit(Record("byte_budget")) == SubmitResult::Accepted, "first byte-budget record rejected");
    pause.WaitForWriter();
    const auto in_flight = store.PendingBytes();
    Require(in_flight > 0 && in_flight <= config.max_pending_bytes, "in-flight buffer missing from byte budget");
    size_t accepted = 1;
    bool full = false;
    for (size_t attempt = 0; attempt < config.capacity; ++attempt) {
        const auto result = store.Submit(Record("byte_budget"));
        Require(store.PendingBytes() <= config.max_pending_bytes, "byte budget exceeded while writer paused");
        if (result == SubmitResult::Full) { full = true; break; }
        Require(result == SubmitResult::Accepted, "unexpected byte-budget submission result");
        ++accepted;
    }
    Require(full && accepted < config.capacity, "total byte limit failed to reject before count limit");
    Require(store.Rejected() == 1, "byte-limit Full rejection was not counted");
    pause.Resume();
    store.SubmitDurable(Record("after_byte_budget_recovers"));
    Require(store.PendingBytes() == 0, "writer did not release all reserved byte budget");
    store.Close();
    Require(CompleteLines(ReadIndependent(path)).size() == accepted + 1, "byte-budget recovery lost accepted records");
    std::cout << "PASS: paused real fsync keeps in-flight bytes reserved, total byte limit rejects before count limit, capacity recovers after drain\n";
}
void SyncFailureStopsSideEffect() {
    TemporaryDirectory directory;
    EvidenceStore::Config config; config.sync_each_record = false;
    EvidenceStore store((directory.path / "sync_failure.jsonl").string(), config);
    const auto syncs_before = file_sync_calls.load();
    bool side_effect = false, expected_failure = false;
    fail_file_sync = true;
    try {
        store.SubmitDurable(Record("sync_failure"));
        side_effect = true;
    } catch (const std::system_error& error) {
        expected_failure = error.code().value() == EIO;
    } catch (...) { fail_file_sync = false; throw; }
    fail_file_sync = false;
    Require(expected_failure && !side_effect, "fsync EIO did not prevent dependent side effect");
    Require(file_sync_calls.load() > syncs_before, "fsync failure injector did not execute");
    Require(store.Submit(Record("after_failure")) == SubmitResult::Failed, "failed store accepted another record");
    bool close_failed = false;
    try { store.Close(); } catch (const std::system_error& error) { close_failed = error.code().value() == EIO; }
    Require(close_failed, "Close did not propagate async sync failure");
    std::cout << "PASS: injected regular-file fsync EIO propagates through durable submission and Close, dependent side effect prevented\n";
}
void ShortWriteFailureStopsSideEffect() {
    TemporaryDirectory directory;
    const auto path = directory.path / "write_failure.jsonl";
    const auto marker = directory.path / "side_effect_performed";
    // Fork after all earlier test stores and their writer threads have stopped.
    const auto child = ::fork();
    if (child < 0) throw std::system_error(errno, std::generic_category(), "fork");
    if (child == 0) {
        std::signal(SIGXFSZ, SIG_IGN);
        struct rlimit limit{128, 128};
        if (::setrlimit(RLIMIT_FSIZE, &limit)) ::_exit(3);
        int status = 1;
        try {
            EvidenceStore::Config config; config.sync_each_record = false;
            EvidenceStore store(path.string(), config);
            auto record = Record("durable_write_failure"); record.detail.assign(4096, 'x');
            store.SubmitDurable(std::move(record));
            auto effect = OwnFd(::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
            if (effect->value < 0) ::_exit(4);
        } catch (const std::system_error& error) {
            if (error.code().value() == EFBIG) status = 0;
        } catch (...) { status = 2; }
        ::_exit(status);
    }
    int status = 0; pid_t waited;
    do { waited = ::waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    Require(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "durable submit did not propagate deterministic short-write EFBIG");
    Require(!std::filesystem::exists(marker), "dependent side effect occurred after failed durable submission");
    Require(std::filesystem::file_size(path) == 128, "short-write injection did not leave the expected partial prefix");
    std::cout << "PASS: real RLIMIT_FSIZE short write and EFBIG propagate before dependent side effect; incomplete prefix preserved\n";
}
}
int main() {
    try {
        DurableVisibilityAndConcurrency(); EncodedLimitsAndRecovery(); PendingBytesIncludeInFlight();
        SyncFailureStopsSideEffect(); ShortWriteFailureStopsSideEffect();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
