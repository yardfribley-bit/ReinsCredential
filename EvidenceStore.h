#pragma once
#include "Types.h"
#include "SystemResources.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <exception>
#include <future>
#include <mutex>
#include <thread>

namespace agentsec {
enum class SubmitResult { Accepted, Full, Closed, Failed, Oversized };
class EvidenceStore {
public:
    struct Config {
        size_t capacity = 4096;
        bool sync_each_record = true;
        size_t max_record_bytes = 1024 * 1024;
        size_t max_pending_bytes = 16 * 1024 * 1024;
    };
    EvidenceStore(const std::string& path, Config config);
    ~EvidenceStore();
    EvidenceStore(const EvidenceStore&) = delete;
    EvidenceStore& operator=(const EvidenceStore&) = delete;
    SubmitResult Submit(EvidenceRecord record);
    void SubmitCritical(EvidenceRecord record, std::chrono::seconds timeout = std::chrono::seconds(5));
    // Acknowledge this record only after write + fsync. An fsync acknowledgement
    // is not a power-loss, remote-transaction or legal-admissibility guarantee.
    void SubmitDurable(EvidenceRecord record, std::chrono::seconds timeout = std::chrono::seconds(5));
    void Close(); // drain, sync, join, then report any async write error
    void Check() const;
    uint64_t Rejected() const noexcept { return rejected_.load(); }
    size_t PendingBytes() const;
    // Read the already-open log inode; path replacement cannot spoof rotation.
    // Control thread only, before Close. Pending records may increase this later.
    uint64_t FileBytes() const;
private:
    struct Pending {
        std::string fields;
        size_t bytes = 0;
        std::unique_ptr<std::promise<void>> receipt;
    };
    Pending Prepare(EvidenceRecord record) const;
    bool Fits(const Pending& pending) const noexcept;
    void EnqueueAndWait(Pending pending, std::chrono::seconds timeout, bool durable);
    void Run() noexcept;
    void WriteAll(const std::string& line);
    void Join() noexcept;
    UniqueFd fd_;
    Config config_;
    const std::string session_;
    mutable std::mutex mutex_;
    std::condition_variable ready_, space_;
    std::deque<Pending> queue_;
    size_t pending_bytes_ = 0; // includes the record currently held by the writer
    bool closed_ = false;
    std::exception_ptr error_;
    std::atomic<uint64_t> rejected_{0};
    std::thread thread_;
};
} // namespace agentsec
