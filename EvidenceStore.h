#pragma once
#include "Types.h"
#include "SystemResources.h"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <exception>
#include <mutex>
#include <thread>

namespace agentsec {
enum class SubmitResult { Accepted, Full, Closed, Failed };
class EvidenceStore {
public:
    struct Config {
        size_t capacity = 4096;
        bool sync_each_record = true;
    };
    EvidenceStore(const std::string& path, Config config);
    ~EvidenceStore();
    EvidenceStore(const EvidenceStore&) = delete;
    EvidenceStore& operator=(const EvidenceStore&) = delete;
    SubmitResult Submit(EvidenceRecord record);
    void SubmitCritical(EvidenceRecord record, std::chrono::seconds timeout = std::chrono::seconds(5));
    void Close(); // drain, sync, join, then report any async write error
    void Check() const;
    uint64_t Rejected() const noexcept { return rejected_.load(); }
private:
    void Run() noexcept;
    void WriteAll(const std::string& line);
    void Join() noexcept;
    UniqueFd fd_;
    Config config_;
    const std::string session_;
    mutable std::mutex mutex_;
    std::condition_variable ready_, space_;
    std::deque<EvidenceRecord> queue_;
    bool closed_ = false;
    std::exception_ptr error_;
    std::atomic<uint64_t> rejected_{0};
    std::thread thread_;
};
} // namespace agentsec
