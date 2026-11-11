#include "EvidenceStore.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <uuid/uuid.h>
#include <cerrno>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace agentsec {
namespace {
[[noreturn]] void SystemError(const std::string& operation) {
    throw std::system_error(errno, std::generic_category(), operation);
}
// Preserve valid UTF-8. Invalid filename bytes are replaced in display strings;
// target_resource_bytes_hex below preserves the exact target bytes separately.
std::string Quote(const std::string& text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    for (size_t i = 0; i < text.size();) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; ++i; }
        else if (c == '"' || c == '\\') { out += '\\'; out += text[i++]; }
        else if (c < 128) out += text[i++];
        else {
            size_t n = c >= 0xc2 && c <= 0xdf ? 2 : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
            bool valid = n && i + n <= text.size();
            for (size_t j = 1; valid && j < n; ++j) valid = (static_cast<unsigned char>(text[i + j]) & 0xc0) == 0x80;
            if (valid && n >= 3) {
                auto second = static_cast<unsigned char>(text[i + 1]);
                valid = !(c == 0xe0 && second < 0xa0) && !(c == 0xed && second >= 0xa0) &&
                    !(c == 0xf0 && second < 0x90) && !(c == 0xf4 && second >= 0x90);
            }
            if (valid) { out.append(text, i, n); i += n; }
            else { out += "\\ufffd"; ++i; }
        }
    }
    return out + '"';
}
std::string Hex(const std::string& text) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out; out.reserve(text.size() * 2);
    for (unsigned char c : text) { out += hex[c >> 4]; out += hex[c & 15]; }
    return out;
}
std::string Key(const ProcessIdentity& id) {
    return "{\"pid\":" + std::to_string(id.pid) + ",\"start_seconds\":" + std::to_string(id.start_seconds) +
        ",\"start_microseconds\":" + std::to_string(id.start_microseconds) + "}";
}
std::string Entry(const ProcessEntry& entry) {
    const auto state = entry.state == ProcessState::Observed ? "Observed" : entry.state == ProcessState::Replaced ? "Replaced" : "NotObserved";
    return "{\"identity\":" + Key(entry.node.identity) + ",\"ppid\":" + std::to_string(entry.node.ppid) +
        ",\"executable\":" + Quote(entry.node.executable) + ",\"name\":" + Quote(entry.node.name) +
        ",\"state\":" + Quote(state) + ",\"observed_parent_identity\":" + (entry.observed_parent ? Key(*entry.observed_parent) : "null") +
        ",\"first_seen_us\":" + std::to_string(entry.first_seen_us) + ",\"last_seen_us\":" + std::to_string(entry.last_seen_us) + "}";
}
} // namespace
std::string NewUuid() {
    uuid_t uuid; uuid_generate_random(uuid); char result[37]{}; uuid_unparse_lower(uuid, result); return result;
}
namespace {
std::string EncodeFields(const EvidenceRecord& record) {
    std::string actor = "null";
    if (record.actor_process) {
        const auto& a = *record.actor_process;
        actor = "{\"process\":" + Entry(a.process) + ",\"ppid_tree\":[";
        bool comma = false;
        for (const auto& parent : a.ancestors) { if (comma) actor += ','; actor += Entry(parent); comma = true; }
        std::string owning = "null";
        if (a.owning_agent) {
            const auto& owner = *a.owning_agent;
            owning = "{\"name\":" + Quote(owner.name) + ",\"bundle\":" + Quote(owner.bundle) + ",\"root_identity\":" + Key(owner.root) +
                ",\"match_reason\":" + Quote(owner.match_reason) + "}";
        }
        actor += "],\"chain_complete\":" + std::string(a.chain_complete ? "true" : "false") + ",\"chain_status\":" + Quote(a.chain_status) +
            ",\"classification\":" + Quote(a.classification) + ",\"classification_reason\":" + Quote(a.classification_reason) +
            ",\"owning_agent\":" + owning + "}";
    }
    const auto risk = record.risk_level == RiskLevel::High ? "High" : record.risk_level == RiskLevel::Medium ? "Medium" : "Low";
    std::string metrics = "{"; bool comma = false;
    for (const auto& pair : record.metrics) { if (comma) metrics += ','; metrics += Quote(pair.first) + ':' + std::to_string(pair.second); comma = true; }
    metrics += '}';
    std::string related = "[";
    for (const auto& id : record.related_event_ids) { if (related.size() > 1) related += ','; related += Quote(id); }
    related += ']';
    return ",\"event_id\":" + Quote(record.event_id) + ",\"timestamp\":" + std::to_string(record.timestamp) +
        ",\"timestamp_unit\":\"unix_microseconds\",\"type\":" + Quote(record.type) + ",\"actor_process\":" + actor +
        ",\"target_resource\":" + Quote(record.target_resource) + ",\"target_resource_bytes_hex\":" + Quote(Hex(record.target_resource)) +
        ",\"risk_level\":" + Quote(risk) + ",\"attribution\":" + Quote(record.attribution) + ",\"detail\":" + Quote(record.detail) +
        ",\"source_event_id\":" + std::to_string(record.source_event_id) + ",\"source_flags\":" + std::to_string(record.source_flags) +
        ",\"count\":" + std::to_string(record.count) + ",\"metrics\":" + metrics +
        ",\"destination\":" + Quote(record.destination) + ",\"content_sha256\":" + Quote(record.content_sha256) +
        ",\"correlation_id\":" + Quote(record.correlation_id) + ",\"evidence_basis\":" + Quote(record.evidence_basis) +
        ",\"transfer_outcome\":" + Quote(record.transfer_outcome) + ",\"summary\":" + Quote(record.summary) +
        ",\"related_event_ids\":" + related + "}";
}
std::string Envelope(const std::string& session, uint64_t sequence) {
    return "{\"schema_version\":2,\"session_id\":" + Quote(session) + ",\"sequence\":" + std::to_string(sequence);
}
} // namespace
std::string ToJson(const EvidenceRecord& record, const std::string& session, uint64_t sequence) {
    return Envelope(session, sequence) + EncodeFields(record);
}
EvidenceStore::EvidenceStore(const std::string& path, Config config) : config_(config), session_(NewUuid()) {
    if (!config_.capacity || !config_.max_record_bytes || config_.max_pending_bytes < config_.max_record_bytes)
        throw std::invalid_argument("invalid evidence queue record/byte limits");
    // O_NONBLOCK avoids hanging on a malicious FIFO before fstat can reject it.
    int fd = ::open(path.c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) SystemError("open evidence file");
    fd_ = OwnFd(fd);
    struct stat status{};
    if (::fstat(fd, &status)) SystemError("fstat evidence file");
    if (!S_ISREG(status.st_mode) || status.st_uid != ::geteuid() || status.st_nlink != 1 || (status.st_mode & 0777) != 0600)
        throw std::runtime_error("evidence file must be an owned, single-link regular file with mode 0600");
    if (::flock(fd, LOCK_EX | LOCK_NB)) SystemError("evidence file is already locked");
    if (::fstat(fd, &status)) SystemError("fstat locked evidence file");
    if (status.st_size > 0) {
        char last = 0; ssize_t got;
        do { got = ::pread(fd, &last, 1, status.st_size - 1); } while (got < 0 && errno == EINTR);
        if (got != 1 || last != '\n') throw std::runtime_error("evidence file has incomplete tail; preserve and rotate it explicitly");
    }
    // Make the newly created directory entry durable before accepting evidence.
    auto directory = std::filesystem::absolute(path).parent_path();
    const int parent_fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0) SystemError("open evidence directory");
    auto parent = OwnFd(parent_fd);
    if (::fsync(parent->value)) SystemError("fsync evidence directory");
    thread_ = std::thread([this] { Run(); });
}
EvidenceStore::~EvidenceStore() { Join(); }
EvidenceStore::Pending EvidenceStore::Prepare(EvidenceRecord record) const {
    if (record.event_id.empty()) record.event_id = NewUuid();
    if (!record.timestamp) record.timestamp = UnixMicros();
    Pending pending;
    pending.fields = EncodeFields(record);
    // Reserve the largest sequence header + newline; producer-side record and
    // unused argv data are released before waiting on the bounded queue.
    pending.bytes = pending.fields.size() + Envelope(session_, UINT64_MAX).size() + 1;
    return pending;
}
bool EvidenceStore::Fits(const Pending& pending) const noexcept {
    return queue_.size() < config_.capacity && pending.bytes <= config_.max_pending_bytes - pending_bytes_;
}
size_t EvidenceStore::PendingBytes() const {
    std::lock_guard<std::mutex> lock(mutex_); return pending_bytes_;
}
uint64_t EvidenceStore::FileBytes() const {
    if (!fd_) throw std::logic_error("evidence store closed");
    struct stat status{};
    if (::fstat(fd_->value, &status)) SystemError("fstat evidence size");
    if (status.st_size < 0) throw std::runtime_error("negative evidence file size");
    return static_cast<uint64_t>(status.st_size);
}
SubmitResult EvidenceStore::Submit(EvidenceRecord record) {
    auto pending = Prepare(std::move(record));
    std::lock_guard<std::mutex> lock(mutex_);
    if (error_) return SubmitResult::Failed;
    if (closed_) return SubmitResult::Closed;
    if (pending.bytes > config_.max_record_bytes) { ++rejected_; return SubmitResult::Oversized; }
    if (!Fits(pending)) { ++rejected_; return SubmitResult::Full; }
    const auto bytes = pending.bytes;
    queue_.push_back(std::move(pending)); pending_bytes_ += bytes; ready_.notify_one();
    return SubmitResult::Accepted;
}
void EvidenceStore::EnqueueAndWait(Pending pending, std::chrono::seconds timeout, bool durable) {
    const auto deadline = MonoClock::now() + timeout;
    std::future<void> receipt;
    if (durable) { pending.receipt = std::make_unique<std::promise<void>>(); receipt = pending.receipt->get_future(); }
    std::unique_lock<std::mutex> lock(mutex_);
    if (pending.bytes > config_.max_record_bytes) { ++rejected_; throw std::length_error("evidence record exceeds byte limit"); }
    if (!space_.wait_until(lock, deadline, [this, &pending] { return closed_ || error_ || Fits(pending); })) {
        ++rejected_; throw std::runtime_error("critical evidence submission timed out");
    }
    if (error_) std::rethrow_exception(error_);
    if (closed_) throw std::runtime_error("evidence store closed");
    const auto bytes = pending.bytes;
    queue_.push_back(std::move(pending)); pending_bytes_ += bytes; ready_.notify_one(); lock.unlock();
    if (durable) {
        if (receipt.wait_until(deadline) != std::future_status::ready)
            throw std::runtime_error("evidence sync acknowledgement timed out; record may later persist");
        receipt.get();
    }
}
void EvidenceStore::SubmitCritical(EvidenceRecord record, std::chrono::seconds timeout) {
    EnqueueAndWait(Prepare(std::move(record)), timeout, false);
}
void EvidenceStore::SubmitDurable(EvidenceRecord record, std::chrono::seconds timeout) {
    EnqueueAndWait(Prepare(std::move(record)), timeout, true);
}
void EvidenceStore::Check() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (error_) std::rethrow_exception(error_);
}
void EvidenceStore::Join() noexcept {
    { std::lock_guard<std::mutex> lock(mutex_); closed_ = true; }
    ready_.notify_all(); space_.notify_all();
    if (thread_.joinable()) thread_.join();
}
void EvidenceStore::Close() {
    Join(); Check();
    if (fd_) {
        const auto fd = fd_->value; fd_->value = -1; // no retry of a possibly consumed descriptor
        if (::close(fd)) SystemError("close evidence file");
        fd_.reset();
    }
}
void EvidenceStore::WriteAll(const std::string& line) {
    size_t done = 0;
    while (done < line.size()) {
        const auto count = ::write(fd_->value, line.data() + done, line.size() - done);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) SystemError("append evidence");
        if (count == 0) throw std::runtime_error("zero-length evidence write");
        done += static_cast<size_t>(count);
    }
}
void EvidenceStore::Run() noexcept {
    Pending current;
    try {
        uint64_t sequence = 0;
        for (;;) {
            std::unique_lock<std::mutex> lock(mutex_);
            ready_.wait(lock, [this] { return closed_ || !queue_.empty(); });
            if (queue_.empty()) break;
            current = std::move(queue_.front()); queue_.pop_front(); space_.notify_all(); lock.unlock();
            WriteAll(Envelope(session_, ++sequence) + current.fields + '\n');
            if ((config_.sync_each_record || current.receipt) && ::fsync(fd_->value)) SystemError("fsync evidence record");
            // Release the buffer before releasing its byte budget or acknowledging.
            auto receipt = std::move(current.receipt);
            const auto bytes = current.bytes;
            current = {};
            { std::lock_guard<std::mutex> update(mutex_); pending_bytes_ -= bytes; }
            space_.notify_all();
            if (receipt) receipt->set_value();
        }
        if (::fsync(fd_->value)) SystemError("final fsync evidence");
    } catch (...) {
        const auto error = std::current_exception();
        std::lock_guard<std::mutex> lock(mutex_); error_ = error; closed_ = true;
        if (current.receipt) current.receipt->set_exception(error);
        for (auto& pending : queue_) if (pending.receipt) pending.receipt->set_exception(error);
        current = {}; queue_.clear(); pending_bytes_ = 0;
        ready_.notify_all(); space_.notify_all();
    }
}
} // namespace agentsec
