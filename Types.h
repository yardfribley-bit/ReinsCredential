#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include <sys/types.h>

namespace agentsec {
using MonoClock = std::chrono::steady_clock;
inline uint64_t UnixMicros() noexcept {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
struct ProcessIdentity {
    pid_t pid = 0;
    uint64_t start_seconds = 0, start_microseconds = 0;
    auto Tuple() const { return std::tie(pid, start_seconds, start_microseconds); }
    bool operator==(const ProcessIdentity& other) const { return Tuple() == other.Tuple(); }
    bool operator!=(const ProcessIdentity& other) const { return !(*this == other); }
    bool operator<(const ProcessIdentity& other) const { return Tuple() < other.Tuple(); }
};
enum class ProcessState { Observed, NotObserved, Replaced };
struct ProcessNode {
    ProcessIdentity identity;
    pid_t ppid = 0;
    std::string executable, name;
    std::vector<std::string> arguments;
    bool arguments_available = false;
};
struct ProcessEntry {
    ProcessNode node;
    ProcessState state = ProcessState::Observed;
    // A historical, identity-bound parent link. Never replace it with a bare PID lookup.
    std::optional<ProcessIdentity> observed_parent;
    uint64_t first_seen_us = 0, last_seen_us = 0;
    MonoClock::time_point last_seen_mono;
};
struct ActorProcess {
    ProcessEntry process;
    std::vector<ProcessEntry> ancestors; // nearest parent first
    bool chain_complete = false;
    std::string chain_status;
    std::string classification = "unclassified_process", classification_reason;
};
enum class RiskLevel { Low, Medium, High };
struct EvidenceRecord {
    std::string event_id; // generated in the backend, never in an OS callback
    uint64_t timestamp = 0; // observation time, Unix epoch microseconds
    std::string type;
    std::optional<ActorProcess> actor_process;
    std::string target_resource;
    RiskLevel risk_level = RiskLevel::Low;
    std::string attribution = "unavailable", detail;
    uint64_t source_event_id = 0, source_flags = 0, count = 0;
    std::map<std::string, uint64_t> metrics;
    // Optional content-sensor evidence; never populated from socket/FD coincidence.
    std::string destination, content_sha256, correlation_id, evidence_basis, transfer_outcome;
    std::vector<std::string> related_event_ids;
};
std::string NewUuid();
std::string ToJson(const EvidenceRecord& record, const std::string& session, uint64_t sequence);
bool IsWithin(const std::string& path, const std::string& root) noexcept;
} // namespace agentsec
