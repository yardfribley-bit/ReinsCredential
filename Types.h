#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <memory>
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
    // Freeze the parent's observed image AND ancestry when this edge is bound.
    // PID/start identifies a lifetime; it does not identify an exec image.
    std::shared_ptr<const ProcessEntry> parent_at_observation;
    // ppid 1 was re-checked, but launchd's executable and start identity were not readable.
    // This is a boundary, not a fabricated launchd process record.
    bool launchd_parent_validated = false;
    uint64_t first_seen_us = 0, last_seen_us = 0;
    MonoClock::time_point last_seen_mono;
};
// Candidate identity of the desktop agent that owns this process tree.
// A name or bundle match is not authentication.
struct OwningAgent {
    std::string name;
    std::string bundle;
    ProcessIdentity root;
    std::string match_reason;
};
struct ActorProcess {
    ProcessEntry process;
    std::vector<ProcessEntry> ancestors; // nearest parent first
    bool chain_complete = false;
    std::string chain_status;
    std::string classification = "unclassified_process", classification_reason;
    std::optional<OwningAgent> owning_agent;
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
    // Destination may be an observed peer, or a content gateway target. The
    // evidence_basis/type distinguishes them; content hashes and transfer outcomes
    // must never be fabricated from descriptor co-occurrence.
    std::string destination, content_sha256, correlation_id, evidence_basis, transfer_outcome;
    // Empty unless an egress observation closed this record. Values: uploaded,
    // attempted, not_found, not_visible. Never infer one from a socket peer alone.
    std::string upload_verdict;
    // Plain-language description. A file-open sentence is not an upload.
    // A sentence that starts with 已上传 is only written after a body match and
    // an observed transfer result. target_resource remains the absolute path.
    std::string summary;
    std::vector<std::string> related_event_ids;
};
std::string NewUuid();
std::string ToJson(const EvidenceRecord& record, const std::string& session, uint64_t sequence);
bool IsWithin(const std::string& path, const std::string& root) noexcept;
} // namespace agentsec
