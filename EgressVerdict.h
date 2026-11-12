#pragma once
#include <string>
#include <vector>

namespace agentsec {
// Closing words for one sensitive-file access. They describe only what this
// process observed. They are not a claim about channels that were not visible.
enum class UploadVerdict { Uploaded, Attempted, NotFound, NotVisible };

const char* UploadVerdictCode(UploadVerdict verdict) noexcept;
const char* UploadVerdictLabel(UploadVerdict verdict) noexcept;

struct EgressObservation {
    enum class Kind { HttpInspected, OpaqueTunnel, UninspectedSocket };
    Kind kind = Kind::HttpInspected;
    // True only when this observation's body matched the access being closed.
    bool content_match = false;
    // Meaningful for inspected HTTP. A 2xx response is the observed transfer.
    // It is not an independent receipt from the far side.
    bool transfer_succeeded = false;
    std::string destination;
    std::string transfer_outcome;
};

struct AccessClose {
    UploadVerdict verdict = UploadVerdict::NotVisible;
    std::string destination;
    std::string transfer_outcome;
};

// egress_watched means the plaintext HTTP of this process tree was in scope
// for the local proxy. An opaque tunnel or a socket whose bytes were not read
// forces 看不到, unless a visible request already matched. 未发现 is only for
// a watched tree whose observed egress was entirely inspected HTTP and did not
// contain the registered content.
AccessClose CloseAccess(bool egress_watched, const std::vector<EgressObservation>& observations);

// Plain sentence. It starts with the Chinese verdict and names the destination
// and transfer result that were actually observed.
std::string UploadVerdictSummary(const AccessClose& close, const std::string& process, const std::string& path);
} // namespace agentsec
