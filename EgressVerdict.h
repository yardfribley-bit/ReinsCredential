#pragma once
#include "Types.h"
#include <cstdint>
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

// How an already-running agent's outbound flow was observed. No CA and no
// system proxy are involved. TCP byte counts are local send counters, not a
// decrypted body and not a remote receipt.
enum class LiveFlowKind { TcpMeasured, UdpOrQuic, Unreadable };

// One outbound flow sampled on the same process that held a sensitive file.
// tx_baseline is the counter at the first sample (pre-existing connections)
// or zero when the flow appeared after observation started.
struct LiveFlow {
    std::string destination;
    LiveFlowKind kind = LiveFlowKind::TcpMeasured;
    bool loopback = false;
    // Traffic the process itself sent into the local egress proxy. That path
    // is closed with exact body matching, not with this byte-count rule.
    bool to_local_proxy = false;
    // True when a kernel counter supplied tx_latest. TcpMeasured implies this.
    // An unmeasured UDP, QUIC, or TLS socket stays false and cannot support 未发现.
    bool measured = false;
    uint64_t tx_baseline = 0;
    uint64_t tx_latest = 0;
    bool preexisting = false;
    bool established = false;
    // Connect never completed, or the flow closed before a full off-host send.
    bool failed = false;
};

// What was visible for one already-running agent, or for one file it opened.
// Flows are the process tree's off-host sockets over the hold and the tail.
struct LiveAccessView {
    bool agent_visible = false;
    bool inspection_complete = false;
    bool file_open = false;
    // Raw registered size. The upload window's upper edge is this plus slack.
    uint64_t file_bytes = 0;
    // Smallest compressed size computed at registration. Zero means use file_bytes.
    uint64_t content_lower_bound = 0;
    // True after the file has been closed and the tail has elapsed, or when
    // the watch itself is finishing. 未发现 waits for this.
    bool window_settled = true;
    std::vector<LiveFlow> flows;
};

struct LiveClose {
    UploadVerdict verdict = UploadVerdict::NotVisible;
    std::string destination;
    std::string transfer_outcome;
    // flow_txbytes, flow_txbytes_udp, flow_attempt, live_agent_observed,
    // or observation_impossible.
    std::string match_basis;
    std::string detail;
    // The watch is still open. The caller keeps this close off the chain.
    bool defer = false;
};

// Sent-byte slack above the registered file size. A TLS handshake and request
// framing fit; a multi-megabyte unrelated stream does not match a small file.
constexpr uint64_t kFlowTxSlack = 65536;

// Verdict for an agent that was already running.
// 已上传 requires the tree's measured off-host send, summed across TCP and
// UDP/QUIC for the whole hold and the tail, to fall in the compression-aware
// window: at least the registered lower bound and at most the raw size plus
// slack. UDP/QUIC uses flow_txbytes_udp. A proxied body match with success is
// the other 已上传 path. 已尝试未成功 is a connect that never established.
// 未发现 is only when every off-host channel was measured for that whole
// window and the aggregate is below the lower bound. Anything less complete,
// including a send larger than the window, is 看不到. Provider names do not
// pick a different verdict.
LiveClose CloseLiveAccess(const LiveAccessView& view);
std::string LiveVerdictSummary(const LiveClose& close, const std::string& process, const std::string& path);

// A proxy body match closes the process that sent it, and the launched tree
// that sent it. A later process that opens the same file is not covered.
bool ProxyBodyCoversLiveActor(const ProcessIdentity& proxy_actor, bool proxy_from_launched_tree,
    const ProcessIdentity& live_actor, bool live_in_launched_tree) noexcept;

// Peer text for a libproc address. IPv4, IPv4-mapped, and IPv4-compatible
// addresses are dotted decimal. :: and ::1 stay IPv6.
std::string FormatSocketPeer(bool ipv4_flag, const uint8_t address[16], uint16_t port);
// Copies the IPv4 octets when FormatSocketPeer would print them as IPv4.
bool Ipv4PeerOctets(bool ipv4_flag, const uint8_t address[16], uint8_t out[4]) noexcept;
// Host of host:port or [host]:port. Model providers and known relays.
bool IsProviderOrRelay(const std::string& destination) noexcept;
} // namespace agentsec
