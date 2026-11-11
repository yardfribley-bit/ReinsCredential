#include "AgentMonitor.h"
#include "ContentMatcher.h"
#include "EgressVerdict.h"
#include "EvidenceStore.h"
#include "ProcessCache.h"
#include <arpa/inet.h>
#include <libproc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <spawn.h>
#include <fcntl.h>
#include <poll.h>
#include <csignal>
#include <array>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

extern char** environ;

namespace {
using namespace agentsec;
constexpr size_t kMaxBody = 1024 * 1024;
constexpr size_t kMaxHeader = 8192;
constexpr size_t kMaxTree = 64;
volatile std::sig_atomic_t stopping = 0;
void OnStop(int) { stopping = 1; }
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

void Wipe(std::string& bytes) noexcept {
    for (char& c : bytes) {
        volatile char* p = &c;
        *p = 0;
    }
    bytes.clear();
}
struct Version {
    std::string path, sha256, bytes;
    Version() = default;
    Version(Version&& other) noexcept : path(std::move(other.path)), sha256(std::move(other.sha256)), bytes(std::move(other.bytes)) {}
    Version& operator=(Version&& other) noexcept {
        if (this != &other) { Wipe(bytes); path = std::move(other.path); sha256 = std::move(other.sha256); bytes = std::move(other.bytes); }
        return *this;
    }
    Version(const Version&) = delete;
    Version& operator=(const Version&) = delete;
    ~Version() { Wipe(bytes); }
};
std::string ReadFile(const std::string& path) {
    auto fd = OwnFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    Require(fd && fd->value >= 0, "cannot open registered file");
    struct stat st{};
    Require(!fstat(fd->value, &st) && S_ISREG(st.st_mode) && st.st_size >= 16 &&
        st.st_size <= static_cast<off_t>(kMaxBody), "registered file must be a regular file of 16 bytes to 1 MiB");
    std::string bytes;
    std::array<char, 8192> block{};
    for (;;) {
        auto n = ::read(fd->value, block.data(), block.size());
        if (n < 0 && errno == EINTR) continue;
        Require(n >= 0, "file read failed");
        if (!n) break;
        Require(bytes.size() + static_cast<size_t>(n) <= kMaxBody, "file grew beyond limit");
        bytes.append(block.data(), static_cast<size_t>(n));
    }
    return bytes;
}
void SetCloexec(int fd) { Require(!fcntl(fd, F_SETFD, FD_CLOEXEC), "cloexec failed"); }
void SetNoSigPipe(int fd) {
    int yes = 1;
    Require(!setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes)), "nosigpipe failed");
}
bool WaitFd(int fd, short events, std::chrono::milliseconds budget) {
    const auto deadline = MonoClock::now() + budget;
    for (;;) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
        if (left <= 0) return false;
        pollfd item{fd, events, 0};
        int result = poll(&item, 1, static_cast<int>(left));
        if (result > 0) return true;
        if (result == 0) return false;
        if (errno != EINTR) return false;
        if (stopping) return false;
    }
}
bool WriteAll(int fd, const std::string& bytes, std::chrono::milliseconds budget) {
    const auto deadline = MonoClock::now() + budget;
    size_t sent = 0;
    while (sent < bytes.size()) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
        if (left <= 0 || !WaitFd(fd, POLLOUT, std::chrono::milliseconds(left))) return false;
        auto n = ::send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}
// Reads until the marker is present, or until max_bytes. The marker may sit in the middle.
bool ReadSome(int fd, std::string& out, size_t max_bytes, std::chrono::milliseconds budget) {
    const auto deadline = MonoClock::now() + budget;
    while (out.size() < max_bytes) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
        if (left <= 0 || !WaitFd(fd, POLLIN, std::chrono::milliseconds(std::max<int64_t>(left, 1)))) return false;
        std::array<char, 4096> block{};
        auto n = ::recv(fd, block.data(), std::min(block.size(), max_bytes - out.size()), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (!n) return true;
        out.append(block.data(), static_cast<size_t>(n));
    }
    return true;
}
struct HttpRequest { std::string method, target, body; };
HttpRequest ReadRequest(int fd) {
    std::string bytes;
    const auto deadline = MonoClock::now() + std::chrono::seconds(5);
    size_t end = std::string::npos;
    while ((end = bytes.find("\r\n\r\n")) == std::string::npos) {
        Require(bytes.size() <= kMaxHeader, "headers too large");
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now());
        Require(left.count() > 0, "request deadline exceeded");
        auto before = bytes.size();
        Require(ReadSome(fd, bytes, kMaxHeader + 4, left) && bytes.size() > before, "incomplete request");
    }
    Require(end <= kMaxHeader, "headers too large");
    std::istringstream headers(bytes.substr(0, end));
    std::string line, version, extra;
    std::getline(headers, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream first(line);
    HttpRequest request;
    Require(static_cast<bool>(first >> request.method >> request.target >> version) && !(first >> extra) && version == "HTTP/1.1",
        "invalid request line");
    size_t length = 0;
    bool has_length = false;
    while (std::getline(headers, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        Require(colon != std::string::npos && colon > 0, "invalid header");
        auto name = line.substr(0, colon);
        for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        Require(name != "transfer-encoding", "chunked requests unsupported");
        if (name == "content-length") {
            Require(!has_length, "duplicate content length");
            has_length = true;
            auto value = line.substr(colon + 1);
            const auto start = value.find_first_not_of(" \t");
            Require(start != std::string::npos, "empty content length");
            value.erase(0, start);
            Require(value.find_first_not_of("0123456789") == std::string::npos && value.size() <= 10, "invalid content length");
            length = std::stoull(value);
            Require(length <= kMaxBody, "body too large");
        }
    }
    if (request.method != "CONNECT")
        Require(request.method == "GET" || has_length, "request requires content length");
    const auto offset = end + 4;
    while (bytes.size() - offset < length) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now());
        Require(left.count() > 0, "request deadline exceeded");
        auto before = bytes.size();
        Require(ReadSome(fd, bytes, offset + length, left) && bytes.size() > before, "incomplete body");
    }
    Require(bytes.size() - offset == length, "trailing data rejected");
    request.body = bytes.substr(offset, length);
    return request;
}
void Respond(int fd, int code, const std::string& reason, const std::string& body) {
    auto bytes = "HTTP/1.1 " + std::to_string(code) + " " + reason + "\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    Require(WriteAll(fd, bytes, std::chrono::seconds(5)), "response send failed");
}
struct Target { std::string host; uint16_t port = 0; std::string path; std::string url; };
std::optional<Target> ParseHttpUrl(const std::string& url) {
    const std::string prefix = "http://";
    if (url.rfind(prefix, 0) != 0 || url.size() > 2048) return std::nullopt;
    auto rest = url.substr(prefix.size());
    if (rest.empty() || rest.find('@') != std::string::npos || rest.find('\\') != std::string::npos) return std::nullopt;
    const auto slash = rest.find('/');
    const auto authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    auto path = slash == std::string::npos ? std::string("/") : rest.substr(slash);
    if (authority.empty() || authority.find_first_of(" \t\r\n") != std::string::npos || path.find_first_of("\r\n") != std::string::npos)
        return std::nullopt;
    std::string host = authority;
    uint16_t port = 80;
    const auto colon = authority.rfind(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        auto text = authority.substr(colon + 1);
        if (host.empty() || text.empty() || text.size() > 5 || text.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
        const auto value = std::stoi(text);
        if (value <= 0 || value > 65535) return std::nullopt;
        port = static_cast<uint16_t>(value);
    }
    if (host.empty() || host.find(':') != std::string::npos) return std::nullopt;
    return Target{host, port, path, url};
}
std::optional<std::pair<std::string, uint16_t>> ParseHostPort(const std::string& text) {
    if (text.empty() || text.size() > 2048 || text.find_first_of(" \t\r\n/@") != std::string::npos) return std::nullopt;
    const auto colon = text.rfind(':');
    if (colon == std::string::npos || colon == 0) return std::nullopt;
    auto host = text.substr(0, colon);
    auto port_text = text.substr(colon + 1);
    if (host.empty() || host.find(':') != std::string::npos || port_text.empty() || port_text.size() > 5 ||
        port_text.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
    const auto value = std::stoi(port_text);
    if (value <= 0 || value > 65535) return std::nullopt;
    return std::make_pair(host, static_cast<uint16_t>(value));
}
UniqueFd ConnectTcp(const std::string& host, uint16_t port, std::string& error) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &address.sin_addr) != 1) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* resolved = nullptr;
        const auto service = std::to_string(port);
        if (getaddrinfo(host.c_str(), service.c_str(), &hints, &resolved) != 0 || !resolved) {
            error = "resolve_failed";
            return OwnFd(-1);
        }
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> hold(resolved, freeaddrinfo);
        bool copied = false;
        for (auto* item = resolved; item; item = item->ai_next) {
            if (item->ai_family == AF_INET && item->ai_addrlen >= sizeof(sockaddr_in)) {
                std::memcpy(&address, item->ai_addr, sizeof(address));
                copied = true;
                break;
            }
        }
        if (!copied) { error = "resolve_failed"; return OwnFd(-1); }
    }
    auto fd = OwnFd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd || fd->value < 0) { error = "socket_failed"; return OwnFd(-1); }
    SetCloexec(fd->value);
    SetNoSigPipe(fd->value);
    int flags = fcntl(fd->value, F_GETFL, 0);
    Require(flags >= 0 && !fcntl(fd->value, F_SETFL, flags | O_NONBLOCK), "nonblock failed");
    if (::connect(fd->value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 && errno != EINPROGRESS) {
        error = "connect_failed";
        return OwnFd(-1);
    }
    if (!WaitFd(fd->value, POLLOUT, std::chrono::seconds(5))) { error = "connect_failed"; return OwnFd(-1); }
    int so = 0; socklen_t len = sizeof(so);
    if (getsockopt(fd->value, SOL_SOCKET, SO_ERROR, &so, &len) || so) { error = "connect_failed"; return OwnFd(-1); }
    Require(!fcntl(fd->value, F_SETFL, flags), "restore blocking failed");
    return fd;
}
struct Upstream { bool ok = false; int status = 0; std::string failure; std::string raw; };
Upstream Exchange(const Target& target, const std::string& method, const std::string& body) {
    Upstream result;
    auto fd = ConnectTcp(target.host, target.port, result.failure);
    if (!fd || fd->value < 0) { if (result.failure.empty()) result.failure = "connect_failed"; return result; }
    auto host = target.host;
    if (target.port != 80) host += ":" + std::to_string(target.port);
    std::string request = method + " " + target.path + " HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
    request.append(body);
    if (!WriteAll(fd->value, request, std::chrono::seconds(10))) { result.failure = "upstream_write_failed"; Wipe(request); return result; }
    Wipe(request);
    if (!ReadSome(fd->value, result.raw, 64 * 1024, std::chrono::seconds(10)) && result.raw.empty()) {
        result.failure = "upstream_timeout";
        return result;
    }
    auto line_end = result.raw.find("\r\n");
    if (line_end == std::string::npos || result.raw.rfind("HTTP/1.", 0) != 0) { result.failure = "upstream_bad_status"; return result; }
    std::istringstream line(result.raw.substr(0, line_end));
    std::string http, code;
    if (!(line >> http >> code) || code.size() != 3 || code.find_first_not_of("0123456789") != std::string::npos) {
        result.failure = "upstream_bad_status";
        return result;
    }
    result.status = std::stoi(code);
    result.ok = true;
    return result;
}
void Relay(int left, int right) {
    const auto deadline = MonoClock::now() + std::chrono::seconds(15);
    bool open_left = true, open_right = true;
    size_t moved = 0;
    while ((open_left || open_right) && MonoClock::now() < deadline && moved < 2 * kMaxBody && !stopping) {
        pollfd items[2] = {{left, static_cast<short>(open_left ? POLLIN : 0), 0}, {right, static_cast<short>(open_right ? POLLIN : 0), 0}};
        if (!items[0].events && !items[1].events) break;
        auto left_ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
        if (left_ms <= 0) break;
        if (poll(items, 2, static_cast<int>(std::min<int64_t>(left_ms, 200))) <= 0) continue;
        auto pump = [&](int from, int to, bool& open_flag, short revents) {
            if (!open_flag || !(revents & (POLLIN | POLLHUP | POLLERR))) return;
            std::array<char, 4096> block{};
            auto n = ::recv(from, block.data(), block.size(), 0);
            if (n < 0 && errno == EINTR) return;
            if (n <= 0) { open_flag = false; shutdown(to, SHUT_WR); return; }
            moved += static_cast<size_t>(n);
            size_t sent = 0;
            while (sent < static_cast<size_t>(n)) {
                auto w = ::send(to, block.data() + sent, static_cast<size_t>(n) - sent, 0);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { open_flag = false; return; }
                sent += static_cast<size_t>(w);
            }
            for (char& c : block) { volatile char* p = &c; *p = 0; }
        };
        pump(left, right, open_left, items[0].revents);
        pump(right, left, open_right, items[1].revents);
    }
}
bool SocketMatches(pid_t pid, uint16_t local_port, uint16_t foreign_port, in_addr_t foreign_addr, bool network_order) {
    int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
    if (needed <= 0) return false;
    std::vector<proc_fdinfo> fds(static_cast<size_t>(needed) / sizeof(proc_fdinfo) + 8);
    int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
    if (got <= 0) return false;
    const auto count = std::min(fds.size(), static_cast<size_t>(got) / sizeof(proc_fdinfo));
    for (size_t i = 0; i < count; ++i) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
        socket_fdinfo socket{};
        if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != sizeof(socket)) continue;
        const auto& info = socket.psi;
        if (info.soi_family != AF_INET) continue;
        if (info.soi_protocol != IPPROTO_TCP && info.soi_protocol != 0) continue;
        const in_sockinfo* in = nullptr;
        if (info.soi_kind == SOCKINFO_TCP) in = &info.soi_proto.pri_tcp.tcpsi_ini;
        else if (info.soi_kind == SOCKINFO_IN) in = &info.soi_proto.pri_in;
        if (!in || (in->insi_vflag & INI_IPV4) == 0) continue;
        const auto local_seen = network_order ? ntohs(static_cast<uint16_t>(in->insi_lport)) : static_cast<uint16_t>(in->insi_lport);
        const auto foreign_seen = network_order ? ntohs(static_cast<uint16_t>(in->insi_fport)) : static_cast<uint16_t>(in->insi_fport);
        if (local_seen != local_port || foreign_seen != foreign_port) continue;
        // Foreign address is the proxy. The local address is the client's own
        // loopback socket; some OS builds store that side differently, so it is
        // not required once the ports and the proxy address match.
        if (in->insi_faddr.ina_46.i46a_addr4.s_addr != foreign_addr) continue;
        return true;
    }
    return false;
}
std::vector<pid_t> ChildPids(pid_t parent) {
    // proc_listchildpids returns a byte count, matching proc_listpids.
    int bytes = proc_listchildpids(parent, nullptr, 0);
    if (bytes <= 0) return {};
    std::vector<pid_t> buffer(static_cast<size_t>(bytes) / sizeof(pid_t) + 8);
    int got = proc_listchildpids(parent, buffer.data(), static_cast<int>(buffer.size() * sizeof(pid_t)));
    if (got <= 0) return {};
    buffer.resize(std::min(buffer.size(), static_cast<size_t>(got) / sizeof(pid_t)));
    return buffer;
}
ActorProcess Describe(const ProcessNode& node) {
    ActorProcess actor;
    actor.process.node = node;
    actor.process.state = ProcessState::Observed;
    actor.process.first_seen_us = UnixMicros();
    actor.process.last_seen_us = actor.process.first_seen_us;
    actor.chain_complete = false;
    actor.chain_status = "single_process_socket_owner";
    AnnotateActor(actor, {});
    return actor;
}
struct StoredObservation {
    EgressObservation observation;
    std::string matched_path;
    std::string match_kind;
    std::string event_id;
};
struct Access {
    std::string event_id;
    std::string path;
    ActorProcess actor;
};
struct ChildProcess {
    pid_t pid = -1;
    ~ChildProcess() { Stop(); }
    void Stop() noexcept {
        if (pid <= 0) return;
        const auto target = pid;
        kill(-target, SIGTERM);
        kill(target, SIGTERM);
        const auto deadline = MonoClock::now() + std::chrono::milliseconds(500);
        int status = 0;
        while (MonoClock::now() < deadline) {
            auto got = waitpid(target, &status, WNOHANG);
            if (got == target || (got < 0 && errno != EINTR)) { pid = -1; return; }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        kill(-target, SIGKILL);
        kill(target, SIGKILL);
        while (waitpid(target, &status, 0) < 0 && errno == EINTR) {}
        pid = -1;
    }
    bool Exited() {
        if (pid <= 0) return true;
        int status = 0;
        auto got = waitpid(pid, &status, WNOHANG);
        if (got == pid) { pid = -1; return true; }
        return false;
    }
};
struct Session {
    EvidenceStore& store;
    IProcessSource& source;
    std::vector<Version> versions;
    std::vector<std::string> roots;
    ProcessIdentity root_identity;
    bool have_root = false;
    bool egress_watched = false;
    uint16_t proxy_port = 0;
    bool tree_truncated = false;
    std::map<std::string, Access> accesses;
    std::vector<StoredObservation> observations;
    std::set<std::string> socket_seen;
    uint64_t http_requests = 0, content_matches = 0, opaque_tunnels = 0, attribution_failures = 0;
    explicit Session(EvidenceStore& evidence, IProcessSource& processes) : store(evidence), source(processes) {}
    void Emit(EvidenceRecord record) { store.SubmitCritical(std::move(record)); }
    void NoteAccess(const ActorProcess& actor, const std::string& path) {
        if (path.empty() || accesses.count(path)) return;
        EvidenceRecord record;
        record.type = "sensitive_fd_observed";
        record.actor_process = actor;
        record.target_resource = path;
        record.risk_level = RiskLevel::Medium;
        record.attribution = "loopback_socket_4tuple_or_tree_sample";
        record.evidence_basis = "fd_observed";
        record.summary = SummarizeAccess(&actor, path, "fd_observed", {});
        record.detail = "descriptor_observed;bytes_read_unproven;not_an_upload";
        record.event_id = NewUuid();
        accesses.emplace(path, Access{record.event_id, path, actor});
        std::cerr << "egress access " << path << "\n";
        Emit(std::move(record));
    }
    void NoteFilesAndSockets(const ProcessNode& node) {
        auto actor = Describe(node);
        auto activity = source.Inspect(node, roots, true);
        for (const auto& path : activity.sensitive_files) NoteAccess(actor, path);
        for (const auto& peer : activity.socket_peers) {
            const auto own = "127.0.0.1:" + std::to_string(proxy_port) + "/";
            if (peer.compare(0, own.size(), own) == 0) continue;
            if (!socket_seen.insert(peer).second) continue;
            StoredObservation stored;
            stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
            stored.observation.destination = peer;
            stored.observation.transfer_outcome = "socket_body_not_visible";
            stored.event_id = NewUuid();
            EvidenceRecord record;
            record.event_id = stored.event_id;
            record.type = "egress_channel_unseen";
            record.actor_process = actor;
            record.destination = peer;
            record.transfer_outcome = stored.observation.transfer_outcome;
            record.upload_verdict = "not_visible";
            record.evidence_basis = "socket_peer_without_payload";
            record.summary = "看不到。只看到了套接字对端 " + peer + "，没有看到发送的字节。";
            record.risk_level = RiskLevel::Medium;
            record.attribution = "libproc_socket_peer_in_launched_tree";
            observations.push_back(std::move(stored));
            Emit(std::move(record));
        }
    }
    void SampleTree(pid_t root) {
        if (!have_root || root <= 0) return;
        std::vector<pid_t> pending{root};
        std::set<pid_t> visited;
        size_t seen = 0;
        while (!pending.empty() && seen < kMaxTree) {
            auto pid = pending.back();
            pending.pop_back();
            if (!visited.insert(pid).second) continue;
            auto node = source.Lookup(pid);
            if (!node) continue;
            if (pid == root && node->identity != root_identity) {
                StoredObservation stored;
                stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
                stored.observation.transfer_outcome = "root_identity_replaced";
                stored.observation.destination = "";
                if (socket_seen.insert("root_identity_replaced").second) observations.push_back(std::move(stored));
                return;
            }
            ++seen;
            NoteFilesAndSockets(*node);
            for (auto child : ChildPids(pid)) pending.push_back(child);
        }
        if (!pending.empty()) tree_truncated = true;
    }
    std::optional<ActorProcess> Attribute(uint16_t client_port, pid_t root) {
        if (!have_root || root <= 0) return std::nullopt;
        in_addr loop{};
        inet_pton(AF_INET, "127.0.0.1", &loop);
        const bool orders[] = {true, false};
        for (int attempt = 0; attempt < 10; ++attempt) {
            for (bool network_order : orders) {
                std::vector<pid_t> pending{root};
                std::set<pid_t> visited;
                std::optional<ProcessNode> found;
                bool ambiguous = false;
                size_t seen = 0;
                while (!pending.empty() && seen < kMaxTree) {
                    auto pid = pending.back();
                    pending.pop_back();
                    if (!visited.insert(pid).second) continue;
                    auto node = source.Lookup(pid);
                    if (!node) continue;
                    if (pid == root && node->identity != root_identity) return std::nullopt;
                    ++seen;
                    if (SocketMatches(pid, client_port, proxy_port, loop.s_addr, network_order)) {
                        if (found) ambiguous = true;
                        found = *node;
                    }
                    for (auto child : ChildPids(pid)) pending.push_back(child);
                }
                if (ambiguous || !found) continue;
                auto again = source.Lookup(found->identity.pid);
                if (!again || again->identity != found->identity) continue;
                if (!SocketMatches(found->identity.pid, client_port, proxy_port, loop.s_addr, network_order)) continue;
                return Describe(*again);
            }
            if (attempt != 9) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::cerr << "egress unattributed client_port=" << client_port << " proxy_port=" << proxy_port << "\n";
        return std::nullopt;
    }
    struct Fingerprint { std::string path, sha256, kind; };
    std::optional<Fingerprint> Match(const std::string& body) const {
        for (const auto& version : versions) {
            auto kind = MatchContent(body, version.bytes);
            if (!kind.empty()) return Fingerprint{version.path, version.sha256, kind};
        }
        return std::nullopt;
    }
    void CloseAccesses() {
        if (tree_truncated && socket_seen.insert("process_tree_scan_truncated").second) {
            StoredObservation stored;
            stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
            stored.observation.transfer_outcome = "process_tree_scan_truncated";
            observations.push_back(std::move(stored));
        }
        for (const auto& pair : accesses) {
            const auto& access = pair.second;
            std::vector<EgressObservation> view;
            std::vector<std::string> related{access.event_id};
            std::string match_kind, digest;
            for (const auto& stored : observations) {
                auto item = stored.observation;
                item.content_match = !stored.matched_path.empty() && stored.matched_path == access.path;
                if (item.content_match) { match_kind = stored.match_kind; digest = ""; }
                view.push_back(item);
                if (!stored.event_id.empty()) related.push_back(stored.event_id);
            }
            for (const auto& version : versions) if (version.path == access.path) digest = version.sha256;
            const auto closed = CloseAccess(egress_watched, view);
            EvidenceRecord record;
            record.type = "sensitive_access_closed";
            record.actor_process = access.actor;
            record.target_resource = access.path;
            record.destination = closed.destination;
            record.transfer_outcome = closed.transfer_outcome;
            record.upload_verdict = UploadVerdictCode(closed.verdict);
            record.related_event_ids = related;
            record.evidence_basis = closed.verdict == UploadVerdict::Uploaded || closed.verdict == UploadVerdict::Attempted
                ? "egress_proxy_http_body_match" : closed.verdict == UploadVerdict::NotFound
                ? "egress_proxy_watched_http_no_match" : "egress_channel_not_visible";
            if (!match_kind.empty()) record.detail = "match=" + match_kind + ";raw_bytes_not_stored";
            else record.detail = "no_registered_content_in_inspected_body_or_channel_not_visible";
            if (closed.verdict == UploadVerdict::Uploaded || closed.verdict == UploadVerdict::Attempted)
                record.content_sha256 = digest;
            record.risk_level = closed.verdict == UploadVerdict::Uploaded || closed.verdict == UploadVerdict::Attempted
                ? RiskLevel::High : RiskLevel::Low;
            const auto process = access.actor.process.node.name.empty() ? access.actor.process.node.executable : access.actor.process.node.name;
            record.summary = UploadVerdictSummary(closed, process, access.path);
            record.attribution = "launched_tree_egress_proxy";
            Emit(std::move(record));
            std::cerr << "egress close " << record.upload_verdict << " outcome=" << closed.transfer_outcome << "\n";
        }
    }
};
void HandleClient(UniqueFd client, pid_t root, Session& session) {
    Require(client && client->value >= 0, "missing client");
    SetCloexec(client->value);
    SetNoSigPipe(client->value);
    sockaddr_in peer{}; sockaddr_in local{};
    socklen_t peer_len = sizeof(peer), local_len = sizeof(local);
    Require(!getpeername(client->value, reinterpret_cast<sockaddr*>(&peer), &peer_len), "peer name failed");
    Require(!getsockname(client->value, reinterpret_cast<sockaddr*>(&local), &local_len), "local name failed");
    Require(peer.sin_family == AF_INET && local.sin_family == AF_INET, "unexpected address family");
    const auto client_port = ntohs(peer.sin_port);
    auto actor = session.Attribute(client_port, root);
    HttpRequest request;
    try { request = ReadRequest(client->value); }
    catch (...) { Wipe(request.body); throw; }
    struct BodyGuard { std::string* body; ~BodyGuard() { if (body) Wipe(*body); } } guard{&request.body};
    if (!actor) {
        ++session.attribution_failures;
        StoredObservation stored;
        stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
        stored.observation.destination = "127.0.0.1:" + std::to_string(client_port);
        stored.observation.transfer_outcome = "client_not_attributed";
        stored.event_id = NewUuid();
        EvidenceRecord record;
        record.event_id = stored.event_id;
        record.type = "egress_channel_unseen";
        record.destination = stored.observation.destination;
        record.transfer_outcome = stored.observation.transfer_outcome;
        record.upload_verdict = "not_visible";
        record.evidence_basis = "tcp_4tuple_not_matched";
        record.summary = "看不到。连到本地代理的套接字没有对上已启动进程树里的进程，请求体没有记成上传。";
        session.observations.push_back(std::move(stored));
        session.Emit(std::move(record));
        Wipe(request.body);
        try { Respond(client->value, 403, "Peer Unattributed", "peer not in launched tree\n"); } catch (...) {}
        return;
    }
    session.NoteFilesAndSockets(actor->process.node);
    if (request.method == "CONNECT") {
        ++session.opaque_tunnels;
        auto target = ParseHostPort(request.target);
        StoredObservation stored;
        stored.observation.kind = EgressObservation::Kind::OpaqueTunnel;
        stored.event_id = NewUuid();
        std::string failure;
        UniqueFd upstream = OwnFd(-1);
        if (!target) failure = "destination_rejected";
        else {
            stored.observation.destination = target->first + ":" + std::to_string(target->second);
            upstream = ConnectTcp(target->first, target->second, failure);
        }
        EvidenceRecord record;
        record.event_id = stored.event_id;
        record.type = "egress_channel_unseen";
        record.actor_process = *actor;
        record.destination = stored.observation.destination;
        record.upload_verdict = "not_visible";
        record.evidence_basis = "opaque_tunnel_not_inspected";
        record.attribution = "loopback_4tuple_process_in_launched_tree";
        if (!upstream || upstream->value < 0) {
            stored.observation.transfer_outcome = failure.empty() ? "opaque_tunnel_connect_failed" : "opaque_tunnel_" + failure;
            record.transfer_outcome = stored.observation.transfer_outcome;
            record.summary = "看不到。到 " + record.destination + " 的隧道没有建立，隧道里的字节本来也不会被检查。";
            session.observations.push_back(std::move(stored));
            session.Emit(std::move(record));
            Wipe(request.body);
            try { Respond(client->value, 502, "Tunnel Failed", "tunnel failed\n"); } catch (...) {}
            return;
        }
        stored.observation.transfer_outcome = "opaque_tunnel_body_not_visible";
        record.transfer_outcome = stored.observation.transfer_outcome;
        record.summary = "看不到。到 " + record.destination + " 的字节是原样转发的，代理没有检查内容。";
        session.observations.push_back(stored);
        session.Emit(std::move(record));
        // No Content-Length and no Connection: close. The bytes after this line are the tunnel.
        WriteAll(client->value, "HTTP/1.1 200 Connection Established\r\n\r\n", std::chrono::seconds(5));
        Relay(client->value, upstream->value);
        Wipe(request.body);
        return;
    }
    ++session.http_requests;
    auto target = ParseHttpUrl(request.target);
    auto fingerprint = session.Match(request.body);
    const auto body_size = request.body.size();
    Upstream upstream;
    if (!target) upstream.failure = "destination_rejected";
    else upstream = Exchange(*target, request.method, request.body);
    Wipe(request.body);
    const bool success = upstream.ok && upstream.status >= 200 && upstream.status < 300;
    std::string outcome = !upstream.failure.empty() ? upstream.failure : success ? "upstream_http_2xx"
        : "upstream_http_" + std::to_string(upstream.status);
    if (success) outcome = "upstream_http_2xx;application_receipt_requires_independent_verification";
    StoredObservation stored;
    stored.observation.kind = EgressObservation::Kind::HttpInspected;
    stored.observation.destination = target ? target->url : request.target;
    stored.observation.transfer_outcome = outcome;
    stored.observation.transfer_succeeded = success;
    stored.event_id = NewUuid();
    if (fingerprint) {
        stored.matched_path = fingerprint->path;
        stored.match_kind = fingerprint->kind;
        stored.observation.content_match = true;
        ++session.content_matches;
    }
    EvidenceRecord record;
    record.event_id = stored.event_id;
    record.type = "egress_transfer";
    record.actor_process = *actor;
    record.destination = stored.observation.destination;
    record.transfer_outcome = outcome;
    record.count = body_size;
    record.attribution = "loopback_4tuple_process_in_launched_tree";
    record.risk_level = fingerprint ? RiskLevel::High : RiskLevel::Low;
    if (upstream.status) record.metrics["http_status"] = static_cast<uint64_t>(upstream.status);
    if (fingerprint) {
        record.target_resource = fingerprint->path;
        record.content_sha256 = fingerprint->sha256;
        record.evidence_basis = fingerprint->kind;
        record.upload_verdict = success ? "uploaded" : "attempted";
        record.detail = "match=" + fingerprint->kind + ";raw_bytes_not_stored;open_of_source_file_not_proven_by_this_record";
        const auto who = actor->process.node.name.empty() ? actor->process.node.executable : actor->process.node.name;
        AccessClose preview;
        preview.verdict = success ? UploadVerdict::Uploaded : UploadVerdict::Attempted;
        preview.destination = record.destination;
        preview.transfer_outcome = outcome;
        record.summary = UploadVerdictSummary(preview, who, fingerprint->path);
    } else {
        record.evidence_basis = "no_registered_whole_version_match";
        record.detail = "inspected_http_body;registered_content_absent;raw_bytes_not_stored";
        record.summary = "明文 HTTP 已查看，请求体里没有已登记文件的内容。目的地 " + record.destination + "。结果：" + outcome + "。";
    }
    std::cerr << "egress http match=" << (fingerprint ? fingerprint->kind : "none") << " status=" << upstream.status
              << " failure=" << upstream.failure << "\n";
    // The upstream bytes are not evidence and may echo a secret. The client only needs the status.
    Wipe(upstream.raw);
    session.observations.push_back(std::move(stored));
    session.Emit(std::move(record));
    if (!upstream.ok) Respond(client->value, 502, "Upstream Failed", "upstream failed\n");
    else Respond(client->value, upstream.status ? upstream.status : 502, success ? "OK" : "Result", success ? "ok\n" : "upstream result\n");
}
std::vector<std::string> ProxyEnvironment(uint16_t port) {
    std::vector<std::string> env;
    const std::string proxy = "http://127.0.0.1:" + std::to_string(port);
    const std::set<std::string> replace = {"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy",
        "no_proxy", "NO_PROXY", "EGRESS_PROXY", "EGRESS_PROXY_PORT"};
    for (char** item = environ; item && *item; ++item) {
        std::string entry(*item);
        const auto eq = entry.find('=');
        if (eq != std::string::npos && replace.count(entry.substr(0, eq))) continue;
        env.push_back(std::move(entry));
    }
    env.push_back("http_proxy=" + proxy);
    env.push_back("HTTP_PROXY=" + proxy);
    env.push_back("https_proxy=" + proxy);
    env.push_back("HTTPS_PROXY=" + proxy);
    env.push_back("ALL_PROXY=" + proxy);
    env.push_back("all_proxy=" + proxy);
    env.push_back("no_proxy=");
    env.push_back("NO_PROXY=");
    env.push_back("EGRESS_PROXY=" + proxy);
    env.push_back("EGRESS_PROXY_PORT=" + std::to_string(port));
    return env;
}
} // namespace

int main(int argc, char** argv) {
    using namespace agentsec;
    try {
        std::string log, port_file;
        std::vector<std::string> files;
        int duration = 0, sample_ms = 50, timeout_sec = 20;
        std::vector<char*> command;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--launch") {
                Require(i + 1 < argc && std::string(argv[i + 1]) == "--", "usage: --launch -- command");
                ++i;
                for (int j = i + 1; j < argc; ++j) command.push_back(argv[j]);
                break;
            }
            Require(i + 1 < argc, "missing option value");
            const std::string value = argv[++i];
            if (arg == "--log") log = value;
            else if (arg == "--port-file") port_file = value;
            else if (arg == "--sensitive-file") files.push_back(value);
            else if (arg == "--duration") duration = std::stoi(value);
            else if (arg == "--sample-ms") sample_ms = std::stoi(value);
            else if (arg == "--timeout-sec") timeout_sec = std::stoi(value);
            else throw std::runtime_error("unknown option");
        }
        Require(!log.empty() && !files.empty() && files.size() <= 32, "usage: agent-egress --log PATH --sensitive-file PATH [--port-file PATH] [--duration SEC] [--sample-ms N] [--timeout-sec N] [--launch -- command]");
        Require(sample_ms >= 20 && sample_ms <= 1000, "sample-ms must be 20..1000");
        Require(timeout_sec >= 1 && timeout_sec <= 120, "timeout-sec must be 1..120");
        Require(duration >= 0 && duration <= 120, "duration must be 0..120");
        std::signal(SIGTERM, OnStop);
        std::signal(SIGINT, OnStop);
        std::signal(SIGPIPE, SIG_IGN);
        EvidenceStore store(log, {});
        auto source = MakeDarwinProcessSource();
        Session session(store, *source);
        for (const auto& file : files) {
            auto path = std::filesystem::weakly_canonical(std::filesystem::absolute(file)).string();
            Version version;
            version.path = path;
            version.bytes = ReadFile(path);
            version.sha256 = Sha256(version.bytes);
            session.roots.push_back(path);
            session.versions.push_back(std::move(version));
        }
        auto listener = OwnFd(::socket(AF_INET, SOCK_STREAM, 0));
        Require(listener && listener->value >= 0, "socket failed");
        SetCloexec(listener->value);
        int yes = 1;
        Require(!setsockopt(listener->value, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)), "reuse failed");
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        Require(!bind(listener->value, reinterpret_cast<sockaddr*>(&address), sizeof(address)), "bind failed");
        Require(!listen(listener->value, 16), "listen failed");
        socklen_t address_len = sizeof(address);
        Require(!getsockname(listener->value, reinterpret_cast<sockaddr*>(&address), &address_len), "getsockname failed");
        session.proxy_port = ntohs(address.sin_port);
        if (!port_file.empty()) {
            auto fd = OwnFd(::open(port_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600));
            Require(fd && fd->value >= 0, "port file failed");
            auto text = std::to_string(session.proxy_port) + "\n";
            Require(WriteAll(fd->value, text, std::chrono::seconds(2)), "port file write failed");
        }
        const std::string ready_basis = "local_forward_proxy_for_launched_tree;not_system_wide;not_tls_interception;mcp_config_not_modified";
        EvidenceRecord ready;
        ready.type = "egress_proxy_ready";
        ready.destination = "http://127.0.0.1:" + std::to_string(session.proxy_port);
        ready.evidence_basis = ready_basis;
        ready.summary = "本地出口代理已监听。它只检查本次启动的进程树连到该代理的明文 HTTP。不解密 TLS，不修改 MCP 配置。";
        ready.metrics["listen_port"] = session.proxy_port;
        session.Emit(std::move(ready));
        std::cout << "egress_port=" << session.proxy_port << "\n" << std::flush;
        ChildProcess child;
        if (!command.empty()) {
            Require(command[0] != nullptr, "empty command");
            posix_spawnattr_t attr;
            Require(!posix_spawnattr_init(&attr), "spawn attr failed");
            struct AttrGuard { posix_spawnattr_t* value; ~AttrGuard() { posix_spawnattr_destroy(value); } } attr_guard{&attr};
            Require(!posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP), "spawn flags failed");
            Require(!posix_spawnattr_setpgroup(&attr, 0), "spawn pgroup failed");
            auto env_strings = ProxyEnvironment(session.proxy_port);
            std::vector<char*> envp;
            envp.reserve(env_strings.size() + 1);
            for (auto& entry : env_strings) envp.push_back(entry.data());
            envp.push_back(nullptr);
            command.push_back(nullptr);
            int spawned = posix_spawnp(&child.pid, command[0], nullptr, &attr, command.data(), envp.data());
            command.pop_back();
            Require(spawned == 0 && child.pid > 0, "spawn failed");
            std::optional<ProcessNode> root;
            for (int attempt = 0; attempt < 20 && !root; ++attempt) {
                root = source->Lookup(child.pid);
                if (!root) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            Require(static_cast<bool>(root), "launched process was not visible");
            session.root_identity = root->identity;
            session.have_root = true;
            session.egress_watched = true;
            std::cerr << "egress child " << child.pid << "\n";
        }
        const auto started = MonoClock::now();
        const auto limit = command.empty() ? std::chrono::seconds(duration ? duration : 1) : std::chrono::seconds(timeout_sec);
        while (!stopping) {
            if (MonoClock::now() - started >= limit) break;
            if (child.pid > 0 && child.Exited()) break;
            if (command.empty() && duration && MonoClock::now() - started >= std::chrono::seconds(duration)) break;
            pollfd pending{listener->value, POLLIN, 0};
            auto result = poll(&pending, 1, sample_ms);
            if (result < 0 && errno == EINTR) continue;
            Require(result >= 0, "poll failed");
            if (result > 0 && (pending.revents & POLLIN)) {
                auto accepted = accept(listener->value, nullptr, nullptr);
                if (accepted < 0) { if (errno == EINTR) continue; throw std::runtime_error("accept failed"); }
                try { HandleClient(OwnFd(accepted), child.pid, session); }
                catch (const std::exception& error) {
                    std::cerr << "egress request failed: " << error.what() << "\n";
                }
            } else if (session.have_root) {
                session.SampleTree(child.pid);
            }
            store.Check();
        }
        if (session.have_root && child.pid > 0) session.SampleTree(child.pid);
        if (child.pid > 0) child.Stop();
        session.CloseAccesses();
        EvidenceRecord stopped;
        stopped.type = "egress_proxy_stopped";
        stopped.evidence_basis = ready_basis;
        stopped.metrics = {{"http_requests", session.http_requests}, {"content_matches", session.content_matches},
            {"accesses", session.accesses.size()}, {"opaque_tunnels", session.opaque_tunnels},
            {"uninspected_sockets", session.socket_seen.size()}, {"attribution_failures", session.attribution_failures},
            {"tree_truncated", session.tree_truncated ? 1 : 0}};
        stopped.summary = "本地出口代理已停止。没有写入原始敏感字节。";
        session.Emit(std::move(stopped));
        store.Close();
        return 0;
    } catch (const std::exception& error) {
        EvidenceRecord record;
        record.event_id = NewUuid();
        record.type = "egress_proxy_fatal";
        record.detail = error.what();
        std::cerr << ToJson(record, "egress", 0) << '\n';
        return 1;
    }
}
