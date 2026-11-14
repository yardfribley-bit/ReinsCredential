#include "AgentMonitor.h"
#include "ContentMatcher.h"
#include "EgressVerdict.h"
#include "EvidenceStore.h"
#include "ProcessCache.h"
#include "TlsIntercept.h"
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
#include <chrono>
#include <mutex>
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
    uint64_t lower_bound = 0;
    Version() = default;
    Version(Version&& other) noexcept : path(std::move(other.path)), sha256(std::move(other.sha256)), bytes(std::move(other.bytes)), lower_bound(other.lower_bound) {}
    Version& operator=(Version&& other) noexcept {
        if (this != &other) { Wipe(bytes); path = std::move(other.path); sha256 = std::move(other.sha256); bytes = std::move(other.bytes); lower_bound = other.lower_bound; }
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
        auto n = ::write(fd, bytes.data() + sent, bytes.size() - sent);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}
// One chunk, EOF, or the deadline. Callers loop until they have the bytes they need.
// Filling max_bytes here would stall a client that has already sent a short request
// and is waiting for the response.
bool ReadSome(int fd, std::string& out, size_t max_bytes, std::chrono::milliseconds budget) {
    if (out.size() >= max_bytes) return true;
    const auto deadline = MonoClock::now() + budget;
    for (;;) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
        if (left <= 0 || !WaitFd(fd, POLLIN, std::chrono::milliseconds(std::max<int64_t>(left, 1)))) return false;
        std::array<char, 4096> block{};
        auto n = ::recv(fd, block.data(), std::min(block.size(), max_bytes - out.size()), 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (!n) return true;
        out.append(block.data(), static_cast<size_t>(n));
        return true;
    }
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
// nullopt means the buffer is incomplete when need_more is true.
std::optional<HttpRequest> TryParseRequest(const std::string& bytes, bool& need_more, std::string& error) {
    need_more = false;
    auto end = bytes.find("\r\n\r\n");
    if (end == std::string::npos) {
        if (bytes.size() > kMaxHeader) { error = "headers too large"; return std::nullopt; }
        need_more = true;
        return std::nullopt;
    }
    if (end > kMaxHeader) { error = "headers too large"; return std::nullopt; }
    std::istringstream headers(bytes.substr(0, end));
    std::string line, version, extra;
    std::getline(headers, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream first(line);
    HttpRequest request;
    if (!(first >> request.method >> request.target >> version) || (first >> extra) || version != "HTTP/1.1") {
        error = "invalid request line";
        return std::nullopt;
    }
    size_t length = 0;
    bool has_length = false;
    while (std::getline(headers, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto colon = line.find(':');
        if (colon == std::string::npos || colon == 0) { error = "invalid header"; return std::nullopt; }
        auto name = line.substr(0, colon);
        for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (name == "transfer-encoding") { error = "chunked requests unsupported"; return std::nullopt; }
        if (name == "content-length") {
            if (has_length) { error = "duplicate content length"; return std::nullopt; }
            has_length = true;
            auto value = line.substr(colon + 1);
            const auto start = value.find_first_not_of(" \t");
            if (start == std::string::npos) { error = "empty content length"; return std::nullopt; }
            value.erase(0, start);
            if (value.find_first_not_of("0123456789") != std::string::npos || value.size() > 10) { error = "invalid content length"; return std::nullopt; }
            length = std::stoull(value);
            if (length > kMaxBody) { error = "body too large"; return std::nullopt; }
        }
    }
    if (request.method != "GET" && !has_length) { error = "request requires content length"; return std::nullopt; }
    const auto offset = end + 4;
    if (bytes.size() < offset + length) { need_more = true; return std::nullopt; }
    if (bytes.size() != offset + length) { error = "trailing data rejected"; return std::nullopt; }
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
    const auto deadline = MonoClock::now() + std::chrono::seconds(10);
    while (result.raw.find("\r\n") == std::string::npos && result.raw.size() < 64 * 1024) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now());
        if (left.count() <= 0) break;
        const auto before = result.raw.size();
        if (!ReadSome(fd->value, result.raw, 64 * 1024, left) && result.raw.size() == before) break;
        if (result.raw.size() == before) break;
    }
    if (result.raw.empty()) { result.failure = "upstream_timeout"; return result; }
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
// The process holding the descriptor is often a tool inside an agent tree.
// Walk the parents that libproc actually returns so owning_agent names that
// agent. A missing parent stays missing; nothing is chosen by time.
ActorProcess Describe(IProcessSource& source, const ProcessNode& node) {
    ActorProcess actor;
    actor.process.node = node;
    actor.process.state = ProcessState::Observed;
    actor.process.first_seen_us = UnixMicros();
    actor.process.last_seen_us = actor.process.first_seen_us;
    actor.chain_complete = false;
    actor.chain_status = "missing_parent";
    const auto birth = [](const ProcessIdentity& id) {
        return std::make_pair(id.start_seconds, id.start_microseconds);
    };
    auto finish_root = [&](const ProcessNode& current) {
        if (current.identity.pid == 1 || current.ppid == 0) {
            actor.chain_complete = true;
            actor.chain_status = "observed_chain_to_root";
            return true;
        }
        if (current.ppid == 1 && source.ConfirmParentPid(current, 1)) {
            actor.chain_complete = true;
            actor.chain_status = "observed_chain_to_launchd";
            if (current.identity == node.identity) actor.process.launchd_parent_validated = true;
            return true;
        }
        return false;
    };
    if (!finish_root(node)) {
        ProcessNode current = node;
        std::set<ProcessIdentity> visited{node.identity};
        for (int depth = 0; depth < 32; ++depth) {
            if (current.ppid <= 0) break;
            auto parent = source.Lookup(current.ppid);
            if (!parent) {
                actor.chain_status = "missing_parent";
                break;
            }
            if (parent->identity == current.identity || !visited.insert(parent->identity).second) {
                actor.chain_status = "cycle_rejected";
                break;
            }
            if (birth(parent->identity) > birth(current.identity) || !source.ValidateParent(current, *parent)) {
                actor.chain_status = "missing_parent";
                break;
            }
            ProcessEntry entry;
            entry.node = *parent;
            entry.state = ProcessState::Observed;
            entry.first_seen_us = actor.process.first_seen_us;
            entry.last_seen_us = actor.process.last_seen_us;
            actor.ancestors.push_back(std::move(entry));
            current = *parent;
            if (finish_root(current)) break;
        }
    }
    AnnotateActor(actor, {});
    ApplyBehaviorOwner(actor);
    return actor;
}
struct StoredObservation {
    EgressObservation observation;
    std::string matched_path;
    std::string match_kind;
    std::string event_id;
    std::optional<ProcessIdentity> actor_identity;
    bool launched_tree = false;
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
std::string SanitizePeer(const std::string& name) {
    std::string clean;
    for (unsigned char c : name) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')
            clean.push_back(static_cast<char>(c));
        if (clean.size() >= 253) break;
    }
    return clean;
}
// Reverse DNS for a numeric peer. ClientHello SNI is not on a socket we can
// read, so a resolver name is the only hostname available without decryption.
// The lookup runs off the sample thread and is skipped when it is still pending.
std::string PeerName(const std::string& destination) {
    if (destination.empty()) return {};
    std::string host = destination;
    if (!host.empty() && host[0] == '[') {
        const auto end = host.find(']');
        host = end == std::string::npos ? std::string() : host.substr(1, end - 1);
    } else {
        const auto colon = host.rfind(':');
        if (colon != std::string::npos) host.resize(colon);
    }
    if (host.empty() || host.rfind("127.", 0) == 0 || host == "::1" || host == "0.0.0.0") return {};
    in_addr parsed{};
    if (inet_pton(AF_INET, host.c_str(), &parsed) != 1) return {};
    struct Entry { bool done = false; std::string name; };
    static std::mutex mu;
    static std::map<std::string, Entry> cache;
    {
        std::lock_guard<std::mutex> lock(mu);
        auto found = cache.find(host);
        if (found != cache.end()) return found->second.done ? found->second.name : std::string();
        cache[host] = Entry{};
    }
    std::thread([host] {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(80);
        inet_pton(AF_INET, host.c_str(), &address.sin_addr);
        char node[NI_MAXHOST];
        std::string resolved;
        if (getnameinfo(reinterpret_cast<sockaddr*>(&address), sizeof(address), node, sizeof(node), nullptr, 0, NI_NAMEREQD) == 0)
            resolved = SanitizePeer(node);
        if (resolved == host) resolved.clear();
        std::lock_guard<std::mutex> lock(mu);
        cache[host] = Entry{true, resolved};
    }).detach();
    return {};
}
struct Session {
    EvidenceStore& store;
    IProcessSource& source;
    std::vector<Version> versions;
    std::vector<std::string> roots;
    struct Root { ProcessIdentity identity; pid_t pid = 0; bool launched = false; };
    std::vector<Root> watched;
    bool launched = false;
    bool watch_live = false;
    std::unique_ptr<TlsIntercept> tls;
    std::map<pid_t, MonoClock::time_point> inspected_at;
    MonoClock::time_point last_slow_inspect{};
    MonoClock::time_point last_launched_sample{};
    size_t rescan_cursor = 0;
    uint16_t proxy_port = 0;
    bool tree_truncated = false;
    bool launched_tree_truncated = false;
    std::map<std::string, Access> accesses;
    std::vector<StoredObservation> observations;
    std::set<std::string> socket_seen;
    uint64_t http_requests = 0, content_matches = 0, opaque_tunnels = 0, attribution_failures = 0;
    explicit Session(EvidenceStore& evidence, IProcessSource& processes) : store(evidence), source(processes) {}
    void Emit(EvidenceRecord record) { store.SubmitCritical(std::move(record)); }
    void NoteAccess(const ActorProcess& actor, const std::string& path) {
        if (path.empty()) return;
        auto found = accesses.find(path);
        if (found != accesses.end()) {
            // The first sample can race the parent walk. Keep a later sample
            // only when it adds the owning agent the first one missed.
            const bool stored_named = found->second.actor.owning_agent.has_value();
            if (!stored_named && (actor.owning_agent.has_value() || actor.ancestors.size() > found->second.actor.ancestors.size()))
                found->second.actor = actor;
            return;
        }
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
    bool LaunchedActor(const ActorProcess& actor) const {
        for (const auto& root : watched) {
            if (!root.launched) continue;
            if (root.identity == actor.process.node.identity) return true;
            for (const auto& ancestor : actor.ancestors)
                if (ancestor.node.identity == root.identity) return true;
        }
        return false;
    }
    const Version* FindVersion(const std::string& path) const {
        const auto base = [](const std::string& value) {
            const auto slash = value.rfind('/');
            return slash == std::string::npos ? value : value.substr(slash + 1);
        };
        for (const auto& version : versions) if (version.path == path) return &version;
        const Version* by_name = nullptr;
        int named = 0;
        for (const auto& version : versions) {
            if (base(version.path) != base(path)) continue;
            if (version.path.find(path) != std::string::npos || path.find(version.path) != std::string::npos) return &version;
            by_name = &version;
            ++named;
        }
        // /tmp and /private/tmp can name the same file. A unique basename is enough.
        return named == 1 ? by_name : nullptr;
    }
    uint64_t RegisteredSize(const std::string& path) const {
        const auto* version = FindVersion(path);
        return version ? version->bytes.size() : 0;
    }
    uint64_t RegisteredLower(const std::string& path) const {
        const auto* version = FindVersion(path);
        return version ? version->lower_bound : 0;
    }
    std::string RegisteredHash(const std::string& path) const {
        const auto* version = FindVersion(path);
        return version ? version->sha256 : std::string();
    }
    bool ToLocalProxy(const std::string& destination) const {
        const auto port = std::to_string(proxy_port);
        return destination == "127.0.0.1:" + port || destination == "[::1]:" + port || destination == "[::ffff:127.0.0.1]:" + port;
    }
    struct FlowMemory {
        std::string destination;
        bool loopback = false;
        bool udp = false;
        bool bytes_known = false;
        uint64_t baseline = 0;
        uint64_t latest = 0;
        bool preexisting = false;
        bool established = false;
        bool failed = false;
        bool closed = false;
        bool seen_now = false;
        std::string sni;
        bool tls_handshake = false;
        bool tls_app_data = false;
        bool plaintext_http = false;
        uint64_t tls_app_bytes = 0;
    };
    struct LiveProc {
        ProcessIdentity identity;
        ProcessIdentity root;
        ActorProcess actor;
        bool known = false;
        bool inspection_complete = true;
        bool saw_complete_listing = false;
        bool exited = false;
        int samples = 0;
        struct FileHold {
            std::string event_id;
            bool open_now = false;
            bool saw_close = false;
            MonoClock::time_point closed_at{};
        };
        std::map<std::string, FileHold> files;
        std::map<std::string, FlowMemory> flows;
        std::map<std::string, int> emitted_rank;
        std::map<std::string, std::string> emitted_outcome;
        std::map<std::string, std::string> emitted_event;
    };
    std::map<ProcessIdentity, LiveProc> live_procs;
    std::set<ProcessIdentity> live_roots_closed_without_file;
    void ObserveLive(const ProcessNode& node, const ActorProcess& actor, const ActivitySample& activity, const ProcessIdentity& root) {
        auto& proc = live_procs[node.identity];
        proc.known = true;
        proc.identity = node.identity;
        proc.root = root;
        proc.actor = actor;
        // A dying process can fail one descriptor listing. That must not erase
        // an earlier complete listing, or a measured small send becomes 看不到.
        const bool listing_ok = activity.descriptors_complete && activity.identity_validated;
        if (listing_ok) {
            proc.inspection_complete = true;
            proc.saw_complete_listing = true;
        } else if (!proc.saw_complete_listing) {
            proc.inspection_complete = false;
        }
        std::set<std::string> open_now(activity.sensitive_files.begin(), activity.sensitive_files.end());
        for (const auto& path : open_now) {
            auto& hold = proc.files[path];
            if (hold.event_id.empty()) {
                auto noted = accesses.find(path);
                if (noted != accesses.end()) hold.event_id = noted->second.event_id;
            }
            hold.open_now = true;
            hold.saw_close = false;
            (void)path;
        }
        for (auto& item : proc.files) {
            if (open_now.count(item.first)) continue;
            if (!item.second.open_now) continue;
            item.second.open_now = false;
            item.second.saw_close = true;
            item.second.closed_at = MonoClock::now();
        }
        const auto window_upper = OpenWindowUpper(proc);
        std::set<std::string> seen;
        for (const auto& flow : activity.flows) {
            seen.insert(flow.flow_id);
            RememberFlow(proc, flow, proc.samples > 0, window_upper);
        }
        MergeRetained(proc, seen, window_upper);
        for (auto& item : proc.flows) {
            if (seen.count(item.first) || item.second.destination.empty()) continue;
            item.second.closed = true;
            if (!item.second.established && !item.second.preexisting) item.second.failed = true;
            item.second.seen_now = false;
        }
        ++proc.samples;
    }
    uint64_t OpenWindowUpper(const LiveProc& proc) const {
        uint64_t upper = 0;
        for (const auto& file : proc.files) {
            const auto size = RegisteredSize(file.first);
            if (!size) continue;
            upper = std::max(upper, size + kFlowTxSlack + kTlsHandshakeAllowance);
        }
        return upper;
    }
    void RememberFlow(LiveProc& proc, const SocketFlow& flow, bool process_already_sampled, uint64_t window_upper) {
        if (flow.flow_id.empty()) return;
        SocketFlow captured = flow;
        AttachCapturedPayload(captured);
        auto& memory = proc.flows[captured.flow_id];
        if (memory.destination.empty()) {
            memory.destination = captured.destination;
            memory.loopback = captured.loopback;
            memory.udp = captured.udp;
            memory.baseline = InitialFlowBaseline(process_already_sampled, captured.tx_bytes, window_upper);
            memory.preexisting = !process_already_sampled && memory.baseline > 0;
        }
        if (captured.bytes_known) memory.bytes_known = true;
        if (captured.loopback) memory.loopback = true;
        if (memory.sni.empty()) memory.sni = captured.sni;
        if (captured.tls_handshake) memory.tls_handshake = true;
        if (captured.tls_app_data) {
            memory.tls_app_data = true;
            memory.tls_app_bytes = std::max(memory.tls_app_bytes, captured.tls_app_bytes);
        }
        if (captured.plaintext_http) memory.plaintext_http = true;
        memory.latest = std::max(memory.latest, captured.tx_bytes);
        (void)PeerName(captured.destination);
        memory.seen_now = true;
        memory.closed = false;
        // BSD TCP states: ESTABLISHED is 4, TIME_WAIT is 10. SYN_SENT is 2.
        // State 0 is a refused or reset TCP socket that never got a PCB.
        if (captured.tcp_state >= 4 && captured.tcp_state <= 10) {
            memory.established = true;
            memory.failed = false;
        } else if (captured.bytes_known && !captured.loopback && captured.tcp_state == 0) {
            memory.failed = true;
        }
    }
    void MergeRetained(LiveProc& proc, std::set<std::string>& seen, uint64_t window_upper) {
        const bool already = proc.samples > 0;
        for (const auto& flow : source.RetainedFlows(proc.identity.pid)) {
            if (flow.flow_id.empty()) continue;
            seen.insert(flow.flow_id);
            const bool known_flow = proc.flows.count(flow.flow_id) && !proc.flows[flow.flow_id].destination.empty();
            RememberFlow(proc, flow, known_flow ? true : already, window_upper);
        }
    }
    static int VerdictRank(UploadVerdict verdict) {
        switch (verdict) {
        case UploadVerdict::Uploaded: return 4;
        case UploadVerdict::Attempted: return 3;
        case UploadVerdict::NotVisible: return 2;
        case UploadVerdict::NotFound: return 1;
        }
        return 0;
    }
    LiveFlow ToLiveFlow(const FlowMemory& memory) const {
        LiveFlow flow;
        flow.destination = memory.destination;
        flow.loopback = memory.loopback;
        flow.to_local_proxy = ToLocalProxy(memory.destination);
        flow.tx_baseline = memory.baseline;
        flow.tx_latest = memory.latest;
        flow.preexisting = memory.preexisting;
        flow.established = memory.established;
        // Only a connect that never became established counts as a failed
        // attempt. A finished connection that sent some other, smaller payload
        // is ordinary traffic, not an upload attempt.
        flow.failed = (memory.failed || memory.closed) && !memory.established;
        flow.measured = memory.bytes_known;
        flow.sni = memory.sni;
        flow.tls_handshake = memory.tls_handshake;
        flow.tls_app_data = memory.tls_app_data;
        flow.tls_app_bytes = memory.tls_app_bytes;
        flow.plaintext_http = memory.plaintext_http;
        if (memory.udp) flow.kind = LiveFlowKind::UdpOrQuic;
        else if (!memory.bytes_known) flow.kind = LiveFlowKind::Unreadable;
        else flow.kind = LiveFlowKind::TcpMeasured;
        return flow;
    }
    void EmitLiveClose(LiveProc& proc, const std::string& path, const LiveClose& closed, const std::string& previous) {
        const auto key = path.empty() ? std::string("*") : path;
        const auto rank = VerdictRank(closed.verdict);
        auto& prior = proc.emitted_rank[key];
        auto& prior_outcome = proc.emitted_outcome[key];
        // Same-rank updates still matter: a file can be open before the send
        // starts, and the first close is then "no upload" until the flow appears.
        if (!ShouldEmitCloseUpdate(prior, prior_outcome, closed)) return;
        EvidenceRecord record;
        record.type = "sensitive_access_closed";
        record.actor_process = proc.actor;
        record.target_resource = path;
        record.destination = closed.destination;
        record.transfer_outcome = closed.transfer_outcome;
        record.upload_verdict = UploadVerdictCode(closed.verdict);
        record.evidence_basis = closed.match_basis;
        record.detail = closed.detail;
        record.attribution = "live_agent_flow_correlation";
        record.risk_level = closed.verdict == UploadVerdict::Uploaded || closed.verdict == UploadVerdict::Attempted
            ? RiskLevel::High : RiskLevel::Low;
        if (closed.verdict == UploadVerdict::Uploaded || closed.verdict == UploadVerdict::Attempted)
            record.content_sha256 = RegisteredHash(path);
        auto noted = proc.files.find(path);
        if (noted != proc.files.end() && !noted->second.event_id.empty()) record.related_event_ids.push_back(noted->second.event_id);
        const auto peer_name = PeerName(closed.destination);
        if (!peer_name.empty()) record.detail += ";peer_name=" + peer_name;
        if (!previous.empty()) record.related_event_ids.push_back(previous);
        const auto process = proc.actor.process.node.name.empty() ? proc.actor.process.node.executable : proc.actor.process.node.name;
        record.summary = LiveVerdictSummary(closed, process, path);
        record.event_id = NewUuid();
        proc.emitted_event[key] = record.event_id;
        prior = rank;
        prior_outcome = closed.transfer_outcome;
        std::cerr << "egress live-close " << record.upload_verdict << " basis=" << record.evidence_basis
                  << " outcome=" << record.transfer_outcome << "\n";
        Emit(std::move(record));
    }
    void FlushLive(bool finishing = false) {
        if (!watch_live) return;
        std::set<ProcessIdentity> roots_with_file;
        for (auto& item : live_procs) {
            auto& proc = item.second;
            if (proc.samples < 1) continue;
            if (proc.files.empty()) continue;
            std::set<std::string> retained_seen;
            MergeRetained(proc, retained_seen, OpenWindowUpper(proc));
            roots_with_file.insert(proc.root);
            if (!proc.inspection_complete && proc.samples < 2 && !finishing) continue;
            LiveAccessView shared;
            shared.agent_visible = true;
            shared.inspection_complete = proc.inspection_complete;
            std::set<std::string> seen_flows;
            for (const auto& other : live_procs) {
                if (other.second.root != proc.root && other.first != proc.root) continue;
                if (!other.second.inspection_complete) shared.inspection_complete = false;
                for (const auto& flow : other.second.flows) {
                    if (!seen_flows.insert(flow.first).second) continue;
                    shared.flows.push_back(ToLiveFlow(flow.second));
                }
            }
            for (const auto& file : proc.files) {
                // The startup canary's exact_bytes match covers that launched
                // process only. A later actor on the same file still closes.
                if (ProxyCovers(file.first, proc.actor)) continue;
                LiveAccessView view = shared;
                view.file_open = true;
                view.file_bytes = RegisteredSize(file.first);
                view.content_lower_bound = RegisteredLower(file.first);
                const auto tail = std::chrono::milliseconds(500);
                view.process_exited = proc.exited;
                view.window_settled = finishing || proc.exited ||
                    (file.second.saw_close && MonoClock::now() - file.second.closed_at >= tail);
                const auto closed = CloseLiveAccess(view);
                if (closed.defer) continue;
                const auto rank = VerdictRank(closed.verdict);
                const bool handshake_close = closed.transfer_outcome.find("tls_handshake") != std::string::npos ||
                    closed.transfer_outcome.find("provider_or_relay_body_not_visible") != std::string::npos;
                if (!handshake_close && rank < 3 && proc.samples < 2 && !finishing && !proc.exited) continue;
                EmitLiveClose(proc, file.first, closed, proc.emitted_event[file.first]);
            }
        }
        if (tree_truncated && watched.size() >= 64 && socket_seen.insert("live_agent_scan_truncated").second) {
            EvidenceRecord record;
            record.type = "egress_channel_unseen";
            record.upload_verdict = "not_visible";
            record.evidence_basis = "observation_impossible";
            record.transfer_outcome = "live_agent_scan_truncated";
            record.detail = "more_than_64_agent_processes;remainder_not_judged;app_settings_not_modified";
            record.summary = "看不到。桌面 Agent 进程超过了 64 个，多出来的没有逐个下结论。";
            Emit(std::move(record));
        }
        for (const auto& root : watched) {
            if (root.launched || roots_with_file.count(root.identity)) continue;
            auto found = live_procs.find(root.identity);
            if (found == live_procs.end() || found->second.samples < 2) continue;
            if (live_roots_closed_without_file.count(root.identity)) continue;
            LiveAccessView view;
            view.agent_visible = true;
            view.inspection_complete = found->second.inspection_complete;
            view.file_open = false;
            for (const auto& flow : found->second.flows) view.flows.push_back(ToLiveFlow(flow.second));
            // A descendant that could not be inspected keeps the agent at 看不到.
            for (const auto& item : live_procs) {
                if (item.second.root == root.identity && !item.second.inspection_complete) view.inspection_complete = false;
            }
            const auto closed = CloseLiveAccess(view);
            EmitLiveClose(found->second, "", closed, "");
            live_roots_closed_without_file.insert(root.identity);
        }
    }
    bool AnyProxyMatch(const std::string& path) const {
        for (const auto& stored : observations)
            if (stored.observation.kind == EgressObservation::Kind::HttpInspected && stored.matched_path == path &&
                stored.observation.content_match)
                return true;
        return false;
    }
    bool ProxyCovers(const std::string& path, const ActorProcess& live) const {
        const bool live_launched = LaunchedActor(live);
        for (const auto& stored : observations) {
            if (stored.observation.kind != EgressObservation::Kind::HttpInspected || stored.matched_path != path ||
                !stored.observation.content_match || !stored.actor_identity)
                continue;
            if (ProxyBodyCoversLiveActor(*stored.actor_identity, stored.launched_tree, live.process.node.identity, live_launched))
                return true;
        }
        return false;
    }
    void NoteFilesAndSockets(const ProcessNode& node, bool launched_tree, const ProcessIdentity& root) {
        auto actor = Describe(source, node);
        auto activity = source.Inspect(node, roots, true);
        // libproc does not set identity_validated on this direct call. The
        // lookup above already re-read the process; a missing descriptor list
        // is the incompleteness signal.
        activity.identity_validated = true;
        for (const auto& path : activity.sensitive_files) NoteAccess(actor, path);
        if (!launched_tree) {
            source.WatchFlows(node.identity.pid);
            ObserveLive(node, actor, activity, root);
            return;
        }
        for (const auto& peer : activity.socket_peers) {
            const auto own = "127.0.0.1:" + std::to_string(proxy_port) + "/";
            if (peer.compare(0, own.size(), own) == 0) continue;
            if (!socket_seen.insert(peer).second) continue;
            const bool udp = peer.find("/protocol=17") != std::string::npos;
            StoredObservation stored;
            stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
            stored.observation.destination = peer;
            stored.observation.transfer_outcome = udp ? "udp_or_quic_body_not_visible" : "socket_body_not_visible";
            stored.event_id = NewUuid();
            EvidenceRecord record;
            record.event_id = stored.event_id;
            record.type = "egress_channel_unseen";
            record.actor_process = actor;
            record.destination = peer;
            record.transfer_outcome = stored.observation.transfer_outcome;
            record.upload_verdict = "not_visible";
            record.evidence_basis = "socket_peer_without_payload";
            record.summary = std::string("看不到。只看到了套接字对端 ") + peer + "，没有看到发送的字节。";
            record.risk_level = RiskLevel::Medium;
            record.attribution = "libproc_socket_peer_in_launched_tree";
            observations.push_back(std::move(stored));
            Emit(std::move(record));
        }
    }
    void SampleTree(pid_t root, const ProcessIdentity& identity, bool launched_tree) {
        if (root <= 0) return;
        if (!launched_tree && !source.Lookup(root)) {
            auto found = live_procs.find(identity);
            if (found != live_procs.end() && found->second.known) {
                found->second.exited = true;
                for (auto& flow : found->second.flows) {
                    if (!flow.second.established && !flow.second.loopback && flow.second.bytes_known)
                        flow.second.failed = true;
                }
                for (auto& file : found->second.files) {
                    file.second.open_now = false;
                    if (!file.second.saw_close) {
                        file.second.saw_close = true;
                        file.second.closed_at = MonoClock::now();
                    }
                }
            }
            return;
        }
        std::vector<pid_t> pending{root};
        std::set<pid_t> visited;
        size_t seen = 0;
        while (!pending.empty() && seen < kMaxTree) {
            auto pid = pending.back();
            pending.pop_back();
            if (!visited.insert(pid).second) continue;
            auto node = source.Lookup(pid);
            if (!node) continue;
            if (pid == root && node->identity != identity) {
                if (!launched_tree) {
                    auto& proc = live_procs[identity];
                    proc.known = true;
                    proc.identity = identity;
                    proc.root = identity;
                    proc.inspection_complete = false;
                    proc.samples = std::max(proc.samples, 2);
                } else {
                    StoredObservation stored;
                    stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
                    stored.observation.transfer_outcome = "root_identity_replaced";
                    stored.observation.destination = "";
                    if (socket_seen.insert("root_identity_replaced").second) observations.push_back(std::move(stored));
                }
                return;
            }
            ++seen;
            NoteFilesAndSockets(*node, launched_tree, identity);
            for (auto child : ChildPids(pid)) pending.push_back(child);
        }
        if (!pending.empty()) {
            tree_truncated = true;
            if (launched_tree) launched_tree_truncated = true;
            else {
                auto& proc = live_procs[identity];
                proc.known = true;
                proc.identity = identity;
                proc.root = identity;
                proc.inspection_complete = false;
                proc.samples = std::max(proc.samples, 2);
            }
        }
    }
    bool WatchingPid(pid_t pid) const {
        for (const auto& root : watched) if (root.pid == pid) return true;
        return false;
    }
    bool ConsiderPid(pid_t pid) {
        inspected_at[pid] = MonoClock::now();
        if (watched.size() >= 64) { tree_truncated = true; return false; }
        if (WatchingPid(pid)) return false;
        auto node = source.Lookup(pid);
        if (!node || IsCollectorProcess(*node) || IsAppleSystemDaemon(*node)) return false;
        auto activity = source.Inspect(*node, roots, false);
        if (activity.sensitive_files.empty()) return false;
        auto actor = Describe(source, *node);
        std::string label = node->name.empty() ? node->executable : node->name;
        if (actor.owning_agent && !actor.owning_agent->bundle.empty()) label = actor.owning_agent->bundle;
        watched.push_back(Root{node->identity, node->identity.pid, false});
        std::cerr << "egress live " << node->identity.pid << " " << label << "\n";
        return true;
    }
    void DiscoverHolders() {
        if (!watch_live) return;
        source.StartFlowWatch();
        const auto now = MonoClock::now();
        auto hot = source.TakeHotPids();
        std::sort(hot.begin(), hot.end(), [](pid_t left, pid_t right) { return left > right; });
        std::vector<pid_t> later;
        bool took_hot = false;
        for (const auto pid : hot) {
            const auto seen = inspected_at.find(pid);
            const bool recent = seen != inspected_at.end() && now - seen->second < std::chrono::seconds(1);
            if (!took_hot && FastDiscoveryInspect(false, true, WatchingPid(pid), recent)) {
                ConsiderPid(pid);
                took_hot = true;
            } else if (!WatchingPid(pid)) {
                later.push_back(pid);
            }
        }
        if (!later.empty()) source.RestoreHotPids(later);
        int estimate = proc_listallpids(nullptr, 0);
        if (estimate <= 0) return;
        std::vector<pid_t> pids(static_cast<size_t>(estimate) + 64);
        const int count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
        if (count <= 0) return;
        const auto listed = std::min(pids.size(), static_cast<size_t>(count));
        std::vector<pid_t> fresh;
        fresh.reserve(32);
        for (size_t index = 0; index < listed; ++index) {
            const auto pid = pids[index];
            if (pid <= 1 || WatchingPid(pid) || inspected_at.count(pid)) continue;
            fresh.push_back(pid);
        }
        std::sort(fresh.begin(), fresh.end(), [](pid_t left, pid_t right) { return left > right; });
        size_t fresh_budget = 4;
        for (const auto pid : fresh) {
            if (!fresh_budget || watched.size() >= 64) break;
            if (!FastDiscoveryInspect(true, false, WatchingPid(pid), false)) continue;
            --fresh_budget;
            ConsiderPid(pid);
        }
        if (inspected_at.size() > 8192) {
            const auto cutoff = MonoClock::now() - std::chrono::seconds(30);
            for (auto it = inspected_at.begin(); it != inspected_at.end(); ) {
                if (it->second < cutoff && !WatchingPid(it->first)) it = inspected_at.erase(it);
                else ++it;
            }
        }
        std::vector<pid_t> rotation;
        rotation.reserve(inspected_at.size());
        for (const auto& item : inspected_at) if (!WatchingPid(item.first)) rotation.push_back(item.first);
        const bool slow_due = last_slow_inspect.time_since_epoch().count() == 0 ||
            now - last_slow_inspect >= std::chrono::milliseconds(500);
        if (slow_due && !rotation.empty() && watched.size() < 64) {
            const auto pid = rotation[rescan_cursor % rotation.size()];
            ++rescan_cursor;
            const auto seen = inspected_at.find(pid);
            const bool quiet = seen == inspected_at.end() || now - seen->second >= std::chrono::seconds(5);
            if (SlowDiscoveryInspect(WatchingPid(pid), quiet, 0, 1)) {
                ConsiderPid(pid);
                last_slow_inspect = now;
            }
        }
    }
    void SampleWatched() {
        DiscoverHolders();
        const auto now = MonoClock::now();
        const bool sample_launched = last_launched_sample.time_since_epoch().count() == 0 ||
            now - last_launched_sample >= std::chrono::seconds(1);
        if (sample_launched) last_launched_sample = now;
        for (const auto& root : watched) {
            if (root.launched && !sample_launched) continue;
            SampleTree(root.pid, root.identity, root.launched);
        }
        FlushLive();
    }
    std::optional<ActorProcess> AttributeOne(uint16_t client_port, pid_t root, const ProcessIdentity& identity) {
        if (root <= 0) return std::nullopt;
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
                    if (pid == root && node->identity != identity) return std::nullopt;
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
                return Describe(source, *again);
            }
            if (attempt != 9) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        return std::nullopt;
    }
    std::optional<ActorProcess> Attribute(uint16_t client_port) {
        for (const auto& root : watched) {
            if (auto actor = AttributeOne(client_port, root.pid, root.identity)) return actor;
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
        if (launched_tree_truncated && socket_seen.insert("process_tree_scan_truncated").second) {
            StoredObservation stored;
            stored.observation.kind = EgressObservation::Kind::UninspectedSocket;
            stored.observation.transfer_outcome = "process_tree_scan_truncated";
            observations.push_back(std::move(stored));
        }
        FlushLive(true);
        bool inspected_http = false, unseen = false;
        for (const auto& stored : observations) {
            if (stored.observation.kind == EgressObservation::Kind::HttpInspected) inspected_http = true;
            else unseen = true;
        }
        const bool egress_watched = launched || (inspected_http && !unseen);
        for (const auto& pair : accesses) {
            const auto& access = pair.second;
            // Already-running agents are closed from TCP send counters in FlushLive.
            // A body that actually entered this proxy is still an exact-bytes close.
            const bool launched_actor = LaunchedActor(access.actor);
            if (!launched_actor && !AnyProxyMatch(access.path)) continue;
            std::vector<EgressObservation> view;
            std::vector<std::string> related{access.event_id};
            std::string match_kind, digest;
            bool covered_match = false;
            for (const auto& stored : observations) {
                auto item = stored.observation;
                const bool same_file = !stored.matched_path.empty() && stored.matched_path == access.path;
                const bool this_actor = !stored.actor_identity || ProxyBodyCoversLiveActor(
                    *stored.actor_identity, stored.launched_tree, access.actor.process.node.identity, launched_actor);
                // The startup canary's body match must not close a different process
                // that later opens the same file (a refused connect is not that upload).
                item.content_match = same_file && stored.observation.content_match && this_actor;
                if (item.content_match) { match_kind = stored.match_kind; digest = ""; covered_match = true; }
                view.push_back(item);
                if (!stored.event_id.empty()) related.push_back(stored.event_id);
            }
            for (const auto& version : versions) if (version.path == access.path) digest = version.sha256;
            if (!launched_actor && !covered_match) continue;
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
            if (!LaunchedActor(access.actor)) record.detail += ";live_agent_connected_to_proxy;app_settings_not_modified";
            if (closed.destination.rfind("https://", 0) == 0) record.detail += ";tls_intercept";
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
void RecordTransfer(Session& session, const ActorProcess& actor, HttpRequest& request, const std::string& destination,
    const std::string& outcome, bool success, const std::string& tls_detail) {
    auto fingerprint = session.Match(request.body);
    const auto body_size = request.body.size();
    Wipe(request.body);
    StoredObservation stored;
    stored.observation.kind = EgressObservation::Kind::HttpInspected;
    stored.observation.destination = destination;
    stored.observation.transfer_outcome = outcome;
    stored.observation.transfer_succeeded = success;
    stored.event_id = NewUuid();
    stored.actor_identity = actor.process.node.identity;
    stored.launched_tree = session.LaunchedActor(actor);
    if (fingerprint) {
        stored.matched_path = fingerprint->path;
        stored.match_kind = fingerprint->kind;
        stored.observation.content_match = true;
        ++session.content_matches;
    }
    EvidenceRecord record;
    record.event_id = stored.event_id;
    record.type = "egress_transfer";
    record.actor_process = actor;
    record.destination = destination;
    record.transfer_outcome = outcome;
    record.count = body_size;
    record.attribution = "loopback_4tuple_process_in_watched_tree";
    record.risk_level = fingerprint ? RiskLevel::High : RiskLevel::Low;
    if (fingerprint) {
        record.target_resource = fingerprint->path;
        record.content_sha256 = fingerprint->sha256;
        record.evidence_basis = fingerprint->kind;
        record.upload_verdict = success ? "uploaded" : "attempted";
        record.detail = "match=" + fingerprint->kind + ";raw_bytes_not_stored;open_of_source_file_not_proven_by_this_record" + tls_detail;
        const auto who = actor.process.node.name.empty() ? actor.process.node.executable : actor.process.node.name;
        AccessClose preview;
        preview.verdict = success ? UploadVerdict::Uploaded : UploadVerdict::Attempted;
        preview.destination = destination;
        preview.transfer_outcome = outcome;
        record.summary = UploadVerdictSummary(preview, who, fingerprint->path);
    } else {
        record.evidence_basis = "no_registered_whole_version_match";
        record.detail = "inspected_http_body;registered_content_absent;raw_bytes_not_stored" + tls_detail;
        record.summary = "明文 HTTP 已查看，请求体里没有已登记文件的内容。目的地 " + destination + "。结果：" + outcome + "。";
    }
    std::cerr << "egress http match=" << (fingerprint ? fingerprint->kind : "none") << " outcome=" << outcome << "\n";
    session.observations.push_back(std::move(stored));
    session.Emit(std::move(record));
}
bool ReadTlsRequest(TlsSession& tls, HttpRequest& request, std::string& error) {
    std::string buffer;
    const auto deadline = MonoClock::now() + std::chrono::seconds(10);
    while (MonoClock::now() < deadline && buffer.size() < kMaxHeader + kMaxBody + 4) {
        bool need_more = false;
        std::string parse_error;
        auto parsed = TryParseRequest(buffer, need_more, parse_error);
        if (!parse_error.empty()) { Wipe(buffer); error = parse_error; return false; }
        if (parsed) { request = std::move(*parsed); Wipe(buffer); return true; }
        if (!need_more) { Wipe(buffer); error = "incomplete tls request"; return false; }
        std::array<char, 4096> block{};
        size_t got = 0;
        if (!tls.Read(block.data(), block.size(), got, error)) { Wipe(buffer); return false; }
        if (!got) { Wipe(buffer); error = "incomplete tls request"; return false; }
        buffer.append(block.data(), got);
        for (char& c : block) { volatile char* p = &c; *p = 0; }
    }
    Wipe(buffer);
    error = "tls request deadline exceeded";
    return false;
}
void InspectConnect(int fd, const ActorProcess& actor, const std::pair<std::string, uint16_t>& target, Session& session) {
    timeval budget{10, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &budget, sizeof(budget));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &budget, sizeof(budget));
    std::string error;
    auto client = session.tls->AcceptClient(fd, target.first, error);
    if (!client) {
        StoredObservation stored;
        stored.observation.kind = EgressObservation::Kind::OpaqueTunnel;
        stored.observation.destination = "https://" + target.first + ":" + std::to_string(target.second);
        stored.observation.transfer_outcome = error.empty() ? "tls_intercept_handshake_failed" : error;
        stored.event_id = NewUuid();
        EvidenceRecord record;
        record.event_id = stored.event_id;
        record.type = "egress_channel_unseen";
        record.actor_process = actor;
        record.destination = stored.observation.destination;
        record.transfer_outcome = stored.observation.transfer_outcome;
        record.upload_verdict = "not_visible";
        record.evidence_basis = "tls_intercept_handshake_failed";
        record.summary = "看不到。到 " + record.destination + " 的 TLS 没有完成代理侧握手，正文没有被检查。证书固定、客户端不信任临时 CA，或 QUIC 都会是这个结果。";
        session.observations.push_back(std::move(stored));
        session.Emit(std::move(record));
        std::cerr << "egress tls client failed " << record.transfer_outcome << "\n";
        return;
    }
    HttpRequest request;
    if (!ReadTlsRequest(*client, request, error)) {
        StoredObservation stored;
        stored.observation.kind = EgressObservation::Kind::OpaqueTunnel;
        stored.observation.destination = "https://" + target.first + ":" + std::to_string(target.second);
        stored.observation.transfer_outcome = error.empty() ? "tls_intercept_body_unreadable" : error;
        stored.event_id = NewUuid();
        EvidenceRecord record;
        record.event_id = stored.event_id;
        record.type = "egress_channel_unseen";
        record.actor_process = actor;
        record.destination = stored.observation.destination;
        record.transfer_outcome = stored.observation.transfer_outcome;
        record.upload_verdict = "not_visible";
        record.evidence_basis = "tls_intercept_body_unreadable";
        record.summary = "看不到。TLS 握手之后没有读到完整的 HTTP 请求，不能把它写成未发现。";
        session.observations.push_back(std::move(stored));
        session.Emit(std::move(record));
        return;
    }
    const auto path = request.target.empty() ? "/" : request.target;
    const auto destination = "https://" + target.first + ":" + std::to_string(target.second) + path;
    std::string failure;
    auto upstream_fd = ConnectTcp(target.first, target.second, failure);
    std::unique_ptr<TlsSession> origin;
    int status = 0;
    if (upstream_fd && upstream_fd->value >= 0) {
        setsockopt(upstream_fd->value, SOL_SOCKET, SO_RCVTIMEO, &budget, sizeof(budget));
        setsockopt(upstream_fd->value, SOL_SOCKET, SO_SNDTIMEO, &budget, sizeof(budget));
        origin = session.tls->ConnectOrigin(upstream_fd->value, target.first, failure);
    }
    if (!origin) {
        auto outcome = failure.empty() ? "tls_upstream_failed" : failure;
        if (outcome.find("upstream_http_") == std::string::npos && outcome.find("tls_") != 0) outcome = "tls_" + outcome;
        RecordTransfer(session, actor, request, destination, outcome, false, ";tls_intercept");
        const char* failed = "HTTP/1.1 502 Upstream Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        try { client->Write(failed, std::strlen(failed), error); } catch (...) {}
        return;
    }
    std::string wire = request.method + " " + path + " HTTP/1.1\r\nHost: " + target.first + ":" + std::to_string(target.second) +
        "\r\nContent-Length: " + std::to_string(request.body.size()) + "\r\nConnection: close\r\n\r\n" + request.body;
    if (!origin->Write(wire.data(), wire.size(), failure)) {
        Wipe(wire);
        RecordTransfer(session, actor, request, destination, failure.empty() ? "tls_upstream_write_failed" : failure, false, ";tls_intercept");
        return;
    }
    Wipe(wire);
    std::string raw;
    const auto deadline = MonoClock::now() + std::chrono::seconds(10);
    while (raw.find("\r\n") == std::string::npos && raw.size() < 8192 && MonoClock::now() < deadline) {
        std::array<char, 2048> block{};
        size_t got = 0;
        if (!origin->Read(block.data(), block.size(), got, failure) || !got) break;
        raw.append(block.data(), got);
    }
    if (raw.size() >= 12 && raw.rfind("HTTP/1.", 0) == 0) {
        std::istringstream line(raw.substr(0, raw.find("\r\n")));
        std::string http, code;
        if ((line >> http >> code) && code.size() == 3 && code.find_first_not_of("0123456789") == std::string::npos) status = std::stoi(code);
    }
    Wipe(raw);
    const bool success = status >= 200 && status < 300;
    std::string outcome = success ? "upstream_http_2xx;application_receipt_requires_independent_verification"
        : status ? "upstream_http_" + std::to_string(status) : "tls_upstream_bad_status";
    RecordTransfer(session, actor, request, destination, outcome, success, ";tls_intercept");
    std::string response = "HTTP/1.1 " + std::to_string(status ? status : 502) + " Result\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    client->Write(response.data(), response.size(), error);
}
void HandleClient(UniqueFd client, Session& session) {
    Require(client && client->value >= 0, "missing client");
    SetCloexec(client->value);
    SetNoSigPipe(client->value);
    sockaddr_in peer{}; sockaddr_in local{};
    socklen_t peer_len = sizeof(peer), local_len = sizeof(local);
    Require(!getpeername(client->value, reinterpret_cast<sockaddr*>(&peer), &peer_len), "peer name failed");
    Require(!getsockname(client->value, reinterpret_cast<sockaddr*>(&local), &local_len), "local name failed");
    Require(peer.sin_family == AF_INET && local.sin_family == AF_INET, "unexpected address family");
    const auto client_port = ntohs(peer.sin_port);
    auto actor = session.Attribute(client_port);
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
    session.NoteFilesAndSockets(actor->process.node, session.LaunchedActor(*actor), actor->process.node.identity);
    if (request.method == "CONNECT") {
        ++session.opaque_tunnels;
        auto target = ParseHostPort(request.target);
        if (session.tls && target) {
            ++session.http_requests;
            WriteAll(client->value, "HTTP/1.1 200 Connection Established\r\n\r\n", std::chrono::seconds(5));
            InspectConnect(client->value, *actor, *target, session);
            Wipe(request.body);
            return;
        }
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
    stored.actor_identity = actor->process.node.identity;
    stored.launched_tree = session.LaunchedActor(*actor);
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
        std::string log, port_file, tls_cert, tls_key;
        std::vector<std::string> files;
        int duration = 0, sample_ms = 50, timeout_sec = 20;
        bool watch_live = false;
        std::vector<char*> command;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--launch") {
                Require(i + 1 < argc && std::string(argv[i + 1]) == "--", "usage: --launch -- command");
                ++i;
                for (int j = i + 1; j < argc; ++j) command.push_back(argv[j]);
                break;
            }
            if (arg == "--watch-live") { watch_live = true; continue; }
            Require(i + 1 < argc, "missing option value");
            const std::string value = argv[++i];
            if (arg == "--log") log = value;
            else if (arg == "--port-file") port_file = value;
            else if (arg == "--sensitive-file") files.push_back(value);
            else if (arg == "--duration") duration = std::stoi(value);
            else if (arg == "--sample-ms") sample_ms = std::stoi(value);
            else if (arg == "--timeout-sec") timeout_sec = std::stoi(value);
            else if (arg == "--tls-ca-cert") tls_cert = value;
            else if (arg == "--tls-ca-key") tls_key = value;
            else throw std::runtime_error("unknown option");
        }
        Require(!log.empty() && !files.empty() && files.size() <= 32, "usage: agent-egress --log PATH --sensitive-file PATH [--port-file PATH] [--duration SEC] [--sample-ms N] [--timeout-sec N] [--watch-live] [--tls-ca-cert PEM --tls-ca-key PEM] [--launch -- command]");
        // --watch-live with --duration 0 (the default) and no --launch command
        // stays up until SIGTERM so the installed app can supervise it.
        Require(tls_cert.empty() == tls_key.empty(), "tls intercept needs both a CA certificate and a CA key");
        Require(sample_ms >= 20 && sample_ms <= 1000, "sample-ms must be 20..1000");
        Require(timeout_sec >= 1 && timeout_sec <= 120, "timeout-sec must be 1..120");
        Require(duration >= 0 && duration <= 120, "duration must be 0..120");
        std::signal(SIGTERM, OnStop);
        std::signal(SIGINT, OnStop);
        std::signal(SIGPIPE, SIG_IGN);
        sigset_t unblock;
        sigemptyset(&unblock);
        sigaddset(&unblock, SIGTERM);
        sigaddset(&unblock, SIGINT);
        sigprocmask(SIG_UNBLOCK, &unblock, nullptr);
        EvidenceStore store(log, {});
        auto source = MakeDarwinProcessSource();
        Session session(store, *source);
        session.watch_live = watch_live;
        if (!tls_cert.empty()) session.tls = std::make_unique<TlsIntercept>(tls_cert, tls_key);
        for (const auto& file : files) {
            auto path = std::filesystem::weakly_canonical(std::filesystem::absolute(file)).string();
            Version version;
            version.path = path;
            version.bytes = ReadFile(path);
            version.sha256 = Sha256(version.bytes);
            version.lower_bound = ContentLowerBound(version.bytes);
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
        if (watch_live) session.SampleWatched();
        if (!port_file.empty()) {
            auto fd = OwnFd(::open(port_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600));
            Require(fd && fd->value >= 0, "port file failed");
            auto text = std::to_string(session.proxy_port) + "\n";
            Require(WriteAll(fd->value, text, std::chrono::seconds(2)), "port file write failed");
        }
        const std::string ready_basis = std::string(watch_live ? "live_agent_trees_and_" : "") +
            (session.tls ? "optional_tls_intercept_with_supplied_ca;" : "no_tls_interception;") +
            "not_system_wide;login_keychain_not_modified;mcp_config_not_modified";
        EvidenceRecord ready;
        ready.type = "egress_proxy_ready";
        ready.destination = "http://127.0.0.1:" + std::to_string(session.proxy_port);
        ready.evidence_basis = ready_basis;
        ready.summary = session.tls
            ? "本地出口代理已监听。可选的 TLS 检查使用调用方提供的 CA，不写入登录钥匙串，不修改 MCP 配置。证书固定、QUIC 和直连仍然看不到。"
            : "本地出口代理已监听。已经在运行的 Agent 不改道；能看全描述符和 TCP 发送字节数时按流量关联下结论，看不到只用于确实无法观察的情况。不修改 MCP 配置。";
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
            session.watched.push_back(Session::Root{root->identity, child.pid, true});
            session.launched = true;
            std::cerr << "egress child " << child.pid << "\n";
        }
        const auto started = MonoClock::now();
        // --watch-live and duration 0 keep the proxy up until SIGTERM even if a
        // --launch child is also running (required for the installed supervisor).
        const bool serve_until_signal = watch_live && duration == 0;
        const auto limit = command.empty() ? std::chrono::seconds(duration ? duration : 1) : std::chrono::seconds(timeout_sec);
        while (!stopping) {
            if (!serve_until_signal && MonoClock::now() - started >= limit) break;
            if (child.pid > 0 && child.Exited()) break;
            if (command.empty() && duration && MonoClock::now() - started >= std::chrono::seconds(duration)) break;
            pollfd pending{listener->value, POLLIN, 0};
            auto result = poll(&pending, 1, sample_ms);
            if (result < 0 && errno == EINTR) continue;
            Require(result >= 0, "poll failed");
            if (result > 0 && (pending.revents & POLLIN)) {
                auto accepted = accept(listener->value, nullptr, nullptr);
                if (accepted < 0) { if (errno == EINTR) continue; throw std::runtime_error("accept failed"); }
                try { HandleClient(OwnFd(accepted), session); }
                catch (const std::exception& error) {
                    std::cerr << "egress request failed: " << error.what() << "\n";
                }
            }
            session.SampleWatched();
            store.Check();
        }
            if (child.pid > 0) {
            for (const auto& root : session.watched) if (root.pid == child.pid) session.SampleTree(child.pid, root.identity, root.launched);
        }
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
