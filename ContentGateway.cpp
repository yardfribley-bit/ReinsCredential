#include "AgentMonitor.h"
#include "ContentMatcher.h"
#include <bsm/libbsm.h>
#include <curl/curl.h>
#include <libproc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <array>
#include <algorithm>
#include <cctype>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {
using namespace agentsec;
constexpr size_t max_body = 1024 * 1024, max_header = 8192;
volatile std::sig_atomic_t stopping = 0;
void Stop(int) { stopping = 1; }
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::string ReadFile(const std::string& path) {
    auto fd = OwnFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    Require(fd->value >= 0, "cannot open registered file");
    struct stat st{};
    Require(!fstat(fd->value, &st) && S_ISREG(st.st_mode) && st.st_size >= 16 &&
        st.st_size <= static_cast<off_t>(max_body), "registered file must be regular, 16 bytes to 1 MiB");
    std::string bytes;
    std::array<char, 8192> block{};
    for (;;) {
        auto n = ::read(fd->value, block.data(), block.size());
        if (n < 0 && errno == EINTR) continue;
        Require(n >= 0, "file read failed");
        if (!n) break;
        Require(bytes.size() + static_cast<size_t>(n) <= max_body, "file grew beyond limit");
        bytes.append(block.data(), static_cast<size_t>(n));
    }
    return bytes;
}
struct Request { std::string method, path, body; };
Request ReadRequest(int fd) {
    const auto deadline = MonoClock::now() + std::chrono::seconds(5);
    std::string bytes;
    auto receive = [&] {
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
        Require(remaining > 0, "request deadline exceeded");
        pollfd item{fd, POLLIN, 0};
        int result;
        do { result = poll(&item, 1, static_cast<int>(remaining)); } while (result < 0 && errno == EINTR && !stopping);
        Require(result > 0, "request read timeout");
        std::array<char, 8192> block{};
        auto n = ::recv(fd, block.data(), block.size(), 0);
        Require(n > 0, "incomplete request");
        bytes.append(block.data(), static_cast<size_t>(n));
    };
    size_t end;
    while ((end = bytes.find("\r\n\r\n")) == std::string::npos) {
        Require(bytes.size() <= max_header, "headers too large"); receive();
    }
    Require(end <= max_header, "headers too large");
    std::istringstream headers(bytes.substr(0, end));
    std::string line, version, extra;
    std::getline(headers, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream first(line);
    Request request;
    Require(static_cast<bool>(first >> request.method >> request.path >> version) && !(first >> extra) &&
        version == "HTTP/1.1", "invalid request line");
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
            Require(!has_length, "duplicate content length"); has_length = true;
            auto value = line.substr(colon + 1);
            const auto start = value.find_first_not_of(" \t");
            Require(start != std::string::npos, "empty content length"); value.erase(0, start);
            Require(value.find_first_not_of("0123456789") == std::string::npos && value.size() <= 10, "invalid content length");
            length = std::stoull(value); Require(length <= max_body, "body too large");
        }
    }
    Require(request.method != "POST" || has_length, "POST requires content length");
    const auto offset = end + 4;
    while (bytes.size() - offset < length) receive();
    Require(bytes.size() - offset == length, "pipelined/trailing data rejected");
    request.body = bytes.substr(offset, length);
    return request;
}
void Respond(int fd, int code, const std::string& body) {
    auto bytes = "HTTP/1.1 " + std::to_string(code) + " Result\r\nContent-Type: application/octet-stream\r\nConnection: close\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    size_t sent = 0;
    const auto deadline = MonoClock::now() + std::chrono::seconds(5);
    while (sent < bytes.size()) {
        Require(MonoClock::now() < deadline, "response deadline exceeded");
        auto n = ::send(fd, bytes.data() + sent, bytes.size() - sent, 0);
        if (n < 0 && errno == EINTR) continue;
        Require(n > 0, "response send failed"); sent += static_cast<size_t>(n);
    }
}
std::optional<ActorProcess> Peer(int fd, ProcessCache& cache, IProcessSource& source) {
    audit_token_t token{}; socklen_t size = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) || size != sizeof(token)) return {};
    uid_t uid; gid_t gid;
    if (getpeereid(fd, &uid, &gid) || uid != geteuid()) return {};
    std::array<char, PROC_PIDPATHINFO_MAXSIZE> path{};
    if (proc_pidpath_audittoken(&token, path.data(), path.size()) <= 0) return {};
    const auto pid = audit_token_to_pid(token);
    cache.Refresh();
    auto view = cache.View(); auto current = view->current.find(pid);
    if (current == view->current.end()) return {};
    auto actor = view->Resolve(current->second);
    if (!actor || actor->process.node.executable != path.data() || !source.Validate(actor->process.node)) return {};
    if (proc_pidpath_audittoken(&token, path.data(), path.size()) <= 0 || actor->process.node.executable != path.data()) return {};
    auto reason = MatchAgent(actor->process.node, {});
    for (const auto& parent : actor->ancestors) if (reason.empty() && !MatchAgent(parent.node, {}).empty()) reason = "observed_ancestor";
    actor->classification = reason.empty() ? "unclassified_process" : "known_agent_candidate";
    actor->classification_reason = reason;
    return actor;
}
ProcessIdentity Scope(const ActorProcess& actor) {
    if (!MatchAgent(actor.process.node, {}).empty()) return actor.process.node.identity;
    for (const auto& parent : actor.ancestors) if (!MatchAgent(parent.node, {}).empty()) return parent.node.identity;
    return actor.process.node.identity;
}
struct CurlDelete { void operator()(CURL* p) const noexcept { curl_easy_cleanup(p); } };
struct HeadersDelete { void operator()(curl_slist* p) const noexcept { curl_slist_free_all(p); } };
struct CurlGlobal {
    CurlGlobal() { Require(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl initialization failed"); }
    ~CurlGlobal() { curl_global_cleanup(); }
};
struct ForwardResult { CURLcode code; long status = 0; std::string response; };
ForwardResult Forward(const std::string& url, const std::string& body) {
    std::unique_ptr<CURL, CurlDelete> curl(curl_easy_init());
    Require(static_cast<bool>(curl), "curl allocation failed");
    std::unique_ptr<curl_slist, HeadersDelete> headers(curl_slist_append(nullptr, "Content-Type: application/octet-stream"));
    Require(static_cast<bool>(headers), "curl header allocation failed");
    ForwardResult result{};
    auto set = [&](CURLoption option, auto value) { Require(curl_easy_setopt(curl.get(), option, value) == CURLE_OK, "curl option failed"); };
    set(CURLOPT_URL, url.c_str()); set(CURLOPT_HTTPHEADER, headers.get());
    set(CURLOPT_POSTFIELDS, body.data()); set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    set(CURLOPT_FOLLOWLOCATION, 0L); set(CURLOPT_CONNECTTIMEOUT_MS, 5000L); set(CURLOPT_TIMEOUT_MS, 15000L);
    set(CURLOPT_NOSIGNAL, 1L); set(CURLOPT_SSL_VERIFYPEER, 1L); set(CURLOPT_SSL_VERIFYHOST, 2L);
    set(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
    set(CURLOPT_WRITEFUNCTION, +[](char* data, size_t size, size_t count, void* context) noexcept -> size_t {
        if (size && count > max_body * 2 / size) return 0;
        auto& response = *static_cast<std::string*>(context);
        const auto length = size * count;
        if (response.size() + length > max_body * 2) return 0;
        try { response.append(data, length); return length; } catch (...) { return 0; }
    });
    set(CURLOPT_WRITEDATA, &result.response);
    result.code = curl_easy_perform(curl.get());
    Require(curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &result.status) == CURLE_OK, "curl status unavailable");
    return result;
}
struct SocketPath {
    std::string path; ino_t inode = 0;
    ~SocketPath() { struct stat st{}; if (inode && !lstat(path.c_str(), &st) && st.st_ino == inode && S_ISSOCK(st.st_mode)) unlink(path.c_str()); }
};
}
int main(int argc, char** argv) {
    using namespace agentsec;
    try {
        std::string socket_path, log, file, upstream;
        bool loopback = false;
        int correlation_seconds = 3600;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--allow-loopback-http") { loopback = true; continue; }
            Require(i + 1 < argc, "missing option value");
            std::string value = argv[++i];
            if (arg == "--socket") socket_path = value;
            else if (arg == "--log") log = value;
            else if (arg == "--sensitive-file") file = value;
            else if (arg == "--upstream") upstream = value;
            else if (arg == "--correlation-seconds") {
                Require(!value.empty() && value.find_first_not_of("0123456789") == std::string::npos && value.size() <= 5, "invalid correlation seconds");
                correlation_seconds = std::stoi(value);
                Require(correlation_seconds > 0 && correlation_seconds <= 86400, "correlation seconds must be 1..86400");
            }
            else throw std::runtime_error("unknown option");
        }
        Require(!socket_path.empty() && !log.empty() && !file.empty() && !upstream.empty(),
            "usage: agent-gateway --socket PATH --log PATH --sensitive-file PATH --upstream HTTPS_URL [--allow-loopback-http] [--correlation-seconds 1..86400]");
        // Fixed destination only. No client-supplied URLs, redirects, auth forwarding or TLS interception.
        Require(upstream.rfind("https://", 0) == 0 || (loopback && upstream.rfind("http://127.0.0.1:", 0) == 0), "HTTPS required except explicit loopback test");
        const auto authority_end = upstream.find('/', upstream.find("://") + 3);
        const auto authority = upstream.substr(upstream.find("://") + 3, authority_end - (upstream.find("://") + 3));
        Require(!authority.empty() && authority.find('@') == std::string::npos && upstream.find_first_of("\r\n?#") == std::string::npos, "URL credentials, query, fragments and controls forbidden");
        file = std::filesystem::absolute(file).lexically_normal().string();
        const auto sensitive = ReadFile(file), digest = Sha256(sensitive);
        auto parent = std::filesystem::path(socket_path).parent_path();
        struct stat st{};
        Require(!lstat(parent.c_str(), &st) && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 0777) == 0700,
            "socket parent must be an owned mode-0700 directory");
        sockaddr_un address{}; address.sun_family = AF_UNIX;
        Require(socket_path.size() < sizeof(address.sun_path), "socket path too long");
        std::memcpy(address.sun_path, socket_path.c_str(), socket_path.size() + 1);
        auto listener = OwnFd(::socket(AF_UNIX, SOCK_STREAM, 0));
        Require(listener->value >= 0, "socket creation failed");
        Require(!fcntl(listener->value, F_SETFD, FD_CLOEXEC), "socket cloexec failed");
        Require(!bind(listener->value, reinterpret_cast<sockaddr*>(&address), sizeof(address)), "socket bind failed; existing paths are never removed");
        SocketPath cleanup{socket_path, 0};
        Require(!lstat(socket_path.c_str(), &st), "socket stat failed"); cleanup.inode = st.st_ino;
        Require(!chmod(socket_path.c_str(), 0600) && !listen(listener->value, 16), "socket setup failed");
        EvidenceStore store(log, {});
        auto source = MakeDarwinProcessSource(); ProcessCache cache(source, {}); cache.Start();
        CurlGlobal curl_global;
        std::signal(SIGTERM, Stop); std::signal(SIGINT, Stop); std::signal(SIGPIPE, SIG_IGN);
        EvidenceRecord ready; ready.type = "gateway_ready"; ready.destination = upstream;
        ready.evidence_basis = "explicit_opt_in_gateway;not_system_wide_interception"; store.SubmitCritical(ready);
        struct Delivery { ProcessIdentity scope; std::string event; MonoClock::time_point time; };
        std::vector<Delivery> deliveries;
        while (!stopping) {
            pollfd pending{listener->value, POLLIN, 0};
            if (poll(&pending, 1, 200) <= 0) { store.Check(); cache.Check(); continue; }
            auto client = OwnFd(accept(listener->value, nullptr, nullptr));
            if (client->value < 0) { if (errno == EINTR) continue; throw std::runtime_error("accept failed"); }
            Require(!fcntl(client->value, F_SETFD, FD_CLOEXEC), "client cloexec failed");
            timeval timeout{5, 0}; Require(!setsockopt(client->value, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)), "socket timeout failed");
            EvidenceRecord record; record.event_id = NewUuid(); record.timestamp = UnixMicros(); record.correlation_id = NewUuid();
            try {
                record.actor_process = Peer(client->value, cache, *source);
                Require(static_cast<bool>(record.actor_process), "peer identity unavailable; request rejected");
                record.attribution = "kernel_audit_token_authenticated_connection_initiator";
                const auto request = ReadRequest(client->value);
                const auto after = Peer(client->value, cache, *source);
                Require(after && after->process.node.identity == record.actor_process->process.node.identity, "peer changed during request");
                const auto scope = Scope(*record.actor_process);
                deliveries.erase(std::remove_if(deliveries.begin(), deliveries.end(), [&](const auto& item) {
                    return MonoClock::now() - item.time > std::chrono::seconds(correlation_seconds);
                }), deliveries.end());
                if (request.method == "GET" && request.path == "/read" && request.body.empty()) {
                    auto bytes = ReadFile(file); Require(Sha256(bytes) == digest, "registered source version changed; restart gateway");
                    record.type = "sensitive_content_delivery_attempt"; record.target_resource = file;
                    record.content_sha256 = digest; record.count = bytes.size(); record.risk_level = RiskLevel::Medium;
                    record.destination = "unix-peer:" + std::to_string(record.actor_process->process.node.identity.pid);
                    record.evidence_basis = "gateway_read_registered_file_on_behalf_of_peer;not_native_peer_read";
                    store.SubmitDurable(record);
                    Respond(client->value, 200, bytes);
                    record.related_event_ids = {record.event_id}; record.event_id = NewUuid();
                    record.timestamp = UnixMicros();
                    record.type = "sensitive_content_delivered"; record.transfer_outcome = "written_to_local_socket;model_receipt_unproven";
                    store.SubmitCritical(record);
                    if (deliveries.size() == 256) deliveries.erase(deliveries.begin());
                    deliveries.push_back({scope, record.event_id, MonoClock::now()});
                } else if (request.method == "POST" && request.path == "/submit") {
                    const auto match = MatchContent(request.body, sensitive);
                    record.type = match.empty() ? "payload_observed" : "sensitive_payload_observed";
                    record.destination = upstream; record.content_sha256 = Sha256(request.body); record.count = request.body.size();
                    record.risk_level = match.empty() ? RiskLevel::Low : RiskLevel::High;
                    record.evidence_basis = match.empty() ? "no_registered_whole_version_match" : match;
                    if (!match.empty()) {
                        record.target_resource = file;
                        for (auto it = deliveries.rbegin(); it != deliveries.rend(); ++it) if (it->scope == scope) { record.related_event_ids.push_back(it->event); break; }
                        record.detail = "registered_content_version_sha256=" + digest + ";source_copy_origin_unproven";
                        if (!record.related_event_ids.empty()) record.detail += ";linked_by_same_observed_agent_scope_and_content_not_memory_taint";
                    }
                    // Fail closed until the admission record has been written and fsynced.
                    store.SubmitDurable(record);
                    const auto forwarded = Forward(upstream, request.body);
                    record.related_event_ids.push_back(record.event_id); record.event_id = NewUuid();
                    record.timestamp = UnixMicros();
                    record.type = "transfer_result";
                    record.metrics = {{"curl_code", static_cast<uint64_t>(forwarded.code)}, {"http_status", static_cast<uint64_t>(forwarded.status)}};
                    record.transfer_outcome = forwarded.code == CURLE_OK && forwarded.status >= 200 && forwarded.status < 300 ?
                        "upstream_http_2xx;application_receipt_requires_independent_verification" : "failed_or_non_2xx;partial_delivery_possible";
                    store.SubmitCritical(record);
                    Respond(client->value, forwarded.code == CURLE_OK ? static_cast<int>(forwarded.status ? forwarded.status : 502) : 502,
                        forwarded.code == CURLE_OK ? forwarded.response : "upstream transport failed\n");
                } else throw std::runtime_error("unsupported method/path");
            } catch (const std::exception& error) {
                record.event_id = NewUuid(); record.type = "gateway_request_failed"; record.detail = error.what();
                record.timestamp = UnixMicros();
                record.transfer_outcome = "request_failed;inspect_preceding_events"; store.SubmitCritical(record);
                try { Respond(client->value, 400, "request rejected\n"); } catch (...) {}
            }
            store.Check();
        }
        cache.Stop(); cache.Check(); store.Close();
        return 0;
    } catch (const std::exception& error) {
        EvidenceRecord record; record.event_id = NewUuid(); record.type = "gateway_fatal"; record.detail = error.what();
        std::cerr << ToJson(record, "gateway", 0) << '\n'; return 1;
    }
}
