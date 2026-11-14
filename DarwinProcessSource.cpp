#include "ProcessCache.h"
#include "EgressVerdict.h"
#include <libproc.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdlib>
#include <atomic>
#include <deque>
#include <iostream>
#include <set>
#include <thread>
#include <utility>
#undef inp_faddr
#undef inp_laddr
#undef in6p_faddr
#undef in6p_laddr
#undef in6p_lport
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <array>
#include <cstring>
#include <filesystem>
#include <condition_variable>
#include <map>
#include <mutex>
#include <stdexcept>

namespace agentsec {
namespace {
std::optional<proc_bsdinfo> BsdInfo(pid_t pid) {
    proc_bsdinfo info{};
    if (pid <= 0 || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return std::nullopt;
    return info;
}
ProcessIdentity Identity(const proc_bsdinfo& info) {
    return {static_cast<pid_t>(info.pbi_pid), info.pbi_start_tvsec, info.pbi_start_tvusec};
}
std::string Executable(pid_t pid) {
    std::array<char, PROC_PIDPATHINFO_MAXSIZE> path{};
    if (proc_pidpath(pid, path.data(), static_cast<uint32_t>(path.size())) <= 0) return {};
    return {path.data(), strnlen(path.data(), path.size())};
}
bool Same(const ProcessNode& node, const proc_bsdinfo& info) {
    return node.identity == Identity(info);
}
std::string NormalizeAddress(bool v4, const char* text) {
    if (v4) return text;
    const std::string value(text);
    const std::string mapped = "::ffff:";
    if (value.rfind(mapped, 0) == 0) {
        const auto rest = value.substr(mapped.size());
        in_addr parsed{};
        if (inet_pton(AF_INET, rest.c_str(), &parsed) == 1) return rest;
    }
    return value;
}
std::string PeerText(bool v4, const std::string& address, uint16_t port) {
    if (v4 || address.find(':') == std::string::npos) return address + ":" + std::to_string(port);
    return "[" + address + "]:" + std::to_string(port);
}
// tcp_sockinfo has no cumulative send counter in the public SDK. The pcb list
// does: snd_max - iss is the sequence span for that connection (SYN plus data).
std::optional<uint64_t> TcpDataBytes(const std::string& flow_id) {
    struct Cache {
        std::mutex mu;
        MonoClock::time_point at{};
        std::map<std::string, uint64_t> bytes;
    };
    static Cache cache;
    std::lock_guard<std::mutex> lock(cache.mu);
    const auto now = MonoClock::now();
        if (cache.at.time_since_epoch().count() == 0 || now - cache.at > std::chrono::milliseconds(50)) {
        cache.at = now;
        cache.bytes.clear();
        size_t size = 0;
        const int probed = sysctlbyname("net.inet.tcp.pcblist64", nullptr, &size, nullptr, 0);
        if ((probed == 0 || errno == ENOMEM) && size > sizeof(xinpgen) && size < 8 * 1024 * 1024) {
            std::vector<char> buffer(size);
            if (sysctlbyname("net.inet.tcp.pcblist64", buffer.data(), &size, nullptr, 0) == 0 && size >= sizeof(xinpgen) && size <= buffer.size()) {
                auto* head = reinterpret_cast<xinpgen*>(buffer.data());
                if (head->xig_len >= sizeof(xinpgen) && head->xig_len < size) {
                    char* cursor = buffer.data() + head->xig_len;
                    char* end = buffer.data() + size;
                    while (cursor + sizeof(std::uint32_t) <= end) {
                        std::uint32_t record_len = 0;
                        std::memcpy(&record_len, cursor, sizeof(record_len));
                        if (record_len < sizeof(std::uint32_t) || cursor + record_len > end) break;
                        if (record_len >= sizeof(xtcpcb64)) {
                            xtcpcb64 record{};
                            std::memcpy(&record, cursor, sizeof(record));
                            const auto& inp = record.xt_inpcb;
                            const bool v4 = (inp.inp_vflag & INP_IPV4) != 0;
                            const void* local_addr = v4 ? static_cast<const void*>(&inp.inp_dependladdr.inp46_local.ia46_addr4)
                                                        : static_cast<const void*>(&inp.inp_dependladdr.inp6_local);
                            const void* foreign_addr = v4 ? static_cast<const void*>(&inp.inp_dependfaddr.inp46_foreign.ia46_addr4)
                                                          : static_cast<const void*>(&inp.inp_dependfaddr.inp6_foreign);
                            std::array<char, INET6_ADDRSTRLEN> local_text{};
                            std::array<char, INET6_ADDRSTRLEN> foreign_text{};
                            if (inet_ntop(v4 ? AF_INET : AF_INET6, local_addr, local_text.data(), local_text.size()) &&
                                inet_ntop(v4 ? AF_INET : AF_INET6, foreign_addr, foreign_text.data(), foreign_text.size())) {
                                const auto local_port = ntohs(inp.inp_lport);
                                const auto foreign_port = ntohs(inp.inp_fport);
                                const auto local_address = NormalizeAddress(v4, local_text.data());
                                const auto foreign_address = NormalizeAddress(v4, foreign_text.data());
                                const bool foreign_v4 = foreign_address.find(':') == std::string::npos;
                                const auto peer = PeerText(foreign_v4, foreign_address, foreign_port);
                                const auto span = static_cast<std::uint32_t>(record.snd_max - record.iss);
                                const auto data = span > 0 ? static_cast<uint64_t>(span - 1) : 0;
                                const auto exact = std::to_string(IPPROTO_TCP) + "|" + local_address + ":" + std::to_string(local_port) + "|" + peer;
                                const auto any_local = std::to_string(IPPROTO_TCP) + "|*:" + std::to_string(local_port) + "|" + peer;
                                cache.bytes[exact] = data;
                                cache.bytes[any_local] = std::max(cache.bytes[any_local], data);
                            }
                        }
                        cursor += record_len;
                    }
                }
            }
        }
    }
    auto found = cache.bytes.find(flow_id);
    if (found == cache.bytes.end()) {
        const auto first = flow_id.find('|');
        const auto second = first == std::string::npos ? std::string::npos : flow_id.find('|', first + 1);
        const auto colon = second == std::string::npos ? std::string::npos : flow_id.rfind(':', second);
        if (first != std::string::npos && second != std::string::npos && colon != std::string::npos && colon > first)
            found = cache.bytes.find(flow_id.substr(0, first + 1) + "*:" + flow_id.substr(colon + 1));
    }
    if (found == cache.bytes.end()) return std::nullopt;
    return found->second;
}
// Per-flow UDP/QUIC (and userland TCP) send counters from the same kernel
// control nettop uses. Private, version-sensitive, and optional: if the
// control socket cannot be opened, callers keep the previous unmeasured path.
std::string ProviderHostname(const uint8_t* data, size_t size) {
    std::string best;
    size_t index = 0;
    while (index < size) {
        const auto byte = data[index];
        if (byte < 0x21 || byte > 0x7e) { ++index; continue; }
        size_t end = index;
        while (end < size && data[end] >= 0x21 && data[end] <= 0x7e) ++end;
        if (end - index >= 4 && end - index <= 253 && std::memchr(data + index, '.', end - index)) {
            std::string token(reinterpret_cast<const char*>(data + index), end - index);
            while (!token.empty() && (token.back() == '.' || token.back() == ',')) token.pop_back();
            if (IsProviderOrRelay(token) && token.size() > best.size()) best = std::move(token);
        }
        index = end;
    }
    return best;
}
class PayloadHints {
public:
    struct Hint {
        std::string sni;
        bool tls_handshake = false;
        bool tls_app_data = false;
        bool http = false;
        uint64_t app_bytes = 0;
    };
    static PayloadHints& Shared() { static PayloadHints hints; return hints; }
    void Arm() {
        std::lock_guard<std::mutex> lock(mu_);
        if (started_) return;
        started_ = true;
        std::thread([this] { Loop(); }).detach();
    }
    Hint Lookup(const std::string& flow_id) const {
        const auto bar = flow_id.find('|');
        if (bar == std::string::npos) return {};
        const auto key = flow_id.substr(bar + 1);
        std::lock_guard<std::mutex> lock(mu_);
        auto found = hints_.find(key);
        if (found != hints_.end()) return found->second;
        const auto split = key.find('|');
        const auto colon = split == std::string::npos ? std::string::npos : key.rfind(':', split);
        if (colon == std::string::npos || split == std::string::npos) return {};
        found = hints_.find("*:" + key.substr(colon + 1));
        if (found != hints_.end()) return found->second;
        const auto remote = key.substr(split);
        found = hints_.find(std::string("*") + remote);
        return found == hints_.end() ? Hint{} : found->second;
    }
private:
    void Remember(const std::string& key, const Hint& hint) {
        if (key.empty()) return;
        auto& slot = hints_[key];
        if (slot.sni.empty()) slot.sni = hint.sni;
        slot.tls_handshake = slot.tls_handshake || hint.tls_handshake;
        slot.tls_app_data = slot.tls_app_data || hint.tls_app_data;
        slot.http = slot.http || hint.http;
        slot.app_bytes = std::max(slot.app_bytes, hint.app_bytes);
        if (hints_.size() > 4096) hints_.erase(hints_.begin());
    }
    static void ParseTls(const uint8_t* data, size_t size, Hint& hint) {
        const auto view = ClassifyTlsRecords(data, size);
        if (hint.sni.empty()) hint.sni = view.sni;
        hint.tls_handshake = hint.tls_handshake || view.saw_handshake;
        if (view.saw_app_data) {
            hint.tls_app_data = true;
            hint.app_bytes += view.app_bytes;
        }
    }
    void Ingest(const uint8_t* frame, size_t size, int dlt) {
        size_t offset = 0;
        if (dlt == DLT_EN10MB) {
            if (size < 14) return;
            unsigned eth = (static_cast<unsigned>(frame[12]) << 8) | frame[13];
            offset = 14;
            if (eth == 0x8100 && size >= 18) {
                eth = (static_cast<unsigned>(frame[16]) << 8) | frame[17];
                offset = 18;
            }
            if (eth != 0x0800) return;
        } else if (dlt != DLT_RAW && dlt != DLT_NULL) return;
        if (dlt == DLT_NULL) {
            if (size < 4) return;
            offset = 4;
        }
        if (offset + 20 > size) return;
        const auto header = static_cast<size_t>(frame[offset] & 0x0f) * 4;
        if (header < 20 || frame[offset + 9] != IPPROTO_TCP || offset + header + 20 > size) return;
        const uint8_t* tcp = frame + offset + header;
        const unsigned data_off = (static_cast<unsigned>(tcp[12] >> 4) & 0x0fu) * 4u;
        if (data_off < 20 || offset + header + data_off >= size) return;
        const uint8_t* payload = tcp + data_off;
        const size_t length = size - static_cast<size_t>(payload - frame);
        if (!length) return;
        Hint hint;
        if (length >= 5 && (std::memcmp(payload, "POST ", 5) == 0 || std::memcmp(payload, "HEAD ", 5) == 0)) hint.http = true;
        else if (length >= 4 && (std::memcmp(payload, "GET ", 4) == 0 || std::memcmp(payload, "PUT ", 4) == 0)) hint.http = true;
        else if (length >= 6 && std::memcmp(payload, "PATCH ", 6) == 0) hint.http = true;
        else if (payload[0] == 22 && payload[1] == 0x03) ParseTls(payload, length, hint);
        else return;
        char source_text[INET_ADDRSTRLEN];
        char dest_text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, frame + offset + 12, source_text, sizeof(source_text))) return;
        if (!inet_ntop(AF_INET, frame + offset + 16, dest_text, sizeof(dest_text))) return;
        const unsigned source_port = (static_cast<unsigned>(tcp[0]) << 8) | tcp[1];
        const unsigned dest_port = (static_cast<unsigned>(tcp[2]) << 8) | tcp[3];
        const auto local = std::string(source_text) + ":" + std::to_string(source_port);
        const auto remote = std::string(dest_text) + ":" + std::to_string(dest_port);
        std::lock_guard<std::mutex> lock(mu_);
        Remember(local + "|" + remote, hint);
        Remember("*:" + std::to_string(source_port) + "|" + remote, hint);
        Remember(std::string("*|") + remote, hint);
    }
    int OpenInterface(const std::string& name, int& dlt) {
        int fd = -1;
        for (int index = 0; index < 8 && fd < 0; ++index)
            fd = ::open(("/dev/bpf" + std::to_string(index)).c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        int length = 1 << 16;
        if (ioctl(fd, BIOCSBLEN, &length) < 0) { ::close(fd); return -1; }
        ifreq request{};
        std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, BIOCSETIF, &request) < 0) { ::close(fd); return -1; }
        u_int on = 1;
        ioctl(fd, BIOCIMMEDIATE, &on);
        ioctl(fd, BIOCGDLT, &dlt);
        if (dlt == DLT_EN10MB) {
            bpf_insn program[] = {
                BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0800, 0, 3),
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
                BPF_STMT(BPF_RET + BPF_K, 2048),
                BPF_STMT(BPF_RET + BPF_K, 0),
            };
            bpf_program filter{static_cast<u_int>(sizeof(program) / sizeof(program[0])), program};
            ioctl(fd, BIOCSETF, &filter);
        }
        return fd;
    }
    void Loop() {
        struct Device { int fd; int dlt; };
        std::vector<Device> devices;
        ifaddrs* interfaces = nullptr;
        if (getifaddrs(&interfaces) == 0) {
            std::set<std::string> used;
            for (auto* item = interfaces; item && devices.size() < 4; item = item->ifa_next) {
                if (!item->ifa_name || !item->ifa_addr || item->ifa_addr->sa_family != AF_INET) continue;
                const std::string name = item->ifa_name;
                if (!used.insert(name).second) continue;
                if (name == "lo0" || name.rfind("awdl", 0) == 0 || name.rfind("llw", 0) == 0 || name.rfind("utun", 0) == 0) continue;
                int dlt = 0;
                const int fd = OpenInterface(name, dlt);
                if (fd >= 0) devices.push_back({fd, dlt});
            }
            freeifaddrs(interfaces);
        }
        if (devices.empty()) {
            std::cerr << "egress payload capture unavailable\n";
            return;
        }
        std::vector<uint8_t> buffer(1 << 16);
        while (!stop_.load() && !devices.empty()) {
            pollfd waits[4]{};
            for (size_t index = 0; index < devices.size(); ++index) {
                waits[index].fd = devices[index].fd;
                waits[index].events = POLLIN;
            }
            if (::poll(waits, static_cast<nfds_t>(devices.size()), 200) <= 0) continue;
            for (size_t index = 0; index < devices.size(); ++index) {
                if (!(waits[index].revents & POLLIN)) continue;
                const auto count = ::read(devices[index].fd, buffer.data(), buffer.size());
                if (count <= 0) continue;
                size_t offset = 0;
                while (offset + sizeof(bpf_hdr) <= static_cast<size_t>(count)) {
                    const auto* header = reinterpret_cast<const bpf_hdr*>(buffer.data() + offset);
                    if (header->bh_hdrlen < sizeof(bpf_hdr) || offset + header->bh_hdrlen > static_cast<size_t>(count)) break;
                    const auto cap = static_cast<size_t>(header->bh_caplen);
                    if (offset + header->bh_hdrlen + cap > static_cast<size_t>(count)) break;
                    Ingest(buffer.data() + offset + header->bh_hdrlen, cap, devices[index].dlt);
                    const auto step = BPF_WORDALIGN(header->bh_hdrlen + header->bh_caplen);
                    if (!step) break;
                    offset += step;
                }
            }
        }
        for (const auto& device : devices) ::close(device.fd);
    }
    mutable std::mutex mu_;
    bool started_ = false;
    std::atomic<bool> stop_{false};
    std::map<std::string, Hint> hints_;
};
void ApplyPayloadHint(SocketFlow& flow) {
    if (flow.flow_id.empty()) return;
    const auto hint = PayloadHints::Shared().Lookup(flow.flow_id);
    if (flow.sni.empty() && !hint.sni.empty()) flow.sni = hint.sni;
    if (hint.tls_handshake) flow.tls_handshake = true;
    if (hint.tls_app_data) {
        flow.tls_app_data = true;
        flow.tls_app_bytes = std::max(flow.tls_app_bytes, hint.app_bytes);
    }
    if (hint.http) flow.plaintext_http = true;
}
class NetworkStatistics {
public:
    std::optional<uint64_t> Tx(const std::string& flow_id) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!running_.load()) Refresh();
        auto found = bytes_.find(flow_id);
        if (found == bytes_.end()) {
            const auto first = flow_id.find('|');
            const auto second = first == std::string::npos ? std::string::npos : flow_id.find('|', first + 1);
            const auto colon = second == std::string::npos ? std::string::npos : flow_id.rfind(':', second);
            if (first != std::string::npos && second != std::string::npos && colon != std::string::npos && colon > first)
                found = bytes_.find(flow_id.substr(0, first + 1) + "*:" + flow_id.substr(colon + 1));
        }
        if (found == bytes_.end()) return std::nullopt;
        return found->second;
    }
    std::vector<SocketFlow> FlowsFor(pid_t pid) const {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<SocketFlow> out;
        auto found = retained_.find(pid);
        if (found == retained_.end()) return out;
        for (const auto& item : found->second) out.push_back(item.second);
        return out;
    }
    std::vector<pid_t> TakeHot() {
        std::lock_guard<std::mutex> lock(mu_);
        std::vector<pid_t> out(hot_.begin(), hot_.end());
        hot_.clear();
        return out;
    }
    void Start() {
        std::call_once(start_, [this] { thread_ = std::thread([this] { Loop(); }); });
    }
    void RestoreHot(const std::vector<pid_t>& pids) {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto pid : pids) if (pid > 0) hot_.insert(pid);
    }
    void PollWatched() {
        std::lock_guard<std::mutex> lock(mu_);
        if (!Open()) return;
        Drain(20);
        Pump(64);
        Request(1004, ~uint64_t{0});
        Drain(20);
    }
    void Watch(pid_t pid) {
        if (pid <= 0) return;
        {
            std::lock_guard<std::mutex> lock(mu_);
            watch_.insert(pid);
            SubscribeLocked(pid);
        }
        Start();
        PayloadHints::Shared().Arm();
    }
    ~NetworkStatistics() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        if (fd_ >= 0) ::close(fd_);
    }
private:
    struct Source {
        uint32_t provider = 0;
        bool described = false;
        bool have_tx = false;
        uint64_t tx = 0;
        pid_t pid = 0;
        int tcp_state = -1;
        bool udp = false;
        bool loopback = false;
        std::string flow_id;
        std::string destination;
        std::string sni;
    };
    struct AddAll {
        uint64_t context;
        uint32_t type;
        uint16_t length;
        uint16_t flags;
        uint64_t filter;
        uint64_t events;
        uint32_t provider;
        int32_t target_pid;
        uint8_t uuid[16];
    };
    struct Query {
        uint64_t context;
        uint32_t type;
        uint16_t length;
        uint16_t flags;
        uint64_t srcref;
    };
    static uint32_t Read32(const uint8_t* data, size_t size, size_t offset) {
        if (offset + 4 > size) return 0;
        uint32_t value = 0;
        std::memcpy(&value, data + offset, 4);
        return value;
    }
    static uint64_t Read64(const uint8_t* data, size_t size, size_t offset) {
        if (offset + 8 > size) return 0;
        uint64_t value = 0;
        std::memcpy(&value, data + offset, 8);
        return value;
    }
    static bool Endpoint(const uint8_t* data, size_t size, size_t offset, bool peer, std::string& out) {
        if (offset + 28 > size) return false;
        const uint8_t family = data[offset + 1];
        uint16_t port_be = 0;
        std::memcpy(&port_be, data + offset + 2, 2);
        const auto port = ntohs(port_be);
        if (family == AF_INET) {
            char text[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, data + offset + 4, text, sizeof(text))) return false;
            if (std::strcmp(text, "0.0.0.0") == 0 && port == 0) return false;
            out = std::string(text) + ":" + std::to_string(port);
            return true;
        }
        if (family == AF_INET6) {
            char text[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, data + offset + 8, text, sizeof(text))) return false;
            if (std::strcmp(text, "::") == 0 && port == 0) return false;
            out = peer ? "[" + std::string(text) + "]:" + std::to_string(port)
                       : std::string(text) + ":" + std::to_string(port);
            return true;
        }
        return false;
    }
    static bool Describe(uint32_t provider, const uint8_t* data, size_t size, Source& source) {
        const bool tcp = provider == 2 || provider == 3 || provider == 8;
        const bool udp = provider == 4 || provider == 5;
        if (!tcp && !udp) return false;
        const size_t pid_off = tcp ? 116 : 128;
        const size_t local_off = tcp ? 124 : 56;
        const size_t remote_off = tcp ? 152 : 84;
        const size_t min_len = tcp ? 260 : 196;
        if (size < min_len) return false;
        const auto pid = Read32(data, size, pid_off);
        if (pid == 0 || pid >= 0x00400000) return false;
        std::string local, remote;
        if (!Endpoint(data, size, local_off, false, local) || !Endpoint(data, size, remote_off, true, remote)) return false;
        source.pid = static_cast<pid_t>(pid);
        source.udp = udp || provider == 8;
        source.tcp_state = tcp ? static_cast<int>(Read32(data, size, 76)) : -1;
        source.destination = remote;
        source.loopback = remote.rfind("127.", 0) == 0 || remote.rfind("[::1]:", 0) == 0 || remote.rfind("[::ffff:127.", 0) == 0;
        source.flow_id = std::to_string(source.udp ? IPPROTO_UDP : IPPROTO_TCP) + "|" + local + "|" + remote;
        source.described = true;
        source.provider = provider;
        if (source.sni.empty()) source.sni = ProviderHostname(data, size);
        return true;
    }
    static std::string Wildcard(const std::string& flow_id) {
        const auto first = flow_id.find('|');
        const auto second = first == std::string::npos ? std::string::npos : flow_id.find('|', first + 1);
        if (first == std::string::npos || second == std::string::npos) return {};
        const auto local = flow_id.substr(first + 1, second - first - 1);
        const auto colon = local.rfind(':');
        if (colon == std::string::npos) return {};
        return flow_id.substr(0, first + 1) + "*:" + local.substr(colon + 1) + flow_id.substr(second);
    }
    void Publish(const std::string& flow_id, uint64_t tx) {
        if (flow_id.empty()) return;
        bytes_[flow_id] = std::max(bytes_[flow_id], tx);
        const auto wildcard = Wildcard(flow_id);
        if (!wildcard.empty()) bytes_[wildcard] = std::max(bytes_[wildcard], tx);
        if (!announced_) {
            announced_ = true;
            std::cerr << "egress ntstat ready\n";
        }
    }
    bool Send(const void* data, size_t size) {
        if (fd_ < 0) return false;
        const auto wrote = ::send(fd_, data, size, 0);
        return wrote == static_cast<ssize_t>(size);
    }
    bool Open() {
        static_assert(sizeof(AddAll) == 56, "nstat add-all layout");
        static_assert(sizeof(Query) == 24, "nstat query layout");
        if (fd_ >= 0) return true;
        if (failed_) return false;
        if (const char* disabled = std::getenv("REINS_DISABLE_NTSTAT")) {
            if (disabled[0] == '1') { failed_ = true; std::cerr << "egress ntstat disabled\n"; return false; }
        }
        fd_ = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd_ < 0) { failed_ = true; std::cerr << "egress ntstat unavailable\n"; return false; }
        ctl_info info{};
        std::strncpy(info.ctl_name, "com.apple.network.statistics", sizeof(info.ctl_name) - 1);
        if (::ioctl(fd_, CTLIOCGINFO, &info) != 0) { ::close(fd_); fd_ = -1; failed_ = true; std::cerr << "egress ntstat unavailable\n"; return false; }
        sockaddr_ctl address{};
        address.sc_len = sizeof(address);
        address.sc_family = AF_SYSTEM;
        address.ss_sysaddr = AF_SYS_CONTROL;
        address.sc_id = info.ctl_id;
        address.sc_unit = 0;
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            ::close(fd_); fd_ = -1; failed_ = true; std::cerr << "egress ntstat unavailable\n"; return false;
        }
        const int buffer = 1 << 20;
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));
        const int flags = ::fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
        EnsureUdpSubscription();
        return true;
    }
    void EnsureUdpSubscription() {
        if (udp_subscribed_) return;
        udp_subscribed_ = true;
        constexpr uint64_t kFilter = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 |
            0x200000;
        // UDP has no pcb send counter. Subscribing to UDP only, not every TCP flow.
        for (const uint32_t provider : {4u, 5u}) {
            AddAll message{};
            message.context = 0x1000 + provider;
            message.type = 1002;
            message.length = sizeof(message);
            message.flags = 1;
            message.filter = kFilter;
            message.provider = provider;
            message.target_pid = -1;
            if (!Send(&message, sizeof(message))) { ::close(fd_); fd_ = -1; failed_ = true; udp_subscribed_ = false; std::cerr << "egress ntstat unavailable\n"; return; }
        }
    }
    void SubscribeLocked(pid_t pid) {
        if (pid <= 0 || !Open() || !subscribed_.insert(pid).second) return;
        if (SubscribeEveryProcessFlow()) pid = -1;
        constexpr uint64_t kFilter = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 |
            0x200000;
        for (const uint32_t provider : {2u, 3u, 8u}) {
            AddAll message{};
            message.context = 0x1000 + provider + static_cast<uint32_t>(pid);
            message.type = 1002;
            message.length = sizeof(message);
            message.flags = 1;
            message.filter = kFilter;
            message.provider = provider;
            message.target_pid = pid;
            if (!Send(&message, sizeof(message))) { ::close(fd_); fd_ = -1; failed_ = true; std::cerr << "egress ntstat unavailable\n"; return; }
        }
    }
    void Request(uint32_t type, uint64_t srcref) {
        Query message{};
        message.context = srcref == ~uint64_t{0} ? 0xC0 : srcref;
        message.type = type;
        message.length = sizeof(message);
        message.flags = 1;
        message.srcref = srcref;
        Send(&message, sizeof(message));
    }
    void Apply(const uint8_t* data, size_t size) {
        if (size < 16) return;
        const auto type = Read32(data, size, 8);
        if (type == 10001) {
            const auto srcref = Read64(data, size, 16);
            const auto provider = Read32(data, size, 24);
            if (srcref == 0 || sources_.count(srcref)) return;
            sources_[srcref].provider = provider;
            // Asking for every system flow in the same drain feeds the socket
            // as fast as we read it. Describe a bounded batch; the rest wait.
            const bool udp = provider == 4 || provider == 5;
            if (udp || query_budget_ > 0) {
                if (!udp && query_budget_ > 0) --query_budget_;
                Request(1005, srcref);
                Request(1004, srcref);
            } else if (pending_.size() < 128) pending_.push_back(srcref);
        } else if (type == 10002) {
            const auto srcref = Read64(data, size, 16);
            auto found = sources_.find(srcref);
            if (found == sources_.end()) return;
            Remember(found->second);
            sources_.erase(found);
        } else if (type == 10004) {
            const auto srcref = Read64(data, size, 16);
            auto found = sources_.find(srcref);
            if (found == sources_.end()) return;
            found->second.tx = Read64(data, size, 32 + 24);
            found->second.have_tx = true;
            const auto attempts = size >= 32 + 96 ? Read32(data, size, 32 + 92) : 0;
            const auto successes = size >= 32 + 100 ? Read32(data, size, 32 + 96) : 0;
            if (found->second.tcp_state < 0 && attempts > successes) found->second.tcp_state = 2;
            if (found->second.described) Remember(found->second);
        } else if (type == 10003) {
            const auto srcref = Read64(data, size, 16);
            const auto provider = Read32(data, size, 32);
            auto found = sources_.find(srcref);
            if (found == sources_.end() || size <= 40) return;
            if (!Describe(provider, data + 40, size - 40, found->second)) return;
            if (found->second.have_tx) Remember(found->second);
        } else if (type == 10006 && size > 152) {
            const auto srcref = Read64(data, size, 16);
            if (srcref == 0) return;
            auto& source = sources_[srcref];
            source.tx = Read64(data, size, 32 + 24);
            source.have_tx = true;
            const auto provider = Read32(data, size, 144);
            if (provider != 0) source.provider = provider;
            Describe(source.provider, data + 152, size - 152, source);
            Remember(source);
        }
    }
    void Remember(const Source& source) {
        if (source.pid <= 0 || source.flow_id.empty()) return;
        SocketFlow flow;
        flow.flow_id = source.flow_id;
        flow.destination = source.destination;
        flow.loopback = source.loopback;
        flow.udp = source.udp;
        flow.bytes_known = source.have_tx;
        flow.tx_bytes = source.tx;
        flow.tcp_state = source.tcp_state;
        flow.sni = source.sni;
        if (source.have_tx && !source.udp && source.tcp_state < 0 && source.tx > 0) flow.tcp_state = 4;
        auto& slot = retained_[source.pid][source.flow_id];
        const bool changed = slot.flow_id.empty() || (flow.bytes_known && flow.tx_bytes > slot.tx_bytes) ||
            (!source.sni.empty() && slot.sni.empty());
        if (slot.flow_id.empty()) slot = flow;
        else {
            if (flow.bytes_known) {
                slot.bytes_known = true;
                slot.tx_bytes = std::max(slot.tx_bytes, flow.tx_bytes);
            }
            if (flow.tcp_state >= 4) slot.tcp_state = flow.tcp_state;
            else if (slot.tcp_state < 0 && flow.tcp_state >= 0) slot.tcp_state = flow.tcp_state;
            if (flow.loopback) slot.loopback = true;
            slot.udp = flow.udp;
            if (!flow.destination.empty()) slot.destination = flow.destination;
        }
        if (source.have_tx) Publish(source.flow_id, source.tx);
        if (!source.sni.empty() && slot.sni.empty()) slot.sni = source.sni;
        ApplyPayloadHint(slot);
        if (changed && (watch_.count(source.pid) || hot_.size() < 64)) hot_.insert(source.pid);
        if (retained_[source.pid].size() > 64) retained_[source.pid].erase(retained_[source.pid].begin());
    }
    void Drain(int budget_ms) {
        const auto deadline = MonoClock::now() + std::chrono::milliseconds(budget_ms);
        std::array<uint8_t, 65536> buffer{};
        while (MonoClock::now() < deadline && fd_ >= 0) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - MonoClock::now()).count();
            pollfd wait{};
            wait.fd = fd_;
            wait.events = POLLIN;
            const int ready = ::poll(&wait, 1, static_cast<int>(std::max<int64_t>(left, 0)));
            if (ready <= 0) break;
            const auto count = ::recv(fd_, buffer.data(), buffer.size(), 0);
            if (count < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) continue;
                ::close(fd_); fd_ = -1; failed_ = true; std::cerr << "egress ntstat unavailable\n"; return;
            }
            if (count == 0) break;
            size_t offset = 0;
            while (offset + 16 <= static_cast<size_t>(count)) {
                uint16_t length = 0;
                std::memcpy(&length, buffer.data() + offset + 12, 2);
                if (length < 16 || offset + length > static_cast<size_t>(count)) break;
                Apply(buffer.data() + offset, length);
                offset += length;
            }
        }
    }
    void Pump(size_t batch) {
        size_t sent = 0;
        std::deque<uint64_t> again;
        while (sent < batch && !pending_.empty()) {
            const auto srcref = pending_.front();
            pending_.pop_front();
            auto found = sources_.find(srcref);
            if (found == sources_.end()) continue;
            if (!found->second.described) { Request(1005, srcref); ++sent; }
            if (!found->second.have_tx) { Request(1004, srcref); ++sent; }
            if (!found->second.described || !found->second.have_tx) again.push_back(srcref);
        }
        if (pending_.size() + again.size() < 256)
            for (const auto id : again) pending_.push_back(id);
    }
    void DrainNonblock() {
        if (fd_ < 0) return;
        std::array<uint8_t, 65536> buffer{};
        for (;;) {
            const auto count = ::recv(fd_, buffer.data(), buffer.size(), 0);
            if (count < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS) return;
                ::close(fd_); fd_ = -1; failed_ = true; std::cerr << "egress ntstat unavailable\n"; return;
            }
            if (count == 0) return;
            size_t offset = 0;
            while (offset + 16 <= static_cast<size_t>(count)) {
                uint16_t length = 0;
                std::memcpy(&length, buffer.data() + offset + 12, 2);
                if (length < 16 || offset + length > static_cast<size_t>(count)) break;
                Apply(buffer.data() + offset, length);
                offset += length;
            }
        }
    }
    std::vector<SocketFlow> Snapshot(pid_t pid) {
        std::vector<SocketFlow> flows;
        int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (needed <= 0) return flows;
        std::vector<proc_fdinfo> fds(static_cast<size_t>(needed) / sizeof(proc_fdinfo) + 8);
        int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
        if (got <= 0) return flows;
        const auto count = std::min(fds.size(), static_cast<size_t>(got) / sizeof(proc_fdinfo));
        for (size_t i = 0; i < count; ++i) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            socket_fdinfo socket{};
            if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != sizeof(socket)) continue;
            const auto& info = socket.psi;
            if (info.soi_family != AF_INET && info.soi_family != AF_INET6) continue;
            const in_sockinfo* in = nullptr;
            if (info.soi_kind == SOCKINFO_TCP) in = &info.soi_proto.pri_tcp.tcpsi_ini;
            else if (info.soi_kind == SOCKINFO_IN) in = &info.soi_proto.pri_in;
            if (!in || !in->insi_fport) continue;
            uint8_t foreign_raw[16] = {};
            uint8_t local_raw[16] = {};
            std::memcpy(foreign_raw, &in->insi_faddr, sizeof(foreign_raw));
            std::memcpy(local_raw, &in->insi_laddr, sizeof(local_raw));
            const bool v4_flag = (in->insi_vflag & INI_IPV4) != 0;
            const auto port = ntohs(static_cast<uint16_t>(in->insi_fport));
            const auto peer = FormatSocketPeer(v4_flag, foreign_raw, port);
            if (peer.empty()) continue;
            const auto local_port = ntohs(static_cast<uint16_t>(in->insi_lport));
            std::string local_id = "?:" + std::to_string(local_port);
            uint8_t local_v4[4];
            if (Ipv4PeerOctets(v4_flag, local_raw, local_v4)) {
                local_id = std::to_string(local_v4[0]) + "." + std::to_string(local_v4[1]) + "." +
                    std::to_string(local_v4[2]) + "." + std::to_string(local_v4[3]) + ":" + std::to_string(local_port);
            }
            SocketFlow flow;
            flow.destination = peer;
            flow.flow_id = std::to_string(info.soi_protocol) + "|" + local_id + "|" + peer;
            uint8_t v4[4];
            const bool ipv4 = Ipv4PeerOctets(v4_flag, foreign_raw, v4);
            flow.loopback = (ipv4 && v4[0] == 127) || (!ipv4 && (peer.rfind("[::1]:", 0) == 0 || peer.rfind("[::ffff:127.", 0) == 0));
            if (info.soi_kind == SOCKINFO_TCP) {
                flow.udp = false;
                flow.tcp_state = info.soi_proto.pri_tcp.tcpsi_state;
                if (auto sent = TcpDataBytes(flow.flow_id)) {
                    flow.bytes_known = true;
                    flow.tx_bytes = *sent;
                } else if (flow.tcp_state < 4) {
                    flow.bytes_known = true;
                    flow.tx_bytes = 0;
                }
            } else if (info.soi_protocol == IPPROTO_TCP || info.soi_protocol == 0) {
                flow.udp = false;
                flow.bytes_known = true;
                flow.tx_bytes = 0;
                flow.tcp_state = 0;
            } else if (info.soi_protocol == IPPROTO_UDP) {
                flow.udp = true;
                flow.tcp_state = -1;
            } else continue;
            flows.push_back(std::move(flow));
        }
        return flows;
    }
    void Loop() {
        running_.store(true);
        {
            std::lock_guard<std::mutex> lock(mu_);
            Open();
        }
        while (!stop_.load()) {
            int fd = -1;
            {
                std::lock_guard<std::mutex> lock(mu_);
                fd = fd_;
            }
            int ready = 0;
            if (fd >= 0) {
                pollfd wait{};
                wait.fd = fd;
                wait.events = POLLIN;
                ready = ::poll(&wait, 1, 200);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            if (stop_.load()) break;
            if (ready > 0) {
                std::lock_guard<std::mutex> lock(mu_);
                query_budget_ = 8;
                DrainNonblock();
                Pump(4);
            }
        }
    }
    void Refresh() {
        if (!Open()) return;
        const auto now = MonoClock::now();
        if (refreshed_.time_since_epoch().count() != 0 && now - refreshed_ < std::chrono::milliseconds(30)) return;
        refreshed_ = now;
        Pump(64);
        Request(1004, ~uint64_t{0});
        Drain(30);
        Pump(64);
        Drain(15);
    }
    mutable std::mutex mu_;
    int fd_ = -1;
    bool failed_ = false;
    bool announced_ = false;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
    std::once_flag start_;
    std::thread thread_;
    MonoClock::time_point refreshed_{};
    std::set<pid_t> watch_;
    std::set<pid_t> subscribed_;
    bool udp_subscribed_ = false;
    int query_budget_ = 0;
    std::map<uint64_t, Source> sources_;
    std::deque<uint64_t> pending_;
    std::map<std::string, uint64_t> bytes_;
    std::map<pid_t, std::map<std::string, SocketFlow>> retained_;
    std::set<pid_t> hot_;
};
NetworkStatistics& Ntstat() {
    static NetworkStatistics stats;
    return stats;
}
std::optional<uint64_t> NtstatTxBytes(const std::string& flow_id) { return Ntstat().Tx(flow_id); }
void ReadArguments(ProcessNode& node) {
    int max = 0; size_t size = sizeof(max); int max_mib[] = {CTL_KERN, KERN_ARGMAX};
    if (sysctl(max_mib, 2, &max, &size, nullptr, 0) || max <= 0 || max > 16 * 1024 * 1024) return;
    struct ScrubbedBuffer {
        explicit ScrubbedBuffer(size_t count) : bytes(count) {}
        ~ScrubbedBuffer() { for (char& byte : bytes) static_cast<volatile char&>(byte) = 0; }
        std::vector<char> bytes;
    } buffer(static_cast<size_t>(max));
    auto& data = buffer.bytes; size = data.size();
    int mib[] = {CTL_KERN, KERN_PROCARGS2, node.identity.pid};
    if (sysctl(mib, 3, data.data(), &size, nullptr, 0) || size < sizeof(int)) return;
    int argc = 0; std::memcpy(&argc, data.data(), sizeof(argc));
    if (argc <= 0 || static_cast<size_t>(argc) > size) return;
    size_t pos = sizeof(argc);
    while (pos < size && data[pos]) ++pos;
    while (pos < size && !data[pos]) ++pos;
    std::vector<std::string> arguments;
    // Retain only argv[0], entry point and an optional Python -m module.
    // Prompt text and environment data must not live in the process cache.
    for (int i = 0; i < argc && i < 3; ++i) {
        if (pos >= size) return;
        size_t begin = pos;
        while (pos < size && data[pos]) ++pos;
        if (pos == size) return;
        arguments.emplace_back(data.data() + begin, pos - begin); ++pos;
        if (i == 1 && arguments[1] != "-m") break;
    }
    node.arguments = std::move(arguments); node.arguments_available = true;
}
class DarwinProcessSource final : public IProcessSource {
    std::optional<ProcessNode> ReadNode(pid_t pid) const {
        auto before = BsdInfo(pid);
        if (!before) return std::nullopt;
        ProcessNode node;
        node.identity = Identity(*before); node.ppid = static_cast<pid_t>(before->pbi_ppid);
        node.name.assign(before->pbi_name, strnlen(before->pbi_name, sizeof(before->pbi_name)));
        node.executable = Executable(pid);
        if (node.executable.empty()) return std::nullopt;
        const auto base = std::filesystem::path(node.executable).filename().string();
        if (base == "node" || base == "bun" || base == "python" || base == "python3" || base.rfind("python3.", 0) == 0)
            ReadArguments(node);
        auto after = BsdInfo(pid);
        if (!after || !Same(node, *after) || static_cast<pid_t>(after->pbi_ppid) != node.ppid || Executable(pid) != node.executable)
            return std::nullopt;
        return node;
    }
public:
    ProcessSample Sample() override {
        int estimate = proc_listallpids(nullptr, 0);
        if (estimate <= 0) throw std::runtime_error("proc_listallpids sizing failed");
        std::vector<pid_t> pids(static_cast<size_t>(estimate) + 256);
        int count = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
            if (count <= 0) throw std::runtime_error("process enumeration failed");
            if (static_cast<size_t>(count) < pids.size()) break;
            if (attempt != 3) pids.resize(pids.size() * 2);
        }
        ProcessSample sample;
        sample.enumeration_complete = static_cast<size_t>(count) < pids.size();
        ++sample_generation_;
        std::set<pid_t> live;
        for (size_t i = 0; i < std::min(pids.size(), static_cast<size_t>(count)); ++i) {
            const auto pid = pids[i];
            if (pid <= 0) continue;
            live.insert(pid);
            auto cached = idle_nodes_.find(pid);
            // New pids are read in full so a short-lived process is not missed.
            // A stable pid is not queried on every 500 ms pass; one slice in
            // sixteen re-reads it, which is enough to notice exec and PID reuse.
            const bool refresh = cached == idle_nodes_.end() ||
                (sample_generation_ % 16) == (static_cast<uint32_t>(pid) % 16);
            if (!refresh) {
                cached->second.confirmed = sample_generation_;
                sample.processes.push_back(cached->second.node);
                continue;
            }
            auto info = BsdInfo(pid);
            if (!info) { ++sample.unavailable; continue; }
            const auto identity = Identity(*info);
            if (cached != idle_nodes_.end() && cached->second.node.identity == identity &&
                (sample_generation_ % 8) != (static_cast<uint32_t>(pid) % 8)) {
                cached->second.node.ppid = static_cast<pid_t>(info->pbi_ppid);
                cached->second.confirmed = sample_generation_;
                sample.processes.push_back(cached->second.node);
                continue;
            }
            if (auto node = ReadNode(pid)) {
                idle_nodes_[pid] = IdleNode{*node, sample_generation_};
                sample.processes.push_back(std::move(*node));
            } else ++sample.unavailable;
        }
        if ((sample_generation_ % 8) == 0) {
            for (auto it = idle_nodes_.begin(); it != idle_nodes_.end(); ) {
                if (!live.count(it->first)) it = idle_nodes_.erase(it);
                else ++it;
            }
        }
        return sample;
    }
    std::optional<ProcessNode> Lookup(pid_t pid) override { return ReadNode(pid); }
    bool ConfirmParentPid(const ProcessNode& node, pid_t ppid) override {
        auto before = BsdInfo(node.identity.pid);
        if (!before || !Same(node, *before) || static_cast<pid_t>(before->pbi_ppid) != ppid) return false;
        if (!node.executable.empty() && Executable(node.identity.pid) != node.executable) return false;
        auto after = BsdInfo(node.identity.pid);
        return after && Same(node, *after) && static_cast<pid_t>(after->pbi_ppid) == ppid;
    }
    bool Validate(const ProcessNode& node) override {
        auto cached = idle_nodes_.find(node.identity.pid);
        if (cached != idle_nodes_.end() && cached->second.confirmed == sample_generation_ &&
            cached->second.node.identity == node.identity && cached->second.node.executable == node.executable &&
            cached->second.node.arguments == node.arguments)
            return true;
        auto before = BsdInfo(node.identity.pid);
        if (!before || !Same(node, *before) || Executable(node.identity.pid) != node.executable) return false;
        auto after = BsdInfo(node.identity.pid);
        return after && Same(node, *after);
    }
    bool ValidateParent(const ProcessNode& child, const ProcessNode& parent) override {
        auto before = BsdInfo(child.identity.pid);
        if (!before || !Same(child, *before) || static_cast<pid_t>(before->pbi_ppid) != parent.identity.pid || !Validate(parent)) return false;
        auto after = BsdInfo(child.identity.pid);
        return after && Same(child, *after) && static_cast<pid_t>(after->pbi_ppid) == parent.identity.pid;
    }
    ActivitySample Inspect(const ProcessNode& node, const std::vector<std::string>& roots, bool include_idle_peers) override {
        ActivitySample result;
        const auto pid = node.identity.pid;
        int needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (needed <= 0) { result.descriptors_complete = false; return result; }
        std::vector<proc_fdinfo> fds(static_cast<size_t>(needed) / sizeof(proc_fdinfo) + 64);
        int got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
        if (got <= 0) { result.descriptors_complete = false; return result; }
        if (static_cast<size_t>(got) >= fds.size() * sizeof(proc_fdinfo)) result.descriptors_complete = false;
        std::vector<int> socket_fds;
        for (size_t i = 0; i < std::min(fds.size(), static_cast<size_t>(got) / sizeof(proc_fdinfo)); ++i) {
            const auto& fd = fds[i];
            if (fd.proc_fdtype == PROX_FDTYPE_VNODE) {
                vnode_fdinfowithpath vnode{};
                if (proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vnode, sizeof(vnode)) != sizeof(vnode)) {
                    result.descriptors_complete = false; continue;
                }
                std::string path(vnode.pvip.vip_path, strnlen(vnode.pvip.vip_path, sizeof(vnode.pvip.vip_path)));
                for (const auto& root : roots) if (IsWithin(path, root)) { result.sensitive_files.insert(path); break; }
            } else if (fd.proc_fdtype == PROX_FDTYPE_SOCKET) {
                socket_fds.push_back(fd.proc_fd);
            }
        }
        // Unknown software is always inspected for sensitive files. Only expand
        // peers when such a file is observed, or when a known candidate requests it.
        if (include_idle_peers || !result.sensitive_files.empty()) for (const int socket_fd : socket_fds) {
                socket_fdinfo socket{};
                if (proc_pidfdinfo(pid, socket_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != sizeof(socket)) {
                    result.descriptors_complete = false; continue;
                }
                const auto& s = socket.psi;
                if (s.soi_family != AF_INET && s.soi_family != AF_INET6) continue;
                const in_sockinfo* in = nullptr; // borrowed C API union member
                if (s.soi_kind == SOCKINFO_TCP) in = &s.soi_proto.pri_tcp.tcpsi_ini;
                else if (s.soi_kind == SOCKINFO_IN) in = &s.soi_proto.pri_in;
                if (!in || !in->insi_fport) continue;
                uint8_t foreign_raw[16] = {};
                uint8_t local_raw[16] = {};
                std::memcpy(foreign_raw, &in->insi_faddr, sizeof(foreign_raw));
                std::memcpy(local_raw, &in->insi_laddr, sizeof(local_raw));
                const bool v4_flag = (in->insi_vflag & INI_IPV4) != 0;
                const auto port = ntohs(static_cast<uint16_t>(in->insi_fport));
                const auto peer = FormatSocketPeer(v4_flag, foreign_raw, port);
                if (peer.empty()) continue;
                result.socket_peers.insert(peer + "/protocol=" + std::to_string(s.soi_protocol));
                SocketFlow flow;
                flow.destination = peer;
                uint8_t v4[4];
                const bool ipv4 = Ipv4PeerOctets(v4_flag, foreign_raw, v4);
                const auto local_port = ntohs(static_cast<uint16_t>(in->insi_lport));
                // The pcb table keys the local side as address:port, without brackets.
                std::string local_id = "?:" + std::to_string(local_port);
                uint8_t local_v4[4];
                if (Ipv4PeerOctets(v4_flag, local_raw, local_v4)) {
                    local_id = std::to_string(local_v4[0]) + "." + std::to_string(local_v4[1]) + "." +
                        std::to_string(local_v4[2]) + "." + std::to_string(local_v4[3]) + ":" + std::to_string(local_port);
                } else {
                    char local_text[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, local_raw, local_text, sizeof(local_text)))
                        local_id = std::string(local_text) + ":" + std::to_string(local_port);
                }
                flow.flow_id = std::to_string(s.soi_protocol) + "|" + local_id + "|" + peer;
                const bool v4_loop = ipv4 && v4[0] == 127;
                const bool v6_loop = !ipv4 && (peer.rfind("[::1]:", 0) == 0 || peer.rfind("[::ffff:127.", 0) == 0);
                flow.loopback = v4_loop || v6_loop;
                if (s.soi_kind == SOCKINFO_TCP) {
                    const auto& tcp = s.soi_proto.pri_tcp;
                    flow.udp = false;
                    flow.tcp_state = tcp.tcpsi_state;
                    if (auto sent = TcpDataBytes(flow.flow_id)) {
                        flow.bytes_known = true;
                        flow.tx_bytes = *sent;
                    } else if (tcp.tcpsi_state < 4) {
                        // SYN_SENT, SYN_RECEIVED, or CLOSED. The pcb list has no
                        // span because the connect never established.
                        flow.bytes_known = true;
                        flow.tx_bytes = 0;
                    } else if (auto sent = NtstatTxBytes(flow.flow_id)) {
                        // Userland TCP, including TLS that never entered the proxy.
                        flow.bytes_known = true;
                        flow.tx_bytes = *sent;
                    }
                } else if (s.soi_protocol == IPPROTO_TCP || s.soi_protocol == 0) {
                    // ECONNREFUSED and RST leave a TCP socket without a PCB.
                    // libproc reports SOCKINFO_IN. No sequence span exists, and
                    // the connect did not become established.
                    flow.udp = false;
                    flow.bytes_known = true;
                    flow.tx_bytes = 0;
                    flow.tcp_state = 0;
                } else {
                    flow.udp = s.soi_protocol == IPPROTO_UDP;
                    flow.tcp_state = -1;
                    if (flow.udp) {
                        if (auto sent = NtstatTxBytes(flow.flow_id)) {
                            flow.bytes_known = true;
                            flow.tx_bytes = *sent;
                        } else {
                            flow.bytes_known = false;
                        }
                    } else {
                        flow.bytes_known = false;
                    }
                }
                ApplyPayloadHint(flow);
                result.flows.push_back(std::move(flow));
        }
        return result;
    }
    struct IdleNode {
        ProcessNode node;
        uint32_t confirmed = 0;
    };
    std::map<pid_t, IdleNode> idle_nodes_;
    uint32_t sample_generation_ = 0;
    std::vector<SocketFlow> RetainedFlows(pid_t pid) const override { return Ntstat().FlowsFor(pid); }
    std::vector<pid_t> TakeHotPids() override { return Ntstat().TakeHot(); }
    void RestoreHotPids(const std::vector<pid_t>& pids) override { Ntstat().RestoreHot(pids); }
    void WatchFlows(pid_t pid) override { Ntstat().Watch(pid); }
    void PollFlowCounts() override { Ntstat().PollWatched(); }
    void StartFlowWatch() override {
        Ntstat().Start();
        PayloadHints::Shared().Arm();
    }
};
} // namespace
std::shared_ptr<IProcessSource> MakeDarwinProcessSource() { return std::make_shared<DarwinProcessSource>(); }
void AttachCapturedPayload(SocketFlow& flow) { ApplyPayloadHint(flow); }
bool IsWithin(const std::string& path, const std::string& root) noexcept {
    return path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && (root == "/" || path[root.size()] == '/'));
}
} // namespace agentsec
