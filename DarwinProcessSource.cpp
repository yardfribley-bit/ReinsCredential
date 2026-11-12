#include "ProcessCache.h"
#include <libproc.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
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
    if (cache.at.time_since_epoch().count() == 0 || now - cache.at > std::chrono::milliseconds(30)) {
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
                                const std::string peer = std::string(v4 ? "" : "[") + foreign_text.data() + (v4 ? ":" : "]:") + std::to_string(foreign_port);
                                const std::string key = std::to_string(IPPROTO_TCP) + "|" + local_text.data() + ":" + std::to_string(local_port) + "|" + peer;
                                const auto span = static_cast<std::uint32_t>(record.snd_max - record.iss);
                                cache.bytes[key] = span > 0 ? static_cast<uint64_t>(span - 1) : 0;
                            }
                        }
                        cursor += record_len;
                    }
                }
            }
        }
    }
    auto found = cache.bytes.find(flow_id);
    if (found == cache.bytes.end()) return std::nullopt;
    return found->second;
}
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
        for (size_t i = 0; i < std::min(pids.size(), static_cast<size_t>(count)); ++i) {
            if (pids[i] <= 0) continue;
            if (auto node = ReadNode(pids[i])) sample.processes.push_back(std::move(*node));
            else ++sample.unavailable;
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
                std::array<char, INET6_ADDRSTRLEN> address{};
                const bool ipv4 = in->insi_vflag & INI_IPV4;
                const void* raw = ipv4 ? static_cast<const void*>(&in->insi_faddr.ina_46.i46a_addr4) : static_cast<const void*>(&in->insi_faddr.ina_6);
                if (inet_ntop(ipv4 ? AF_INET : AF_INET6, raw, address.data(), static_cast<socklen_t>(address.size()))) {
                    const auto port = ntohs(static_cast<uint16_t>(in->insi_fport));
                    const auto peer = std::string(ipv4 ? "" : "[") + address.data() + (ipv4 ? ":" : "]:") + std::to_string(port);
                    result.socket_peers.insert(peer + "/protocol=" + std::to_string(s.soi_protocol));
                    SocketFlow flow;
                    flow.destination = peer;
                    std::array<char, INET6_ADDRSTRLEN> local_address{};
                    const void* local_raw = ipv4 ? static_cast<const void*>(&in->insi_laddr.ina_46.i46a_addr4)
                                                 : static_cast<const void*>(&in->insi_laddr.ina_6);
                    std::string local = "?";
                    if (inet_ntop(ipv4 ? AF_INET : AF_INET6, local_raw, local_address.data(), static_cast<socklen_t>(local_address.size())))
                        local = local_address.data();
                    flow.flow_id = std::to_string(s.soi_protocol) + "|" + local + ":" +
                        std::to_string(ntohs(static_cast<uint16_t>(in->insi_lport))) + "|" + peer;
                    const auto foreign = ipv4 ? ntohl(in->insi_faddr.ina_46.i46a_addr4.s_addr) : 0;
                    const bool v4_loop = ipv4 && (foreign >> 24) == 127;
                    const bool v6_loop = !ipv4 && peer.rfind("[::1]:", 0) == 0;
                    const bool v4_mapped_loop = !ipv4 && peer.rfind("[::ffff:127.", 0) == 0;
                    flow.loopback = v4_loop || v6_loop || v4_mapped_loop;
                    if (s.soi_kind == SOCKINFO_TCP) {
                        const auto& tcp = s.soi_proto.pri_tcp;
                        flow.udp = false;
                        flow.tcp_state = tcp.tcpsi_state;
                        if (auto sent = TcpDataBytes(flow.flow_id)) {
                            flow.bytes_known = true;
                            flow.tx_bytes = *sent;
                        }
                    } else {
                        flow.udp = s.soi_protocol == IPPROTO_UDP;
                        flow.bytes_known = false;
                        flow.tcp_state = -1;
                    }
                    result.flows.push_back(std::move(flow));
                }
        }
        return result;
    }
};
} // namespace
std::shared_ptr<IProcessSource> MakeDarwinProcessSource() { return std::make_shared<DarwinProcessSource>(); }
bool IsWithin(const std::string& path, const std::string& root) noexcept {
    return path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && (root == "/" || path[root.size()] == '/'));
}
} // namespace agentsec
