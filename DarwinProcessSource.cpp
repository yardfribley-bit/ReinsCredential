#include "ProcessCache.h"
#include <libproc.h>
#include <sys/sysctl.h>
#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
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
            auto before = BsdInfo(pids[i]);
            if (!before) { ++sample.unavailable; continue; }
            ProcessNode node;
            node.identity = Identity(*before); node.ppid = static_cast<pid_t>(before->pbi_ppid);
            node.name.assign(before->pbi_name, strnlen(before->pbi_name, sizeof(before->pbi_name)));
            node.executable = Executable(pids[i]);
            const auto base = std::filesystem::path(node.executable).filename().string();
            if (base == "node" || base == "bun" || base == "python" || base == "python3" || base.rfind("python3.", 0) == 0)
                ReadArguments(node);
            auto after = BsdInfo(pids[i]);
            if (!after || !Same(node, *after) || after->pbi_ppid != before->pbi_ppid ||
                node.executable.empty() || Executable(pids[i]) != node.executable) { ++sample.unavailable; continue; }
            sample.processes.push_back(std::move(node));
        }
        return sample;
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
                if (inet_ntop(ipv4 ? AF_INET : AF_INET6, raw, address.data(), static_cast<socklen_t>(address.size())))
                    result.socket_peers.insert(std::string(ipv4 ? "" : "[") + address.data() + (ipv4 ? ":" : "]:") +
                        std::to_string(ntohs(static_cast<uint16_t>(in->insi_fport))) + "/protocol=" + std::to_string(s.soi_protocol));
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
