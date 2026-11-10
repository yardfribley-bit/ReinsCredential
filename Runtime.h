#pragma once
// Included after the single-file MVP classes in main.cpp.
struct Options {
    int intervalMs = 500, durationSeconds = 0;
    bool includeRuntimes = false;
    std::string log;
    std::vector<std::string> extraNames;
    std::vector<std::filesystem::path> sensitive;
};
static std::string Identity(const ProcessNode& p) {
    return std::to_string(p.pid) + ":" + std::to_string(p.startSeconds) + ":" + std::to_string(p.startMicroseconds);
}
static std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
static std::string MatchAgent(const ProcessNode& p, const Options& options) {
    const auto base = Lower(std::filesystem::path(p.executable).filename().string());
    const auto path = Lower(p.executable);
    for (const auto& name : options.extraNames)
        if (base == Lower(name)) return "configured_name:" + name;
    for (const std::string name : {"claude", "codex", "cursor", "aider", "goose", "opencode", "gemini", "cline", "roo"})
        if (base == name) return "known_name:" + name;
    for (const std::string bundle : {"/cursor.app/", "/claude.app/", "/codex.app/", "/windsurf.app/", "/trae.app/"})
        if (path.find(bundle) != std::string::npos) return "application_bundle:" + bundle;
    // Match package entry points only, not arbitrary prompt strings in later argv.
    const bool runtime = base == "node" || base == "bun" || base == "python" || base == "python3" || base.rfind("python3.", 0) == 0;
    if (runtime && p.arguments.size() > 1) {
        const auto entry = Lower(p.arguments[1]);
        for (const std::string package : {"/@anthropic-ai/claude-code/", "/@openai/codex/", "/@google/gemini-cli/", "/@sourcegraph/amp/", "/opencode-ai/"})
            if (entry.find(package) != std::string::npos) return "package_entrypoint:" + package;
        if (p.arguments.size() > 2 && entry == "-m" && (p.arguments[2] == "aider" || p.arguments[2] == "aider.main")) return "python_module:aider";
    }
    if (runtime && options.includeRuntimes) return "generic_runtime_candidate";
    return {};
}
class EvidenceWriter {
public:
    explicit EvidenceWriter(const std::string& path) {
        if (!path.empty()) {
            file_.open(path, std::ios::app);
            if (!file_) throw std::runtime_error("cannot open append log: " + path);
        }
        worker_ = std::thread([this] { Run(); });
    }
    ~EvidenceWriter() {
        { std::lock_guard<std::mutex> lock(mutex_); closed_ = true; }
        cv_.notify_one(); worker_.join();
    }
    void Emit(std::string line) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= 4096) { ++dropped_; return; }
        queue_.push_back(std::move(line)); cv_.notify_one();
    }
    bool Failed() const { return failed_.load(); }
private:
    void Run() noexcept {
        try {
            for (;;) {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return closed_ || !queue_.empty(); });
                if (queue_.empty()) break;
                auto line = std::move(queue_.front()); queue_.pop_front(); lock.unlock();
                std::cout << line << '\n'; std::cout.flush();
                if (file_.is_open()) { file_ << line << '\n'; file_.flush(); if (!file_) failed_ = true; }
                if (!std::cout) failed_ = true;
            }
            if (dropped_) std::cerr << "WARNING: evidence queue dropped " << dropped_ << " records\n";
        } catch (...) { failed_ = true; }
    }
    std::ofstream file_;
    std::mutex mutex_; std::condition_variable cv_; std::deque<std::string> queue_;
    bool closed_ = false; std::atomic<bool> failed_{false};
    std::atomic<uint64_t> dropped_{0}; std::thread worker_;
};
struct ObservedAgent {
    ProcessNode node;
    std::string reason, root;
    std::set<std::string> observations;
};
class AgentRuntime {
public:
    AgentRuntime(Options options, EvidenceWriter& writer) : options_(std::move(options)), writer_(writer) {
        for (const auto& p : options_.sensitive)
            paths_.push_back(std::filesystem::weakly_canonical(std::filesystem::absolute(p)).string());
    }
    void Poll() {
        const auto scanStarted = std::chrono::steady_clock::now();
        const int estimate = proc_listallpids(nullptr, 0);
        if (estimate <= 0) throw std::runtime_error("proc_listallpids failed");
        std::vector<pid_t> pids(static_cast<size_t>(estimate) + 256);
        int count = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
        if (count <= 0) throw std::runtime_error("process enumeration failed");
        bool truncated = static_cast<size_t>(count) >= pids.size();
        std::map<pid_t, ProcessNode> snapshot;
        size_t unavailable = 0;
        for (size_t i = 0; i < std::min(pids.size(), static_cast<size_t>(count)); ++i) {
            if (pids[i] <= 0 || pids[i] == getpid()) continue;
            ProcessNode node;
            if (!monitor_.GetProcessInfo(pids[i], node, false)) { ++unavailable; continue; }
            const auto base = Lower(std::filesystem::path(node.executable).filename().string());
            if (base == "node" || base == "bun" || base == "python" || base == "python3" || base.rfind("python3.", 0) == 0) {
                ProcessNode detailed;
                if (monitor_.GetProcessInfo(node.pid, detailed)) node = std::move(detailed);
            }
            snapshot.emplace(node.pid, std::move(node));
        }
        std::map<std::string, ObservedAgent> next;
        for (const auto& pair : snapshot) {
            const auto& node = pair.second;
            const auto id = Identity(node);
            std::string reason = MatchAgent(node, options_), root = id;
            // Previously observed attribution survives parent exit/reparenting.
            auto prior = agents_.find(id);
            if (reason.empty() && prior != agents_.end()) { reason = prior->second.reason; root = prior->second.root; }
            std::set<pid_t> seen;
            pid_t parent = node.ppid;
            for (size_t depth = 0; reason.empty() && depth < 128 && parent > 0 && seen.insert(parent).second; ++depth) {
                auto found = snapshot.find(parent);
                if (found == snapshot.end()) break;
                const auto& ancestor = found->second;
                // A parent cannot have started after its child (PID reuse guard).
                if (std::make_pair(ancestor.startSeconds, ancestor.startMicroseconds) > std::make_pair(node.startSeconds, node.startMicroseconds)) break;
                auto known = agents_.find(Identity(ancestor));
                if (!MatchAgent(ancestor, options_).empty()) { reason = "observed_ancestor"; root = Identity(ancestor); }
                else if (known != agents_.end()) { reason = "observed_ancestor"; root = known->second.root; }
                parent = ancestor.ppid;
            }
            if (reason.empty()) continue;
            ObservedAgent current{node, reason, root, {}};
            if (prior == agents_.end()) Emit("agent_discovered", current, "heuristic_identity");
            else if (prior->second.node.executable != node.executable || prior->second.reason != reason)
                Emit("agent_changed", current, "snapshot_change");
            Inspect(current);
            for (const auto& observation : current.observations)
                if (prior == agents_.end() || !prior->second.observations.count(observation))
                    Emit("activity_observed", current, observation);
            next.emplace(id, std::move(current));
        }
        for (const auto& pair : agents_)
            if (!next.count(pair.first)) Emit("agent_no_longer_observed", pair.second, "exit_or_visibility_loss");
        agents_ = std::move(next);
        if (++polls_ == 1 || polls_ % 20 == 0)
            writer_.Emit("{\"type\":\"coverage\",\"observed_unix_ms\":" + std::to_string(NowMs()) +
                ",\"visible_processes\":" + std::to_string(snapshot.size()) + ",\"unavailable_processes\":" + std::to_string(unavailable) +
                ",\"enumeration_maybe_truncated\":" + (truncated ? "true" : "false") + ",\"tracked_candidates\":" + std::to_string(agents_.size()) +
                ",\"scan_duration_ms\":" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - scanStarted).count()) + "}");
    }
private:
    bool Sensitive(const std::string& path) const {
        for (const auto& root : paths_)
            if (path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && path[root.size()] == '/')) return true;
        return false;
    }
    void Inspect(ObservedAgent& agent) {
        int needed = proc_pidinfo(agent.node.pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (needed <= 0) { agent.observations.insert("fd_visibility_unavailable"); return; }
        std::vector<proc_fdinfo> fds(static_cast<size_t>(needed) / sizeof(proc_fdinfo) + 64);
        int got = proc_pidinfo(agent.node.pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
        if (got <= 0) { agent.observations.insert("fd_visibility_unavailable"); return; }
        for (size_t i = 0; i < static_cast<size_t>(got) / sizeof(proc_fdinfo) && i < fds.size(); ++i) {
            const auto& fd = fds[i];
            if (fd.proc_fdtype == PROX_FDTYPE_VNODE) {
                vnode_fdinfowithpath vnode{};
                if (proc_pidfdinfo(agent.node.pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vnode, sizeof(vnode)) != sizeof(vnode)) continue;
                std::string path(vnode.pvip.vip_path, strnlen(vnode.pvip.vip_path, sizeof(vnode.pvip.vip_path)));
                if (Sensitive(path)) agent.observations.insert("sensitive_file_open:" + path);
            } else if (fd.proc_fdtype == PROX_FDTYPE_SOCKET) {
                socket_fdinfo socket{};
                if (proc_pidfdinfo(agent.node.pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &socket, sizeof(socket)) != sizeof(socket)) continue;
                const auto& s = socket.psi;
                if (s.soi_family != AF_INET && s.soi_family != AF_INET6) continue;
                const in_sockinfo* in = nullptr;
                if (s.soi_kind == SOCKINFO_TCP) in = &s.soi_proto.pri_tcp.tcpsi_ini;
                else if (s.soi_kind == SOCKINFO_IN) in = &s.soi_proto.pri_in;
                if (!in || !in->insi_fport) continue;
                char address[INET6_ADDRSTRLEN]{};
                const bool ipv4 = in->insi_vflag & INI_IPV4;
                const void* addr = ipv4 ? static_cast<const void*>(&in->insi_faddr.ina_46.i46a_addr4) : static_cast<const void*>(&in->insi_faddr.ina_6);
                if (!inet_ntop(ipv4 ? AF_INET : AF_INET6, addr, address, sizeof(address))) continue;
                agent.observations.insert("socket_peer:" + std::string(address) + ":" + std::to_string(ntohs(static_cast<uint16_t>(in->insi_fport))) + ":protocol=" + std::to_string(s.soi_protocol));
            }
        }
        ProcessNode after;
        if (!monitor_.GetProcessInfo(agent.node.pid, after, false) || Identity(after) != Identity(agent.node)) {
            agent.observations.clear(); agent.observations.insert("process_changed_during_fd_scan");
        }
        bool file = false, network = false;
        for (const auto& s : agent.observations) {
            file |= s.rfind("sensitive_file_open:", 0) == 0;
            network |= s.rfind("socket_peer:", 0) == 0;
        }
        if (file && network) agent.observations.insert("risk_signal:file_and_socket_coobserved;upload_unproven");
    }
    void Emit(const std::string& type, const ObservedAgent& a, const std::string& detail) {
        writer_.Emit("{\"type\":" + Json(type) + ",\"observed_unix_ms\":" + std::to_string(NowMs()) +
            ",\"process_identity\":" + Json(Identity(a.node)) + ",\"pid\":" + std::to_string(a.node.pid) +
            ",\"ppid\":" + std::to_string(a.node.ppid) + ",\"executable\":" + Json(a.node.executable) +
            ",\"reason\":" + Json(a.reason) + ",\"root_identity\":" + Json(a.root) +
            ",\"argv_available\":" + (a.node.argumentsAvailable ? "true" : "false") + ",\"detail\":" + Json(detail) + "}");
    }
    Options options_; EvidenceWriter& writer_; ProcessMonitor monitor_;
    std::vector<std::string> paths_; std::map<std::string, ObservedAgent> agents_; size_t polls_ = 0;
};

static int PositiveInt(const std::string& text) {
    size_t pos = 0; long value = std::stol(text, &pos);
    if (pos != text.size() || value <= 0 || value > 86400000) throw std::runtime_error("invalid positive integer: " + text);
    return static_cast<int>(value);
}
int main(int argc, char* argv[]) {
    if (argc >= 2 && std::string(argv[1]) == "--pid") return DemoMain(argc, argv);
    try {
        Options options;
        const char* home = std::getenv("HOME");
        if (home) options.sensitive = {std::filesystem::path(home) / ".ssh", std::filesystem::path(home) / ".aws"};
        options.sensitive.push_back(std::filesystem::current_path() / ".env");
        for (int i = 1; i < argc; ++i) {
            std::string option = argv[i];
            if (option == "--help") {
                std::cout << "Usage: agent-monitor [--interval-ms N] [--duration N] [--match BASENAME] [--include-runtimes] [--sensitive PATH] [--log PATH]\n       agent-monitor --pid PID\n";
                return 0;
            }
            if (option == "--include-runtimes") { options.includeRuntimes = true; continue; }
            if (i + 1 >= argc) throw std::runtime_error("missing option value: " + option);
            std::string value = argv[++i];
            if (option == "--interval-ms") options.intervalMs = PositiveInt(value);
            else if (option == "--duration") options.durationSeconds = PositiveInt(value);
            else if (option == "--match") options.extraNames.push_back(value);
            else if (option == "--sensitive") options.sensitive.emplace_back(value);
            else if (option == "--log") options.log = value;
            else throw std::runtime_error("unknown option: " + option);
        }
        if (options.intervalMs < 50) throw std::runtime_error("minimum polling interval is 50 ms");
        EvidenceWriter writer(options.log);
        AgentRuntime runtime(options, writer);
        FileMonitor files(options.sensitive);
        files.SetSink([&writer](const std::string& detail) {
            writer.Emit("{\"type\":\"filesystem_change\",\"observed_unix_ms\":" + std::to_string(NowMs()) +
                ",\"actor_pid\":null,\"detail\":" + Json(detail) + "}");
        });
        files.Start();
        std::signal(SIGINT, SignalHandler); std::signal(SIGTERM, SignalHandler);
        const auto begin = std::chrono::steady_clock::now(); auto next = begin;
        std::cerr << "Agent candidate monitor started; polling is best effort, upload content is not observable.\n";
        while (!stopping) {
            const auto now = std::chrono::steady_clock::now();
            if (options.durationSeconds && now - begin >= std::chrono::seconds(options.durationSeconds)) break;
            if (now >= next) { runtime.Poll(); next = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.intervalMs); }
            if (writer.Failed()) throw std::runtime_error("evidence output failed");
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
        }
        files.Stop();
    } catch (const std::exception& e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
    return 0;
}
