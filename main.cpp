#include <CoreServices/CoreServices.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <climits>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <map>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cctype>
#include <arpa/inet.h>
#include <atomic>
#include <functional>
#include <dispatch/dispatch.h>

static std::string Json(const std::string& value) {
    std::ostringstream out; out << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c < 32) out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c) << std::dec;
        else out << c;
    }
    out << '"'; return out.str();
}
static long long NowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

struct ProcessNode {
    pid_t pid = 0, ppid = 0;
    uint64_t startSeconds = 0, startMicroseconds = 0;
    std::string name, executable;
    std::vector<std::string> arguments;
    bool argumentsAvailable = false;
};

class ProcessMonitor {
public:
    bool GetProcessInfo(pid_t pid, ProcessNode& node, bool readArguments = true) const {
        node = {};
        proc_bsdinfo info{};
        if (pid <= 0 || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return false;
        node.pid = pid; node.ppid = static_cast<pid_t>(info.pbi_ppid);
        node.startSeconds = info.pbi_start_tvsec; node.startMicroseconds = info.pbi_start_tvusec;
        node.name.assign(info.pbi_name, strnlen(info.pbi_name, sizeof(info.pbi_name)));
        if (node.name.empty()) node.name.assign(info.pbi_comm, strnlen(info.pbi_comm, sizeof(info.pbi_comm)));
        char path[PROC_PIDPATHINFO_MAXSIZE]{};
        if (proc_pidpath(pid, path, sizeof(path)) > 0) node.executable = path;
        if (readArguments) ReadArguments(pid, node);
        proc_bsdinfo after{};
        return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &after, sizeof(after)) == sizeof(after)
            && after.pbi_start_tvsec == info.pbi_start_tvsec
            && after.pbi_start_tvusec == info.pbi_start_tvusec;
    }
    std::vector<ProcessNode> Ancestors(pid_t pid) const {
        std::vector<ProcessNode> chain;
        std::set<pid_t> seen;
        while (pid > 0 && chain.size() < 128 && seen.insert(pid).second) {
            ProcessNode node;
            if (!GetProcessInfo(pid, node)) break;
            pid = node.ppid; chain.push_back(std::move(node));
        }
        return chain;
    }
    // Includes the process itself; exact case-sensitive basename matching.
    bool IsDescendantOf(pid_t pid, const std::vector<std::string>& names) const {
        for (const auto& node : Ancestors(pid))
            for (const auto& name : names)
                if (node.name == name || std::filesystem::path(node.executable).filename() == name) return true;
        return false;
    }
private:
    static void ReadArguments(pid_t pid, ProcessNode& node) {
        int argmax = 0; size_t size = sizeof(argmax);
        int maxMib[] = {CTL_KERN, KERN_ARGMAX};
        if (sysctl(maxMib, 2, &argmax, &size, nullptr, 0) != 0 || argmax <= 0) return;
        std::vector<char> buffer(static_cast<size_t>(argmax)); size = buffer.size();
        int mib[] = {CTL_KERN, KERN_PROCARGS2, pid};
        if (sysctl(mib, 3, buffer.data(), &size, nullptr, 0) != 0 || size < sizeof(int)) return;
        int argc = 0; std::memcpy(&argc, buffer.data(), sizeof(argc));
        if (argc < 0 || static_cast<size_t>(argc) > size) return;
        size_t pos = sizeof(argc);
        while (pos < size && buffer[pos] != '\0') ++pos;
        while (pos < size && buffer[pos] == '\0') ++pos;
        std::vector<std::string> args;
        for (int i = 0; i < argc; ++i) {
            if (pos >= size) return;
            const size_t begin = pos;
            while (pos < size && buffer[pos] != '\0') ++pos;
            if (pos == size) return;
            args.emplace_back(buffer.data() + begin, pos - begin); ++pos;
        }
        // Deliberately do not read the environment following argv.
        node.arguments = std::move(args); node.argumentsAvailable = true;
    }
};

// Bounded producer/consumer MVP. No writer PID
// is inferred: FSEvents supplies neither PID nor per-operation timestamps.
class FileMonitor {
public:
    void SetSink(std::function<void(const std::string&)> sink) { sink_ = std::move(sink); }
    explicit FileMonitor(const std::vector<std::filesystem::path>& paths) {
        for (const auto& path : paths)
            sensitive_.push_back(std::filesystem::weakly_canonical(std::filesystem::absolute(path)).string());
    }
    ~FileMonitor() {
        Stop();
        { std::lock_guard<std::mutex> lock(mutex_); closed_ = true; }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }
    FileMonitor(const FileMonitor&) = delete;
    FileMonitor& operator=(const FileMonitor&) = delete;
    void Start() {
        if (stream_) throw std::runtime_error("already started");
        CFMutableArrayRef roots = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        if (!roots) throw std::runtime_error("CFArray allocation failed");
        std::set<std::string> unique;
        try {
            for (const auto& path : sensitive_) {
                auto root = std::filesystem::path(path).parent_path();
                while (!std::filesystem::exists(root) && root != root.parent_path()) root = root.parent_path();
                unique.insert(root.string());
            }
            for (const auto& root : unique) {
                auto value = CFStringCreateWithFileSystemRepresentation(nullptr, root.c_str());
                if (!value) throw std::runtime_error("invalid watch path");
                CFArrayAppendValue(roots, value); CFRelease(value);
            }
        } catch (...) { CFRelease(roots); throw; }
        FSEventStreamContext context{0, this, nullptr, nullptr, nullptr};
        stream_ = FSEventStreamCreate(nullptr, &Callback, &context, roots,
            kFSEventStreamEventIdSinceNow, 0.1,
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot | kFSEventStreamCreateFlagNoDefer);
        CFRelease(roots);
        if (!stream_) throw std::runtime_error("FSEventStreamCreate failed");
        dispatch_ = dispatch_queue_create("agent.monitor.fsevents", DISPATCH_QUEUE_SERIAL);
        if (!dispatch_) { Stop(); throw std::runtime_error("dispatch queue allocation failed"); }
        FSEventStreamSetDispatchQueue(stream_, dispatch_);
        if (!FSEventStreamStart(stream_)) { Stop(); throw std::runtime_error("FSEventStreamStart failed"); }
        started_ = true;
        worker_ = std::thread([this] {
            try {
                for (;;) {
                    std::unique_lock<std::mutex> lock(mutex_);
                    cv_.wait(lock, [this] { return closed_ || !messages_.empty(); });
                    if (messages_.empty()) break;
                    auto message = std::move(messages_.front()); messages_.pop_front();
                    lock.unlock();
                    if (sink_) sink_(message);
                    else std::cout << message << std::endl;
                }
            } catch (...) { std::fputs("output worker failed\n", stderr); }
        });
    }
    void Stop() noexcept {
        if (!stream_) return;
        if (started_) FSEventStreamStop(stream_);
        FSEventStreamInvalidate(stream_); FSEventStreamRelease(stream_);
        stream_ = nullptr; started_ = false;
        if (dispatch_) {
            dispatch_sync_f(dispatch_, nullptr, [](void*) {});
            dispatch_release(dispatch_); dispatch_ = nullptr;
        }
    }
private:
    static void Callback(ConstFSEventStreamRef, void* context, size_t count, void* paths,
                         const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) noexcept {
        try {
            auto& self = *static_cast<FileMonitor*>(context);
            auto names = static_cast<char**>(paths);
            for (size_t i = 0; i < count; ++i) {
                constexpr auto gap = kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped |
                    kFSEventStreamEventFlagKernelDropped | kFSEventStreamEventFlagRootChanged | kFSEventStreamEventFlagEventIdsWrapped;
                if (flags[i] & gap) std::cerr << "WARNING: event gap/root change; rescan required, flags=" << flags[i] << '\n';
                if (!(flags[i] & (kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemCreated |
                                   kFSEventStreamEventFlagItemRenamed))) continue;
                const std::string path(names[i]);
                for (const auto& target : self.sensitive_) {
                    if (path == target || (path.size() > target.size() && path.compare(0, target.size(), target) == 0 && path[target.size()] == '/')) {
                        std::lock_guard<std::mutex> lock(self.mutex_);
                        if (self.messages_.size() == 4096) {
                            std::fputs("event queue full; notification dropped\n", stderr);
                            break;
                        }
                        self.messages_.push_back("检测到敏感文件变更，进程名: unknown, PID: unknown, 路径: " + path
                            + " event_id=" + std::to_string(ids[i]) + " flags=" + std::to_string(flags[i]));
                        self.cv_.notify_one();
                        break;
                    }
                }
            }
        } catch (...) { std::fputs("FSEvents callback failed; events may be lost\n", stderr); }
    }
    std::vector<std::string> sensitive_;
    FSEventStreamRef stream_ = nullptr;
    bool started_ = false;
    dispatch_queue_t dispatch_ = nullptr;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::string> messages_;
    bool closed_ = false;
    std::thread worker_;
    std::function<void(const std::string&)> sink_;
};
static volatile std::sig_atomic_t stopping = 0;
static void SignalHandler(int) { stopping = 1; }
int DemoMain(int argc, char* argv[]) {
    try {
        ProcessMonitor processes;
        if (argc == 3 && std::string(argv[1]) == "--pid") {
            size_t consumed = 0;
            const long value = std::stol(argv[2], &consumed);
            if (consumed != std::strlen(argv[2]) || value <= 0 || value > INT_MAX) throw std::runtime_error("invalid PID");
            const auto chain = processes.Ancestors(static_cast<pid_t>(value));
            if (chain.empty()) throw std::runtime_error("process unavailable or permission denied");
            for (const auto& p : chain) {
                std::cout << "PID=" << p.pid << " PPID=" << p.ppid << " executable=" << p.executable
                          << " argv_available=" << p.argumentsAvailable << '\n';
                for (const auto& arg : p.arguments) std::cout << "  argv: " << arg << '\n';
            }
            std::cout << "target lineage=" << processes.IsDescendantOf(static_cast<pid_t>(value), {"Cursor", "claude", "node", "Claude"}) << '\n';
            return 0;
        }
        std::vector<std::filesystem::path> paths;
        if (argc > 1) for (int i = 1; i < argc; ++i) paths.emplace_back(argv[i]);
        else {
            const char* home = std::getenv("HOME");
            if (!home) throw std::runtime_error("HOME unset; pass explicit watch paths");
            paths = {std::filesystem::path(home) / ".ssh", std::filesystem::path(home) / ".aws", std::filesystem::current_path() / ".env"};
        }
        FileMonitor monitor(paths);
        std::signal(SIGINT, SignalHandler); std::signal(SIGTERM, SignalHandler);
        monitor.Start();
        std::cout << "监控已启动；Ctrl-C 退出。FSEvents 不提供写入者 PID，也不监控纯读取。" << std::endl;
        while (!stopping) CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);
    } catch (const std::exception& e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
    return 0;
}

#include "Runtime.h"
