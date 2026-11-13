#include "SubtreeWatcher.h"
#include <sys/event.h>
#include <libproc.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <functional>
#include <filesystem>
#include <map>
#include <set>
#include <vector>

namespace agentsec {
namespace {
int ListChildren(pid_t pid, std::vector<pid_t>& children) {
    children.clear();
    int estimate = proc_listchildpids(pid, nullptr, 0);
    if (estimate < 0) return -1;
    children.resize(static_cast<size_t>(estimate) + 8);
    int count = proc_listchildpids(pid, children.data(), static_cast<int>(children.size() * sizeof(pid_t)));
    if (count < 0) return -1;
    if (static_cast<size_t>(count) > children.size()) count = static_cast<int>(children.size());
    children.resize(static_cast<size_t>(count));
    return count;
}
std::vector<std::string> SensitiveFiles(const std::vector<std::string>& roots) {
    std::vector<std::string> files;
    constexpr size_t kMax = 256;
    constexpr int kDepth = 5;
    std::function<void(const std::filesystem::path&, int)> walk;
    walk = [&](const std::filesystem::path& path, int depth) {
        if (files.size() >= kMax || depth > kDepth) return;
        std::error_code error;
        auto status = std::filesystem::symlink_status(path, error);
        if (error || std::filesystem::is_symlink(status)) return;
        if (std::filesystem::is_regular_file(status)) { files.push_back(path.string()); return; }
        if (!std::filesystem::is_directory(status)) return;
        std::filesystem::directory_iterator it(path, error), end;
        for (; !error && it != end; it.increment(error)) walk(it->path(), depth + 1);
    };
    for (const auto& root : roots) {
        if (files.size() >= kMax) break;
        std::error_code error;
        auto status = std::filesystem::symlink_status(root, error);
        if (error || std::filesystem::is_symlink(status)) continue;
        if (std::filesystem::is_regular_file(status)) files.push_back(root);
        else if (std::filesystem::is_directory(status)) walk(root, 0);
    }
    return files;
}
uint64_t AccessStamp(const struct stat& status) {
    return static_cast<uint64_t>(status.st_atimespec.tv_sec) * 1000000000ull + static_cast<uint64_t>(status.st_atimespec.tv_nsec);
}
} // namespace

SubtreeWatcher::SubtreeWatcher(std::shared_ptr<IProcessSource> source, std::vector<std::string> roots, AgentMonitor& monitor)
    : source_(std::move(source)), roots_(std::move(roots)), monitor_(monitor) {}
SubtreeWatcher::~SubtreeWatcher() { Stop(); }
void SubtreeWatcher::Start() {
    if (thread_.joinable() || stopping_) return;
    int pipes[2] = {-1, -1};
    if (::pipe(pipes)) return;
    ::fcntl(pipes[0], F_SETFL, O_NONBLOCK); ::fcntl(pipes[1], F_SETFL, O_NONBLOCK);
    ::fcntl(pipes[0], F_SETFD, FD_CLOEXEC); ::fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
    queue_ = ::kqueue();
    if (queue_ < 0) { ::close(pipes[0]); ::close(pipes[1]); return; }
    wake_ = pipes[1];
    struct kevent change{};
    EV_SET(&change, pipes[0], EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (::kevent(queue_, &change, 1, nullptr, 0, nullptr) < 0) {
        ::close(queue_); ::close(pipes[0]); ::close(pipes[1]); queue_ = wake_ = -1; return;
    }
    int read_end = pipes[0];
    thread_ = std::thread([this, read_end] {
        try {
        std::map<pid_t, ProcessIdentity> watching;
        std::set<pid_t> seen_children;
        std::map<std::string, uint64_t> atime;
        auto files = SensitiveFiles(roots_);
        auto files_refreshed = MonoClock::now();
        auto last_atime = MonoClock::now();
        while (!stopping_.load()) {
            std::vector<ProcessIdentity> focus;
            {
                std::lock_guard<std::mutex> lock(focus_mu_);
                focus = focus_;
            }
            std::vector<struct kevent> changes;
            std::set<pid_t> desired;
            for (const auto& identity : focus) desired.insert(identity.pid);
            for (const auto& pair : watching) if (!desired.count(pair.first) && !seen_children.count(pair.first)) {
                struct kevent remove{};
                EV_SET(&remove, pair.first, EVFILT_PROC, EV_DELETE, 0, 0, nullptr);
                changes.push_back(remove);
            }
            for (auto it = watching.begin(); it != watching.end();) {
                if (!desired.count(it->first) && !seen_children.count(it->first)) it = watching.erase(it);
                else ++it;
            }
            auto arm = [&](pid_t pid, const ProcessIdentity& identity) {
                if (watching.count(pid)) return;
                if (watching.size() >= 512) { ++dropped_; return; }
                struct kevent add{};
                EV_SET(&add, pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_CLEAR,
                    NOTE_FORK | NOTE_EXEC | NOTE_EXIT, 0, nullptr);
                if (::kevent(queue_, &add, 1, nullptr, 0, nullptr) == 0) watching.emplace(pid, identity);
            };
            for (const auto& identity : focus) arm(identity.pid, identity);
            struct kevent events[64];
            timespec timeout{0, 5 * 1000 * 1000};
            int ready = ::kevent(queue_, changes.empty() ? nullptr : changes.data(), static_cast<int>(changes.size()),
                events, 64, &timeout);
            if (ready < 0 && errno == EINTR) continue;
            const auto sweep_began = MonoClock::now();
            std::vector<pid_t> children;
            auto burst = [&](pid_t pid) {
                if (dropped_.load() > 100000) return;
                auto node = source_->Lookup(pid);
                if (!node) return;
                ++bursts_;
                std::set<std::string> hits;
                const auto window_begin = UnixMicros();
                const auto deadline = MonoClock::now() + std::chrono::milliseconds(25);
                do {
                    if (!source_->Validate(*node)) {
                        auto refreshed = source_->Lookup(pid);
                        if (!refreshed || refreshed->identity != node->identity) break;
                        node = *refreshed;
                    }
                    auto activity = source_->Inspect(*node, roots_, false);
                    auto after = source_->Lookup(pid);
                    if (!after || after->identity != node->identity) break;
                    if (after->executable != node->executable) { node = *after; continue; }
                    for (const auto& path : activity.sensitive_files) {
                        if (hits.insert(path).second) {
                            monitor_.ObserveSensitive(*node, path, "fd_observed");
                            ++fd_hits_;
                        }
                    }
                    if (!hits.empty() || ::kill(pid, 0) != 0) break;
                } while (MonoClock::now() < deadline);
                monitor_.NoteObservedDescendant(*node, window_begin, UnixMicros(), std::move(hits));
                if (auto current = source_->Lookup(pid)) {
                    arm(pid, current->identity);
                    seen_children.insert(pid);
                    if (seen_children.size() > 512) seen_children.erase(seen_children.begin());
                }
            };
            std::set<pid_t> parents;
            for (const auto& identity : focus) parents.insert(identity.pid);
            for (const auto& pair : watching) parents.insert(pair.first);
            for (pid_t parent : parents) {
                if (ListChildren(parent, children) < 0) continue;
                for (pid_t child : children) if (child > 0 && !watching.count(child)) burst(child);
            }
            for (int i = 0; i < ready; ++i) {
                if (events[i].filter == EVFILT_READ) {
                    char buffer[64]; while (::read(read_end, buffer, sizeof buffer) > 0) {}
                    continue;
                }
                if (events[i].filter != EVFILT_PROC) continue;
                const auto pid = static_cast<pid_t>(events[i].ident);
                if (events[i].fflags & NOTE_EXIT) {
                    watching.erase(pid); seen_children.erase(pid); continue;
                }
                if (events[i].fflags & NOTE_FORK) {
                    ++fork_notes_;
                    if (ListChildren(pid, children) >= 0)
                        for (pid_t child : children) if (child > 0 && !watching.count(child)) burst(child);
                }
                if (events[i].fflags & NOTE_EXEC) { ++exec_notes_; burst(pid); }
            }
            if (MonoClock::now() - files_refreshed > std::chrono::seconds(30)) {
                files = SensitiveFiles(roots_); files_refreshed = MonoClock::now();
            }
            if (MonoClock::now() - last_atime > std::chrono::seconds(1)) {
                const auto window_begin = UnixMicros() - 1000000;
                for (const auto& path : files) {
                    struct stat status{};
                    if (::lstat(path.c_str(), &status) || S_ISLNK(status.st_mode)) continue;
                    const auto stamp = AccessStamp(status);
                    auto prior = atime.find(path);
                    if (prior != atime.end() && stamp > prior->second) {
                        monitor_.NoteAccessTime(path, window_begin, UnixMicros());
                        ++atime_events_;
                    }
                    atime[path] = stamp;
                }
                last_atime = MonoClock::now();
            }
            sweep_us_.store(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(MonoClock::now() - sweep_began).count()));
            if (watching.size() > 512) ++dropped_;
        }
        } catch (...) {}
        ::close(read_end);
    });
}
void SubtreeWatcher::Stop() noexcept {
    stopping_.store(true);
    if (wake_ >= 0) { char byte = 1; ::write(wake_, &byte, 1); }
    if (thread_.joinable()) thread_.join();
    if (queue_ >= 0) { ::close(queue_); queue_ = -1; }
    if (wake_ >= 0) { ::close(wake_); wake_ = -1; }
}
void SubtreeWatcher::Focus(std::vector<ProcessIdentity> roots) {
    {
        std::lock_guard<std::mutex> lock(focus_mu_);
        focus_ = std::move(roots);
    }
    if (wake_ >= 0) { char byte = 1; ::write(wake_, &byte, 1); }
}
SubtreeWatcher::Stats SubtreeWatcher::GetStats() const {
    std::lock_guard<std::mutex> lock(focus_mu_);
    return {focus_.size(), bursts_.load(), fd_hits_.load(), fork_notes_.load(), exec_notes_.load(),
        dropped_.load(), atime_events_.load(), sweep_us_.load(), thread_.joinable() && !stopping_.load() ? 1ull : 0ull};
}
} // namespace agentsec
