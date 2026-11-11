#include "FileMonitor.h"
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <poll.h>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

namespace {
void Require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
struct TemporaryDirectory {
    TemporaryDirectory() {
        std::string pattern = (std::filesystem::temp_directory_path() / "agentsec-shutdown-XXXXXX").string();
        Require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path = std::filesystem::canonical(pattern);
    }
    ~TemporaryDirectory() { std::error_code ignored; std::filesystem::remove_all(path, ignored); }
    std::filesystem::path path;
};
struct Child {
    explicit Child(pid_t value) : pid(value) {}
    ~Child() {
        if (pid <= 0) return;
        ::kill(pid, SIGKILL);
        while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
    }
    void Wait() {
        int status = 0; pid_t result;
        do { result = ::waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
        Require(result == pid, "waitpid failed"); pid = -1;
        Require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "writer child failed");
    }
    pid_t pid;
};
std::string ReadFile(const std::string& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
void Command(int write_fd, int read_fd) {
    const char value = 'w'; ssize_t count;
    do { count = ::write(write_fd, &value, 1); } while (count < 0 && errno == EINTR);
    Require(count == 1, "writer command failed");
    pollfd ready{read_fd, POLLIN, 0}; int result;
    do { result = ::poll(&ready, 1, 10000); } while (result < 0 && errno == EINTR);
    Require(result == 1 && (ready.revents & POLLIN), "writer acknowledgement timed out");
    char ack = 0;
    do { count = ::read(read_fd, &ack, 1); } while (count < 0 && errno == EINTR);
    Require(count == 1 && ack == 'd', "writer acknowledgement failed");
}
// The child uses only async-signal-safe system calls after fork. All path storage
// and pipes were prepared beforehand; no test credential leaves this directory.
[[noreturn]] void WriteChild(int command, int response, const char* warmup, const char* target) {
    const char* paths[] = {warmup, target};
    for (const auto* path : paths) {
        char value = 0; ssize_t count;
        do { count = ::read(command, &value, 1); } while (count < 0 && errno == EINTR);
        if (count != 1 || value != 'w') ::_exit(10);
        const int fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) ::_exit(11);
        constexpr char content[] = "SYNTHETIC_SHUTDOWN_TEST=not-a-credential\n";
        size_t offset = 0;
        while (offset < sizeof(content) - 1) {
            const auto written = ::write(fd, content + offset, sizeof(content) - 1 - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) ::_exit(12);
            offset += static_cast<size_t>(written);
        }
        if (::fsync(fd) || ::close(fd)) ::_exit(13);
        const char ack = 'd';
        do { count = ::write(response, &ack, 1); } while (count < 0 && errno == EINTR);
        if (count != 1) ::_exit(14);
    }
    ::_exit(0);
}
void RunRound(size_t round, int delay_ms) {
    using namespace agentsec;
    TemporaryDirectory temporary;
    const auto log = (temporary.path / "evidence.jsonl").string();
    const auto warmup = (temporary.path / "warmup.env").string();
    const auto target = (temporary.path / "shutdown.env").string();
    int command[2], response[2];
    Require(::pipe(command) == 0, "command pipe failed");
    auto command_read = OwnFd(command[0]), command_write = OwnFd(command[1]);
    Require(::pipe(response) == 0, "response pipe failed");
    auto response_read = OwnFd(response[0]), response_write = OwnFd(response[1]);
    const auto pid = ::fork();
    Require(pid >= 0, "fork failed");
    if (pid == 0) {
        ::close(command[1]); ::close(response[0]);
        WriteChild(command[0], response[1], warmup.c_str(), target.c_str());
    }
    Child child(pid);
    command_read.reset(); response_write.reset();
    EvidenceStore store(log, {});
    FileMonitor monitor({temporary.path.string()}, store, 1);
    monitor.Start();
    Command(command_write->value, response_read->value);
    const auto deadline = MonoClock::now() + std::chrono::seconds(10);
    const auto warmup_token = "\"target_resource\":\"" + warmup + '"';
    while (ReadFile(log).find(warmup_token) == std::string::npos) {
        monitor.Check(); store.Check();
        Require(MonoClock::now() < deadline, "warmup file event not received");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // The warmup triggers NoDefer delivery; this second write commonly falls
    // inside the 100ms latency window. Do not sleep or wait for its event.
    Command(command_write->value, response_read->value);
    if (delay_ms) std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    monitor.Stop(); monitor.Check();
    child.Wait();
    store.Close();
    const auto records = ReadFile(log);
    Require(records.find("\"target_resource\":\"" + target + '"') != std::string::npos,
            "write acknowledged before Stop is missing from flushed evidence");
    const auto stats = monitor.Stats();
    Require(!stats.queue_dropped && !stats.oversized_paths && !stats.source_gaps && !store.Rejected(),
            "shutdown reported an unexpected coverage loss");
    std::cout << "PASS: round " << round << " independent child write acknowledged, delay_ms=" << delay_ms << ", Stop captured target\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        int delay_ms = 0;
        if (argc == 2) delay_ms = std::stoi(argv[1]);
        Require(argc <= 2 && delay_ms >= 0 && delay_ms <= 2000, "usage: agent-shutdown-probe [diagnostic-delay-ms 0..2000]");
        size_t failures = 0;
        for (size_t round = 1; round <= 6; ++round) {
            try { RunRound(round, delay_ms); }
            catch (const std::exception& error) { ++failures; std::cerr << "FAIL: round " << round << ": " << error.what() << '\n'; }
        }
        std::cout << "RESULT: native FSEvents shutdown rounds=6 failures=" << failures << " delay_ms=" << delay_ms << '\n';
        return failures ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n'; return 1;
    }
}
