#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

// Synthetic agent child. The parent image is copied into a fake ChatGPT.app
// bundle by the test. Children either hold a fake credential open briefly or
// exec /bin/cat on it. No real credentials are read.
int main(int argc, char** argv) {
    if (argc != 5) return 2;
    const char* path = argv[1];
    const int iterations = std::atoi(argv[2]);
    const int hold_ms = std::atoi(argv[3]);
    const std::string mode = argv[4];
    if (iterations < 1 || iterations > 200 || hold_ms < 0 || hold_ms > 1000) return 2;
    if (mode != "hold" && mode != "cat") return 2;
    std::printf("%d\n", getpid());
    std::fflush(stdout);
    char go = 0;
    if (::read(STDIN_FILENO, &go, 1) != 1) return 3;
    for (int i = 0; i < iterations; ++i) {
        const pid_t child = ::fork();
        if (child < 0) return 4;
        if (child == 0) {
            if (mode == "cat") {
                ::execl("/bin/cat", "cat", path, static_cast<char*>(nullptr));
                _exit(9);
            }
            const int fd = ::open(path, O_RDONLY);
            char buffer[16];
            if (fd >= 0) {
                const ssize_t got = ::read(fd, buffer, sizeof buffer);
                (void)got;
            }
            if (hold_ms) ::usleep(static_cast<useconds_t>(hold_ms) * 1000);
            if (fd >= 0) ::close(fd);
            _exit(0);
        }
        int status = 0;
        if (::waitpid(child, &status, 0) < 0) return 5;
        ::usleep(3000);
    }
    ::sleep(1);
    return 0;
}
