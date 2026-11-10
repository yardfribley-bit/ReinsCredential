#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    int file = open(argv[1], O_CREAT | O_RDWR, 0600);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{}; address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (file < 0 || listener < 0 || bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) || listen(listener, 1)) return 3;
    socklen_t size = sizeof(address);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &size)) return 4;
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, reinterpret_cast<sockaddr*>(&address), size)) return 5;
    int server = accept(listener, nullptr, nullptr);
    if (server < 0) return 6;
    pid_t child = fork();
    if (child < 0) return 7;
    if (child == 0) { execl("/bin/sleep", "sleep", "10", static_cast<char*>(nullptr)); _exit(8); }
    std::cout << getpid() << ' ' << child << std::endl;
    for (int i = 0; i < 20; ++i) { if (write(file, "synthetic-test\n", 15) < 0) return 9; fsync(file); usleep(400000); }
    int status = 0; waitpid(child, &status, 0);
    close(server); close(client); close(listener); close(file);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 10;
}
