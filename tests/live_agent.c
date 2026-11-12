/* Synthetic already-running agent. The executable must be named codex, cursor,
   claude, or workbuddy so the collector's existing name rule matches it.
   The bytes it sends are whatever the caller put in the file. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int hold_file(const char* path) {
    return open(path, O_RDONLY);
}

static int read_all(const char* path, char** out, size_t* length) {
    FILE* file = fopen(path, "rb");
    if (!file) return -1;
    if (fseek(file, 0, SEEK_END)) { fclose(file); return -1; }
    long size = ftell(file);
    if (size < 0 || size > 1024 * 1024) { fclose(file); return -1; }
    rewind(file);
    char* bytes = malloc((size_t)size);
    if (!bytes) { fclose(file); return -1; }
    if (fread(bytes, 1, (size_t)size, file) != (size_t)size) { free(bytes); fclose(file); return -1; }
    fclose(file);
    *out = bytes;
    *length = (size_t)size;
    return 0;
}

static int connect_ip(const char* host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr*)&address, sizeof(address))) { close(fd); return -1; }
    return fd;
}

static int send_all(int fd, const char* data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = send(fd, data + sent, length - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static void wait_ready(const char* path) {
    if (!path || !path[0]) {
        usleep(300000);
        return;
    }
    for (int attempt = 0; attempt < 80; ++attempt) {
        if (access(path, R_OK) == 0) return;
        usleep(100000);
    }
}
static int wait_port(const char* path) {
    for (int attempt = 0; attempt < 50; ++attempt) {
        FILE* file = fopen(path, "r");
        if (file) {
            int port = 0;
            if (fscanf(file, "%d", &port) == 1 && port > 0 && port < 65536) { fclose(file); return port; }
            fclose(file);
        }
        usleep(100000);
    }
    return -1;
}

int main(int argc, char** argv) {
    if (argc < 3) return 2;
    int held = hold_file(argv[2]);
    if (held < 0) return 3;
    const char* mode = argv[1];
    char* body = NULL;
    size_t body_len = 0;
    if (strcmp(mode, "sleep") != 0 && read_all(argv[2], &body, &body_len)) { close(held); return 4; }
    int rc = 0;
    if (strcmp(mode, "direct") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = connect_ip(argv[3], atoi(argv[4]));
        if (fd < 0) rc = 5;
        else {
            char header[512];
            int header_len = snprintf(header, sizeof(header),
                "POST /upload HTTP/1.1\r\nHost: %s:%s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                argv[3], argv[4], body_len);
            if (header_len < 0 || send_all(fd, header, (size_t)header_len) || send_all(fd, body, body_len)) rc = 6;
            sleep(2);
            close(fd);
        }
    } else if (strcmp(mode, "proxy") == 0 && argc == 5) {
        int port = wait_port(argv[3]);
        int fd = port < 0 ? -1 : connect_ip("127.0.0.1", port);
        if (fd < 0) rc = 5;
        else {
            const char* url = argv[4];
            char header[1024];
            int header_len = snprintf(header, sizeof(header),
                "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                url, body_len);
            if (header_len < 0 || send_all(fd, header, (size_t)header_len) || send_all(fd, body, body_len)) rc = 6;
            char scratch[256];
            recv(fd, scratch, sizeof(scratch), 0);
            close(fd);
        }
    } else if (strcmp(mode, "attempt") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) rc = 5;
        else {
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            struct sockaddr_in address;
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            address.sin_port = htons((unsigned short)atoi(argv[4]));
            if (inet_pton(AF_INET, argv[3], &address.sin_addr) != 1) rc = 5;
            else {
                /* EINPROGRESS keeps a SYN_SENT socket that libproc can see. */
                connect(fd, (struct sockaddr*)&address, sizeof(address));
                sleep(3);
            }
            close(fd);
        }
    } else if (strcmp(mode, "refused") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) rc = 5;
        else {
            struct sockaddr_in address;
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            address.sin_port = htons((unsigned short)atoi(argv[4]));
            if (inet_pton(AF_INET, argv[3], &address.sin_addr) != 1) rc = 5;
            else {
                /* Blocking connect to a closed local port returns ECONNREFUSED.
                   The fd stays open so libproc can still see the peer. */
                connect(fd, (struct sockaddr*)&address, sizeof(address));
                sleep(6);
            }
            close(fd);
        }
    } else if ((strcmp(mode, "udp") == 0 || strcmp(mode, "udp-file") == 0) && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[4]));
        if (fd < 0 || inet_pton(AF_INET, argv[3], &address.sin_addr) != 1 ||
            connect(fd, (struct sockaddr*)&address, sizeof(address))) rc = 5;
        else {
            if (strcmp(mode, "udp-file") == 0) {
                if (send_all(fd, body, body_len)) rc = 6;
            } else if (send(fd, "Q", 1, 0) != 1) rc = 6;
            sleep(2);
            close(fd);
        }
    } else if (strcmp(mode, "payload") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        char send_path[1024];
        int wrote = snprintf(send_path, sizeof(send_path), "%s.send", argv[2]);
        char* payload = NULL;
        size_t payload_len = 0;
        int fd = -1;
        if (wrote < 0 || (size_t)wrote >= sizeof(send_path) || read_all(send_path, &payload, &payload_len)) rc = 4;
        else if ((fd = connect_ip(argv[3], atoi(argv[4]))) < 0 || send_all(fd, payload, payload_len)) rc = 5;
        else {
            sleep(2);
        }
        if (fd >= 0) close(fd);
        if (payload) { memset(payload, 0, payload_len); free(payload); }
    } else if (strcmp(mode, "chunk3") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fds[3] = {-1, -1, -1};
        size_t offset = 0;
        for (int i = 0; i < 3; ++i) {
            size_t part = body_len / 3;
            if (i == 2) part = body_len - offset;
            fds[i] = connect_ip(argv[3], atoi(argv[4]));
            if (fds[i] < 0 || send_all(fds[i], body + offset, part)) { rc = 5; break; }
            offset += part;
        }
        if (rc == 0) sleep(2);
        for (int i = 0; i < 3; ++i) if (fds[i] >= 0) close(fds[i]);
    } else if (strcmp(mode, "partial") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int tcp = connect_ip(argv[3], atoi(argv[4]));
        int udp = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[4]));
        if (tcp < 0 || udp < 0 || inet_pton(AF_INET, argv[3], &address.sin_addr) != 1 ||
            connect(udp, (struct sockaddr*)&address, sizeof(address)) ||
            send(tcp, "Q", 1, 0) != 1 || send(udp, "Q", 1, 0) != 1) rc = 5;
        else sleep(4);
        if (tcp >= 0) close(tcp);
        if (udp >= 0) close(udp);
    } else if (strcmp(mode, "short") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = connect_ip(argv[3], atoi(argv[4]));
        if (fd < 0) rc = 5;
        else {
            char header[512];
            int header_len = snprintf(header, sizeof(header),
                "POST /upload HTTP/1.1\r\nHost: %s:%s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                argv[3], argv[4], body_len);
            if (header_len < 0 || send_all(fd, header, (size_t)header_len) || send_all(fd, body, body_len)) rc = 6;
            else usleep(100000);
            close(fd);
        }
    } else if (strcmp(mode, "udp-short") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)atoi(argv[4]));
        if (fd < 0 || inet_pton(AF_INET, argv[3], &address.sin_addr) != 1 ||
            connect(fd, (struct sockaddr*)&address, sizeof(address)) ||
            send_all(fd, body, body_len)) rc = 5;
        else usleep(100000);
        if (fd >= 0) close(fd);
    } else if (strcmp(mode, "refused-short") == 0 && (argc == 5 || argc == 6)) {
        wait_ready(argc == 6 ? argv[5] : NULL);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) rc = 5;
        else {
            struct sockaddr_in address;
            memset(&address, 0, sizeof(address));
            address.sin_family = AF_INET;
            address.sin_port = htons((unsigned short)atoi(argv[4]));
            if (inet_pton(AF_INET, argv[3], &address.sin_addr) != 1) rc = 5;
            else {
                connect(fd, (struct sockaddr*)&address, sizeof(address));
                usleep(100000);
            }
            close(fd);
        }
    } else if (strcmp(mode, "sleep") == 0) {
        sleep(2);
    } else rc = 2;
    if (body) {
        memset(body, 0, body_len);
        free(body);
    }
    close(held);
    return rc;
}
