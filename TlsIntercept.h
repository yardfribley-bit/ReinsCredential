#pragma once
#include <memory>
#include <string>

namespace agentsec {
// One TLS connection. The socket is borrowed and stays owned by the caller.
class TlsSession {
public:
    virtual ~TlsSession() = default;
    // Reads one chunk. got == 0 and ok means the peer closed. ok == false is an error.
    virtual bool Read(char* data, size_t capacity, size_t& got, std::string& error) = 0;
    virtual bool Write(const char* data, size_t length, std::string& error) = 0;
};

// Optional HTTPS inspection. The CA is a PEM the caller already has. This class
// mints short-lived leaves in a private temp directory and never touches the
// login keychain or the default keychain search list.
class TlsIntercept {
public:
    TlsIntercept(std::string ca_certificate_pem, std::string ca_private_key_pem);
    ~TlsIntercept();
    TlsIntercept(const TlsIntercept&) = delete;
    TlsIntercept& operator=(const TlsIntercept&) = delete;
    std::unique_ptr<TlsSession> AcceptClient(int fd, const std::string& host, std::string& error);
    std::unique_ptr<TlsSession> ConnectOrigin(int fd, const std::string& host, std::string& error);
private:
    struct State;
    std::unique_ptr<State> state_;
};
} // namespace agentsec
