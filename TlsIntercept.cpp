#include "TlsIntercept.h"
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecImportExport.h>
#include <Security/SecItem.h>
#include <Security/SecPolicy.h>
#include <Security/SecTrust.h>
#include <Security/SecureTransport.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <spawn.h>
#include <fcntl.h>
#include <unistd.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <vector>

extern char** environ;

namespace agentsec {
namespace {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

struct IdentityDelete { void operator()(SecIdentityRef identity) const noexcept { if (identity) CFRelease(identity); } };
struct CertDelete { void operator()(SecCertificateRef cert) const noexcept { if (cert) CFRelease(cert); } };
using IdentityPtr = std::unique_ptr<std::remove_pointer_t<SecIdentityRef>, IdentityDelete>;
using CertPtr = std::unique_ptr<std::remove_pointer_t<SecCertificateRef>, CertDelete>;

int RunTool(const std::vector<std::string>& args) {
    if (args.empty()) return 1;
    std::vector<std::string> owned = args;
    std::vector<char*> argv;
    argv.reserve(owned.size() + 1);
    for (auto& arg : owned) argv.push_back(arg.data());
    argv.push_back(nullptr);
    pid_t pid = -1;
    if (posix_spawnp(&pid, argv[0], nullptr, nullptr, argv.data(), environ)) return 1;
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return 1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
bool SafeHost(const std::string& host) {
    if (host.empty() || host.size() > 200) return false;
    for (unsigned char c : host) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':'))
            return false;
    }
    return true;
}
void Shred(const std::filesystem::path& path) {
    FILE* file = fopen(path.c_str(), "rb+");
    if (!file) { std::filesystem::remove(path); return; }
    if (!fseek(file, 0, SEEK_END)) {
        long size = ftell(file);
        if (size > 0 && size < 1024 * 1024) {
            rewind(file);
            std::vector<char> zeros((size_t)size, 0);
            fwrite(zeros.data(), 1, zeros.size(), file);
            fflush(file);
        }
    }
    fclose(file);
    std::filesystem::remove(path);
}
OSStatus ReadTls(SSLConnectionRef connection, void* data, size_t* length) {
    auto* fd = static_cast<int*>(const_cast<void*>(connection));
    size_t want = *length;
    *length = 0;
    while (*length < want) {
        ssize_t n = ::recv(*fd, static_cast<char*>(data) + *length, want - *length, 0);
        if (n > 0) { *length += static_cast<size_t>(n); return noErr; }
        if (n == 0) return *length ? noErr : errSSLClosedGraceful;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return *length ? noErr : errSSLWouldBlock;
        return errSSLClosedAbort;
    }
    return noErr;
}
OSStatus WriteTls(SSLConnectionRef connection, const void* data, size_t* length) {
    auto* fd = static_cast<int*>(const_cast<void*>(connection));
    size_t want = *length;
    *length = 0;
    while (*length < want) {
        ssize_t n = ::send(*fd, static_cast<const char*>(data) + *length, want - *length, 0);
        if (n > 0) { *length += static_cast<size_t>(n); continue; }
        if (n == 0) return errSSLClosedGraceful;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return *length ? noErr : errSSLWouldBlock;
        return errSSLClosedAbort;
    }
    return noErr;
}
class SecureSession final : public TlsSession {
public:
    SSLContextRef context = nullptr;
    int fd = -1;
    ~SecureSession() override { if (context) CFRelease(context); }
    bool Read(char* data, size_t capacity, size_t& got, std::string& error) override {
        got = 0;
        size_t count = capacity;
        OSStatus status = SSLRead(context, data, count, &count);
        got = count;
        if (status == noErr || status == errSSLWouldBlock || status == errSSLClosedGraceful) return true;
        error = "tls_read_" + std::to_string(static_cast<int>(status));
        return false;
    }
    bool Write(const char* data, size_t length, std::string& error) override {
        size_t sent = 0;
        while (sent < length) {
            size_t count = 0;
            OSStatus status = SSLWrite(context, data + sent, length - sent, &count);
            sent += count;
            if (status == noErr) { if (!count) { error = "tls_write_stall"; return false; } continue; }
            if (status == errSSLWouldBlock && count) continue;
            error = "tls_write_" + std::to_string(static_cast<int>(status));
            return false;
        }
        return true;
    }
};
std::unique_ptr<TlsSession> FinishHandshake(int fd, SSLContextRef context, std::string& error) {
    OSStatus status = noErr;
    for (int attempt = 0; attempt < 8; ++attempt) {
        status = SSLHandshake(context);
        if (status != errSSLWouldBlock) break;
    }
    if (status != noErr) {
        CFRelease(context);
        error = "tls_handshake_" + std::to_string(static_cast<int>(status));
        return nullptr;
    }
    auto session = std::make_unique<SecureSession>();
    session->context = context;
    session->fd = fd;
    SSLSetConnection(context, &session->fd);
    return std::unique_ptr<TlsSession>(session.release());
}
} // namespace

struct TlsIntercept::State {
    std::string ca_cert, ca_key, work;
    CertPtr anchor;
    std::map<std::string, IdentityPtr> leaves;
    ~State() {
        leaves.clear();
        anchor.reset();
        std::error_code ignored;
        if (!work.empty()) {
            for (const auto& entry : std::filesystem::directory_iterator(work, ignored)) Shred(entry.path());
            std::filesystem::remove(work, ignored);
        }
    }
};

TlsIntercept::TlsIntercept(std::string ca_certificate_pem, std::string ca_private_key_pem) : state_(std::make_unique<State>()) {
    state_->ca_cert = std::move(ca_certificate_pem);
    state_->ca_key = std::move(ca_private_key_pem);
    std::string base = "/tmp";
    if (const char* tmp = std::getenv("TMPDIR"); tmp && *tmp) base = tmp;
    if (!base.empty() && base.back() == '/') base.pop_back();
    std::string pattern = base + "/reins-tls-XXXXXX";
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back('\0');
    if (!mkdtemp(buffer.data())) throw std::runtime_error("tls work directory failed");
    state_->work = buffer.data();
    auto der = std::filesystem::path(state_->work) / "ca.der";
    if (RunTool({"/usr/bin/openssl", "x509", "-in", state_->ca_cert, "-outform", "DER", "-out", der.string()}))
        throw std::runtime_error("tls ca conversion failed");
    FILE* file = fopen(der.c_str(), "rb");
    if (!file) throw std::runtime_error("tls ca der missing");
    if (fseek(file, 0, SEEK_END)) { fclose(file); throw std::runtime_error("tls ca der size failed"); }
    long size = ftell(file);
    if (size <= 0 || size > 1024 * 1024) { fclose(file); throw std::runtime_error("tls ca der size rejected"); }
    rewind(file);
    std::vector<unsigned char> bytes((size_t)size);
    if (fread(bytes.data(), 1, bytes.size(), file) != bytes.size()) { fclose(file); throw std::runtime_error("tls ca der read failed"); }
    fclose(file);
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes.data(), bytes.size());
    SecCertificateRef cert = data ? SecCertificateCreateWithData(kCFAllocatorDefault, data) : nullptr;
    if (data) CFRelease(data);
    if (!cert) throw std::runtime_error("tls ca certificate rejected");
    state_->anchor.reset(cert);
}
TlsIntercept::~TlsIntercept() = default;

std::unique_ptr<TlsSession> TlsIntercept::AcceptClient(int fd, const std::string& host, std::string& error) {
    if (!SafeHost(host)) { error = "tls_host_rejected"; return nullptr; }
    IdentityPtr* identity = nullptr;
    auto found = state_->leaves.find(host);
    if (found == state_->leaves.end()) {
        if (state_->leaves.size() >= 32) { error = "tls_leaf_cache_full"; return nullptr; }
        auto dir = std::filesystem::path(state_->work);
        auto key = (dir / (host + ".key")).string();
        auto csr = (dir / (host + ".csr")).string();
        auto crt = (dir / (host + ".crt")).string();
        auto p12 = (dir / (host + ".p12")).string();
        auto ext = (dir / (host + ".ext")).string();
        in_addr ipv4{};
        const bool ip = inet_pton(AF_INET, host.c_str(), &ipv4) == 1;
        FILE* extfile = fopen(ext.c_str(), "w");
        if (!extfile) { error = "tls_ext_failed"; return nullptr; }
        fprintf(extfile, "[ext]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s:%s\n",
            ip ? "IP" : "DNS", host.c_str());
        fclose(extfile);
        if (RunTool({"/usr/bin/openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key}) ||
            RunTool({"/usr/bin/openssl", "req", "-new", "-key", key, "-subj", "/CN=" + host, "-out", csr}) ||
            RunTool({"/usr/bin/openssl", "x509", "-req", "-in", csr, "-CA", state_->ca_cert, "-CAkey", state_->ca_key,
                "-CAserial", (dir / "ca.srl").string(), "-CAcreateserial", "-out", crt, "-days", "1", "-extfile", ext, "-extensions", "ext"}) ||
            RunTool({"/usr/bin/openssl", "pkcs12", "-export", "-inkey", key, "-in", crt, "-certfile", state_->ca_cert,
                "-passout", "pass:ephemeral", "-out", p12})) {
            Shred(key);
            error = "tls_leaf_mint_failed";
            return nullptr;
        }
        Shred(key);
        FILE* pkcs = fopen(p12.c_str(), "rb");
        if (!pkcs) { error = "tls_pkcs12_missing"; return nullptr; }
        if (fseek(pkcs, 0, SEEK_END)) { fclose(pkcs); error = "tls_pkcs12_size_failed"; return nullptr; }
        long size = ftell(pkcs);
        if (size <= 0 || size > 1024 * 1024) { fclose(pkcs); error = "tls_pkcs12_size_rejected"; return nullptr; }
        rewind(pkcs);
        std::vector<unsigned char> bytes((size_t)size);
        if (fread(bytes.data(), 1, bytes.size(), pkcs) != bytes.size()) { fclose(pkcs); error = "tls_pkcs12_read_failed"; return nullptr; }
        fclose(pkcs);
        Shred(p12);
        CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes.data(), bytes.size());
        CFStringRef password = CFStringCreateWithCString(kCFAllocatorDefault, "ephemeral", kCFStringEncodingUTF8);
        const void* keys[] = { kSecImportExportPassphrase };
        const void* values[] = { password };
        CFDictionaryRef options = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFArrayRef items = nullptr;
        OSStatus imported = data && options ? SecPKCS12Import(data, options, &items) : errSecParam;
        if (data) CFRelease(data);
        if (password) CFRelease(password);
        if (options) CFRelease(options);
        if (imported != errSecSuccess || !items || !CFArrayGetCount(items)) {
            if (items) CFRelease(items);
            error = "tls_pkcs12_import_" + std::to_string(static_cast<int>(imported));
            return nullptr;
        }
        auto entry = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(items, 0));
        auto raw = static_cast<SecIdentityRef>(const_cast<void*>(CFDictionaryGetValue(entry, kSecImportItemIdentity)));
        if (!raw) { CFRelease(items); error = "tls_identity_missing"; return nullptr; }
        CFRetain(raw);
        CFRelease(items);
        state_->leaves.emplace(host, IdentityPtr(raw));
        identity = &state_->leaves[host];
    } else identity = &found->second;
    SSLContextRef context = SSLCreateContext(kCFAllocatorDefault, kSSLServerSide, kSSLStreamType);
    if (!context) { error = "tls_context_failed"; return nullptr; }
    SSLSetIOFuncs(context, ReadTls, WriteTls);
    SSLSetConnection(context, &fd);
    SecIdentityRef raw = identity->get();
    CFArrayRef chain = CFArrayCreate(kCFAllocatorDefault, (const void**)&raw, 1, &kCFTypeArrayCallBacks);
    OSStatus set = SSLSetCertificate(context, chain);
    CFRelease(chain);
    if (set != noErr) { CFRelease(context); error = "tls_certificate_" + std::to_string(static_cast<int>(set)); return nullptr; }
    return FinishHandshake(fd, context, error);
}
std::unique_ptr<TlsSession> TlsIntercept::ConnectOrigin(int fd, const std::string& host, std::string& error) {
    if (!SafeHost(host) || !state_->anchor) { error = "tls_origin_rejected"; return nullptr; }
    SSLContextRef context = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    if (!context) { error = "tls_context_failed"; return nullptr; }
    SSLSetIOFuncs(context, ReadTls, WriteTls);
    SSLSetConnection(context, &fd);
    SSLSetPeerDomainName(context, host.c_str(), host.size());
    SSLSetSessionOption(context, kSSLSessionOptionBreakOnServerAuth, true);
    OSStatus status = errSSLWouldBlock;
    bool checked = false;
    for (int attempt = 0; attempt < 12; ++attempt) {
        status = SSLHandshake(context);
        if (status == errSSLPeerAuthCompleted && !checked) {
            checked = true;
            SecTrustRef trust = nullptr;
            SSLCopyPeerTrust(context, &trust);
            SecCertificateRef anchor = state_->anchor.get();
            CFArrayRef anchors = anchor ? CFArrayCreate(kCFAllocatorDefault, (const void**)&anchor, 1, &kCFTypeArrayCallBacks) : nullptr;
            auto trusted_with = [&](SecPolicyRef policy) {
                if (!trust || !anchors || !policy) return false;
                SecTrustSetAnchorCertificates(trust, anchors);
                SecTrustSetAnchorCertificatesOnly(trust, true);
                SecTrustSetPolicies(trust, policy);
                CFErrorRef trust_error = nullptr;
                bool ok = SecTrustEvaluateWithError(trust, &trust_error);
                if (trust_error) CFRelease(trust_error);
                return ok;
            };
            CFStringRef name = CFStringCreateWithCString(kCFAllocatorDefault, host.c_str(), kCFStringEncodingUTF8);
            SecPolicyRef ssl_policy = name ? SecPolicyCreateSSL(true, name) : nullptr;
            bool trusted = trusted_with(ssl_policy);
            // SecureTransport often will not treat an IP SAN as the SSL peer name.
            // The socket was connected to this exact host, and the only anchor is the
            // caller-supplied CA, so a chain check is the verification we can make.
            in_addr ipv4{};
            if (!trusted && inet_pton(AF_INET, host.c_str(), &ipv4) == 1) {
                SecPolicyRef basic = SecPolicyCreateBasicX509();
                trusted = trusted_with(basic);
                if (basic) CFRelease(basic);
            }
            if (ssl_policy) CFRelease(ssl_policy);
            if (name) CFRelease(name);
            if (trust) CFRelease(trust);
            if (anchors) CFRelease(anchors);
            if (!trusted) { CFRelease(context); error = "tls_origin_not_trusted"; return nullptr; }
            continue;
        }
        if (status != errSSLWouldBlock) break;
    }
    if (status != noErr) { CFRelease(context); error = "tls_origin_handshake_" + std::to_string(static_cast<int>(status)); return nullptr; }
    auto session = std::make_unique<SecureSession>();
    session->context = context;
    session->fd = fd;
    SSLSetConnection(context, &session->fd);
    return std::unique_ptr<TlsSession>(session.release());
}
#pragma clang diagnostic pop
} // namespace agentsec
