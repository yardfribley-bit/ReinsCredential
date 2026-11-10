#pragma once
#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>
#include <memory>
#include <type_traits>
#include <unistd.h>

namespace agentsec {
struct CFDeleter {
    template<class T> void operator()(T* ref) const noexcept { if (ref) CFRelease(ref); }
};
template<class Ref> using UniqueCF = std::unique_ptr<std::remove_pointer_t<Ref>, CFDeleter>;
struct DispatchDeleter {
    void operator()(std::remove_pointer_t<dispatch_queue_t>* queue) const noexcept {
        if (queue) dispatch_release(queue);
    }
};
using UniqueDispatch = std::unique_ptr<std::remove_pointer_t<dispatch_queue_t>, DispatchDeleter>;
struct StreamDeleter {
    bool scheduled = false, started = false;
    void operator()(std::remove_pointer_t<FSEventStreamRef>* stream) const noexcept {
        if (!stream) return;
        if (started) FSEventStreamStop(stream);
        if (scheduled) FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
};
using UniqueStream = std::unique_ptr<std::remove_pointer_t<FSEventStreamRef>, StreamDeleter>;
// POSIX descriptors are values; their owner is itself held by unique_ptr.
struct FdHandle {
    explicit FdHandle(int descriptor) noexcept : value(descriptor) {}
    ~FdHandle() { if (value >= 0) ::close(value); } // do not retry close after EINTR
    FdHandle(const FdHandle&) = delete;
    FdHandle& operator=(const FdHandle&) = delete;
    int value;
};
using UniqueFd = std::unique_ptr<FdHandle>;
inline UniqueFd OwnFd(int fd) {
    try { return std::make_unique<FdHandle>(fd); }
    catch (...) { if (fd >= 0) ::close(fd); throw; }
}
} // namespace agentsec
