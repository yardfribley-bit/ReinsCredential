#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <type_traits>

namespace agentsec {
// Exactly one producer and one consumer. No CAS retry loop, locks, allocation,
// waiting or notification syscall. N-1 usable entries; false means explicit loss.
template<class T, size_t N> class SpscRing {
    static_assert(N > 1 && (N & (N - 1)) == 0, "capacity must be a power of two");
    static_assert(std::is_trivially_copyable<T>::value, "hot path payload must be trivial");
    static_assert(std::is_nothrow_copy_assignable<T>::value, "payload copy must not throw");
    static_assert(std::atomic<size_t>::is_always_lock_free, "index atomics must be lock-free");
public:
    bool TryPush(const T& value) noexcept {
        const auto head = head_.load(std::memory_order_relaxed);
        const auto next = (head + 1) & (N - 1);
        if (next == tail_.load(std::memory_order_acquire)) return false;
        slots_[head] = value;
        head_.store(next, std::memory_order_release);
        return true;
    }
    bool TryPop(T& value) noexcept {
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire)) return false;
        value = slots_[tail];
        tail_.store((tail + 1) & (N - 1), std::memory_order_release);
        return true;
    }
private:
    std::array<T, N> slots_{};
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
};
} // namespace agentsec
