#include "WatchPriority.h"
#include <objc/message.h>
#include <objc/runtime.h>
#include <cstdint>

void KeepCollectingDuringDisplaySleep() {
    // NSActivityUserInitiatedAllowingIdleSystemSleep | NSActivityLatencyCritical.
    // This does not prevent the display from sleeping. It keeps this process
    // from being deferred while the display is asleep or the session is locked.
    constexpr uint64_t kOptions = 0x00FFFFFFULL | 0xFF00000000ULL;
    static id held = nullptr;
    if (held) return;
    // No autorelease pool: the returned activity must outlive this call.
    id info = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend)(
        reinterpret_cast<id>(objc_getClass("NSProcessInfo")), sel_registerName("processInfo"));
    if (!info) return;
    id reason = reinterpret_cast<id (*)(id, SEL, const char*)>(objc_msgSend)(
        reinterpret_cast<id>(objc_getClass("NSString")), sel_registerName("stringWithUTF8String:"),
        "Watch local process opens while the display sleeps");
    held = reinterpret_cast<id (*)(id, SEL, uint64_t, id)>(objc_msgSend)(
        info, sel_registerName("beginActivityWithOptions:reason:"), kOptions, reason);
}
