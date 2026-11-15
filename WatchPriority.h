#pragma once

// Opt the collector out of App Nap and timer coalescing. Display sleep and
// session lock must not slow process discovery. The activity is held for the
// process lifetime.
void KeepCollectingDuringDisplaySleep();
