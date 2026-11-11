#pragma once
#include <string>
#include <vector>

namespace agentsec {
// Home-relative credential locations. The CLI also adds the launch directory's
// .env. Saved app configuration replaces this list; --no-default-sensitive clears it.
inline std::vector<std::string> DefaultSensitiveSuffixes() {
    return {".ssh", ".aws", ".config/gh", ".netrc", ".npmrc", ".git-credentials",
        ".docker/config.json", ".kube/config", ".config/gcloud", ".azure"};
}
} // namespace agentsec
