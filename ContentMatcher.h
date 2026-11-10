#pragma once
#include <string>

namespace agentsec {
std::string Sha256(const std::string& bytes);
std::string Base64(const std::string& bytes);
// Exact whole-version match in raw, JSON-escaped, base64 or bounded gzip form.
// Not general dataflow/taint tracking; partial and arbitrarily transformed values can evade it.
std::string MatchContent(const std::string& payload, const std::string& sensitive);
}
