#pragma once
#include <string>

namespace agentsec {
std::string Sha256(const std::string& bytes);
std::string Base64(const std::string& bytes);
// Exact whole-version match in raw, JSON-escaped, base64 or bounded gzip form.
// Not general dataflow/taint tracking; partial and arbitrarily transformed values can evade it.
std::string MatchContent(const std::string& payload, const std::string& sensitive);
// Smallest of the raw size, gzip, zlib, and raw deflate. The compressed
// bytes are wiped. This is a lower bound, not a claim that the sender used
// one of these codecs. zstd is not computed.
uint64_t ContentLowerBound(const std::string& bytes);
}
