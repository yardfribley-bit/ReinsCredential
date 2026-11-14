#include "EgressVerdict.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>

namespace agentsec {
const char* UploadVerdictCode(UploadVerdict verdict) noexcept {
    switch (verdict) {
    case UploadVerdict::Uploaded: return "uploaded";
    case UploadVerdict::Attempted: return "attempted";
    case UploadVerdict::NotFound: return "not_found";
    case UploadVerdict::NotVisible: return "not_visible";
    }
    return "not_visible";
}
const char* UploadVerdictLabel(UploadVerdict verdict) noexcept {
    switch (verdict) {
    case UploadVerdict::Uploaded: return "已上传";
    case UploadVerdict::Attempted: return "已尝试未成功";
    case UploadVerdict::NotFound: return "未发现";
    case UploadVerdict::NotVisible: return "看不到";
    }
    return "看不到";
}
AccessClose CloseAccess(bool egress_watched, const std::vector<EgressObservation>& observations) {
    const EgressObservation* uploaded = nullptr;
    const EgressObservation* attempted = nullptr;
    const EgressObservation* unseen = nullptr;
    const EgressObservation* http = nullptr;
    for (const auto& item : observations) {
        if (item.kind == EgressObservation::Kind::HttpInspected) {
            if (!http) http = &item;
            if (item.content_match && item.transfer_succeeded) {
                if (!uploaded) uploaded = &item;
            } else if (item.content_match && !item.transfer_succeeded) {
                if (!attempted) attempted = &item;
            }
        } else if (!unseen) {
            unseen = &item;
        }
    }
    AccessClose result;
    if (uploaded) {
        result.verdict = UploadVerdict::Uploaded;
        result.destination = uploaded->destination;
        result.transfer_outcome = uploaded->transfer_outcome;
        return result;
    }
    if (attempted) {
        result.verdict = UploadVerdict::Attempted;
        result.destination = attempted->destination;
        result.transfer_outcome = attempted->transfer_outcome;
        return result;
    }
    // A channel whose bytes we did not read cannot be reported as 未发现.
    // That word is reserved for egress we actually inspected.
    if (unseen || !egress_watched) {
        result.verdict = UploadVerdict::NotVisible;
        if (unseen) {
            result.destination = unseen->destination;
            result.transfer_outcome = unseen->transfer_outcome.empty() ? "channel_not_visible" : unseen->transfer_outcome;
        } else {
            result.transfer_outcome = "egress_not_watched";
        }
        return result;
    }
    result.verdict = UploadVerdict::NotFound;
    if (http) {
        result.destination = http->destination;
        result.transfer_outcome = "watched_http_no_registered_content";
    } else {
        result.transfer_outcome = "watched_http_egress_idle";
    }
    return result;
}
std::string UploadVerdictSummary(const AccessClose& close, const std::string& process, const std::string& path) {
    const std::string label = UploadVerdictLabel(close.verdict);
    const std::string who = process.empty() ? "该进程" : process;
    const std::string dest = close.destination.empty() ? "（没有观察到目的地）" : close.destination;
    const std::string file = path.empty() ? "已登记文件" : path;
    switch (close.verdict) {
    case UploadVerdict::Uploaded:
        return label + "。" + who + " 向 " + dest + " 发送的请求体与已登记文件 " + file +
            " 匹配，传输结果：" + close.transfer_outcome + "。这是代理观察到的 HTTP 结果，不是对端的独立回执。";
    case UploadVerdict::Attempted:
        return label + "。" + who + " 向 " + dest + " 发送的请求体与已登记文件 " + file +
            " 匹配，但传输没有成功：" + close.transfer_outcome + "。";
    case UploadVerdict::NotFound:
        return label + "。已查看 " + who + " 的明文 HTTP 出口" +
            (close.destination.empty() ? "，没有请求" : "（" + dest + "）") +
            "，没有看到已登记文件 " + file + " 的内容。结果：" + close.transfer_outcome + "。";
    case UploadVerdict::NotVisible:
        return label + "。看不到 " + who + " 发往 " + dest + " 的通道内容，因此不能判断已登记文件 " +
            file + " 有没有发出去。结果：" + close.transfer_outcome + "。";
    }
    return label;
}

namespace {
uint64_t TxDelta(const LiveFlow& flow) {
    return flow.tx_latest >= flow.tx_baseline ? flow.tx_latest - flow.tx_baseline : 0;
}
uint64_t LowerBound(const LiveAccessView& view) {
    if (view.content_lower_bound == 0 || view.content_lower_bound > view.file_bytes) return view.file_bytes;
    return view.content_lower_bound;
}
bool Measured(const LiveFlow& flow) {
    return flow.measured || flow.kind == LiveFlowKind::TcpMeasured;
}
uint16_t PeerPort(const std::string& destination) {
    std::string text;
    if (!destination.empty() && destination[0] == '[') {
        const auto mark = destination.rfind("]:");
        if (mark == std::string::npos) return 0;
        text = destination.substr(mark + 2);
    } else {
        const auto colon = destination.rfind(':');
        if (colon == std::string::npos) return 0;
        text = destination.substr(colon + 1);
    }
    unsigned value = 0;
    if (text.empty()) return 0;
    for (char c : text) {
        if (c < '0' || c > '9') return 0;
        value = value * 10u + static_cast<unsigned>(c - '0');
        if (value > 65535u) return 0;
    }
    return static_cast<uint16_t>(value);
}
bool TlsShaped(const LiveFlow& flow) {
    if (!flow.sni.empty()) return true;
    if (IsProviderOrRelay(flow.destination)) return true;
    return PeerPort(flow.destination) == 443;
}
uint64_t ApplicationBytes(const LiveFlow& flow, uint64_t delta) {
    if (flow.plaintext_http) return delta;
    if (flow.tls_handshake && !flow.tls_app_data) return 0;
    if (flow.tls_app_data && flow.tls_app_bytes > 0) return flow.tls_app_bytes;
    if (flow.kind == LiveFlowKind::TcpMeasured && TlsShaped(flow))
        return delta > kTlsHandshakeAllowance ? delta - kTlsHandshakeAllowance : 0;
    return delta;
}
bool HandshakeOnly(const LiveFlow& flow, uint64_t delta, uint64_t lower) {
    if (flow.plaintext_http) return false;
    // Application data is a TLS record of type 23 (or a parsed length). Handshake
    // records alone, however large, are not a body. The fixed 1024-byte slack is
    // not what decides this.
    if (flow.tls_handshake && !(flow.tls_app_data && flow.tls_app_bytes > 0)) return true;
    if (flow.tls_app_data && flow.tls_app_bytes > 0) return false;
    return flow.kind == LiveFlowKind::TcpMeasured && TlsShaped(flow) && delta > 0 &&
        ApplicationBytes(flow, delta) < lower;
}
void NoteSni(LiveClose& result, const LiveFlow* flow) {
    if (!flow || flow->sni.empty() || result.detail.find("sni=") != std::string::npos) return;
    result.detail += ";sni=" + flow->sni;
}
std::string SumText(uint64_t sum, uint64_t lower, uint64_t file_bytes) {
    return "tx_sum=" + std::to_string(sum) + ";lower_bound=" + std::to_string(lower) +
        ";file_bytes=" + std::to_string(file_bytes) + ";slack=" + std::to_string(kFlowTxSlack);
}
LiveClose Defer(UploadVerdict verdict) {
    LiveClose result;
    result.defer = true;
    result.verdict = verdict;
    result.match_basis = "live_agent_observed";
    result.transfer_outcome = "watch_window_open";
    result.detail = "hold_or_tail_still_open;not_emitted;app_settings_not_modified";
    return result;
}
} // namespace

TlsRecordView ClassifyTlsRecords(const uint8_t* data, size_t size) noexcept {
    TlsRecordView view;
    if (!data) return view;
    size_t index = 0;
    while (index + 5 <= size && data[index + 1] == 0x03) {
        const uint8_t type = data[index];
        const size_t length = (static_cast<size_t>(data[index + 3]) << 8) | data[index + 4];
        const bool whole = index + 5 + length <= size;
        const uint8_t* body = data + index + 5;
        const size_t body_len = whole ? length : size - (index + 5);
        const size_t step = whole ? 5 + length : size - index;
        if (type == 20 || type == 21) {
            if (!whole) break;
            index += step;
            continue;
        }
        if (type == 22) {
            view.saw_handshake = true;
            view.handshake_bytes += body_len;
            if (view.sni.empty() && body_len > 38 && body[0] == 1) {
                size_t cursor = 38;
                if (cursor < body_len) {
                    const size_t session = body[cursor];
                    cursor += 1 + session;
                    if (cursor + 2 <= body_len) {
                        const size_t ciphers = (static_cast<size_t>(body[cursor]) << 8) | body[cursor + 1];
                        cursor += 2 + ciphers;
                        if (cursor < body_len) {
                            const size_t compression = body[cursor];
                            cursor += 1 + compression;
                            if (cursor + 2 <= body_len) {
                                const size_t extensions = (static_cast<size_t>(body[cursor]) << 8) | body[cursor + 1];
                                cursor += 2;
                                const size_t end = std::min(body_len, cursor + extensions);
                                while (cursor + 4 <= end) {
                                    const size_t kind = (static_cast<size_t>(body[cursor]) << 8) | body[cursor + 1];
                                    const size_t ext = (static_cast<size_t>(body[cursor + 2]) << 8) | body[cursor + 3];
                                    cursor += 4;
                                    if (cursor + ext > end) break;
                                    if (kind == 0 && ext >= 5) {
                                        const size_t name_len = (static_cast<size_t>(body[cursor + 3]) << 8) | body[cursor + 4];
                                        if (name_len > 0 && name_len < 253 && cursor + 5 + name_len <= cursor + ext)
                                            view.sni.assign(reinterpret_cast<const char*>(body + cursor + 5), name_len);
                                    }
                                    cursor += ext;
                                }
                            }
                        }
                    }
                }
            }
        } else if (type == 23) {
            view.saw_app_data = true;
            view.app_bytes += body_len;
        } else break;
        if (!whole) break;
        index += step;
    }
    return view;
}
LiveClose CloseLiveAccess(const LiveAccessView& view) {
    LiveClose result;
    if (!view.agent_visible) {
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "agent_not_visible";
        result.detail = "inspection_incomplete;not_a_clean_bill;app_settings_not_modified";
        return result;
    }
    if (!view.file_open) {
        if (!view.inspection_complete) {
            result.verdict = UploadVerdict::NotVisible;
            result.match_basis = "observation_impossible";
            result.transfer_outcome = "descriptors_or_flows_incomplete";
            result.detail = "inspection_incomplete;not_a_clean_bill;app_settings_not_modified";
            return result;
        }
        result.verdict = UploadVerdict::NotFound;
        result.match_basis = "live_agent_observed";
        result.transfer_outcome = "live_agent_observed_no_access";
        result.detail = "agent_seen;no_registered_file_open;no_offhost_upload;app_settings_not_modified";
        return result;
    }
    if (view.file_bytes == 0) {
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "registered_file_size_unknown";
        result.detail = "file_open_observed;size_unknown;cannot_correlate_send;app_settings_not_modified";
        return result;
    }
    const auto lower = LowerBound(view);
    const auto upper = view.file_bytes + kFlowTxSlack;
    uint64_t tcp_sum = 0;
    uint64_t udp_sum = 0;
    const LiveFlow* upload_peer = nullptr;
    const LiveFlow* attempt = nullptr;
    const LiveFlow* unmeasured = nullptr;
    const LiveFlow* handshake = nullptr;
    const LiveFlow* loopback_send = nullptr;
    const LiveFlow* loopback_peer = nullptr;
    const LiveFlow* measured_offhost = nullptr;
    bool any_offhost = false;
    bool any_measured_offhost = false;
    bool saw_measured_flow = false;
    bool saw_proxy = false;
    for (const auto& flow : view.flows) {
        if (flow.to_local_proxy) { saw_proxy = true; continue; }
        const auto delta = TxDelta(flow);
        const auto app = ApplicationBytes(flow, delta);
        const bool measured = Measured(flow);
        if (measured) saw_measured_flow = true;
        if (flow.loopback) {
            if (measured && !loopback_peer) loopback_peer = &flow;
            if (measured && flow.kind == LiveFlowKind::TcpMeasured && flow.established && delta >= lower && !loopback_send)
                loopback_send = &flow;
            // A datagram whose byte count never arrived is still unresolved,
            // including one aimed at 127.0.0.1.
            if (!measured && !unmeasured) unmeasured = &flow;
            continue;
        }
        any_offhost = true;
        if (!measured) {
            if (!unmeasured) unmeasured = &flow;
            continue;
        }
        any_measured_offhost = true;
        if (!measured_offhost) measured_offhost = &flow;
        if (HandshakeOnly(flow, delta, lower)) {
            if (!handshake) handshake = &flow;
            continue;
        }
        if (flow.kind == LiveFlowKind::UdpOrQuic) {
            udp_sum += delta;
            if (!upload_peer && delta > 0) upload_peer = &flow;
            continue;
        }
        if (flow.established) {
            tcp_sum += app;
            if (app > 0 && !upload_peer) upload_peer = &flow;
        } else if (flow.failed && !attempt && delta < lower) {
            attempt = &flow;
        }
    }
    const auto sum = tcp_sum + udp_sum;
    const bool in_window = sum >= lower && sum <= upper && upload_peer;
    if (in_window) {
        const bool udp_carried = udp_sum > 0 && tcp_sum < lower;
        result.verdict = UploadVerdict::Uploaded;
        result.destination = upload_peer->destination;
        result.match_basis = udp_carried ? "flow_txbytes_udp" : "flow_txbytes";
        result.transfer_outcome = result.match_basis + ";left_host;" + SumText(sum, lower, view.file_bytes);
        result.detail = "match=" + result.match_basis + ";" + SumText(sum, lower, view.file_bytes) +
            ";plaintext_not_recovered;no_ca;no_system_proxy;app_settings_not_modified";
        NoteSni(result, upload_peer);
        return result;
    }
    if (handshake) {
        result.verdict = UploadVerdict::NotVisible;
        result.destination = handshake->destination;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = IsProviderOrRelay(handshake->destination) || !handshake->sni.empty()
            ? "provider_or_relay_body_not_visible" : "tls_handshake_body_not_visible";
        result.detail = "tls_handshake_bytes_are_not_a_body;unresolved_not_a_clean_bill;not_rewritten_as_not_found;" +
            SumText(TxDelta(*handshake), lower, view.file_bytes) + ";app_settings_not_modified";
        NoteSni(result, handshake);
        return result;
    }
    if (unmeasured) {
        if (!view.window_settled) return Defer(UploadVerdict::NotVisible);
        result.verdict = UploadVerdict::NotVisible;
        result.destination = unmeasured->destination;
        result.match_basis = "observation_impossible";
        if (any_measured_offhost) result.transfer_outcome = "off_host_measurement_incomplete";
        else if (IsProviderOrRelay(unmeasured->destination)) result.transfer_outcome = "provider_or_relay_body_not_visible";
        else if (unmeasured->kind == LiveFlowKind::UdpOrQuic) result.transfer_outcome = "udp_or_quic_body_not_visible";
        else result.transfer_outcome = "channel_bytes_unreadable";
        result.detail = "off_host_body_not_fully_measured;unresolved_not_a_clean_bill;not_rewritten_as_not_found;app_settings_not_modified";
        if (!view.inspection_complete) result.detail += ";descriptors_or_flows_incomplete";
        return result;
    }
    if (attempt) {
        result.verdict = UploadVerdict::Attempted;
        result.destination = attempt->destination;
        result.match_basis = "flow_attempt";
        result.transfer_outcome = "flow_attempt;connect_not_completed;" + SumText(TxDelta(*attempt), lower, view.file_bytes);
        result.detail = "match=flow_attempt;file_open_observed;off_host_payload_not_delivered;app_settings_not_modified";
        return result;
    }
    if (sum > upper) {
        result.verdict = UploadVerdict::NotVisible;
        if (upload_peer) result.destination = upload_peer->destination;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "aggregate_above_window";
        result.detail = "measured_send_larger_than_file_plus_slack;file_may_be_inside;not_rewritten_as_not_found;" +
            SumText(sum, lower, view.file_bytes) + ";app_settings_not_modified";
        return result;
    }
    if (!view.inspection_complete && !loopback_send) {
        if (!view.window_settled) return Defer(UploadVerdict::NotVisible);
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "descriptors_or_flows_incomplete";
        result.detail = "inspection_incomplete;not_a_clean_bill;app_settings_not_modified";
        return result;
    }
    if (loopback_send && !any_offhost) {
        result.verdict = UploadVerdict::NotFound;
        result.destination = loopback_send->destination;
        result.match_basis = "live_agent_observed";
        result.transfer_outcome = "live_agent_observed_loopback_not_off_host;" +
            SumText(TxDelta(*loopback_send), lower, view.file_bytes);
        result.detail = "agent_seen;loopback_send_did_not_leave_host;app_settings_not_modified";
        if (!view.inspection_complete) result.detail += ";descriptors_or_flows_incomplete";
        return result;
    }
    if (!view.window_settled) return Defer(UploadVerdict::NotFound);
    if (view.process_exited && !saw_measured_flow) {
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "process_exited_before_send_measured";
        result.detail = "process_exited;no_measured_offhost_send;not_rewritten_as_not_found;app_settings_not_modified";
        return result;
    }
    if (view.file_open && sum == 0 && !handshake && !attempt && !unmeasured && !loopback_send &&
        !loopback_peer && !measured_offhost && !saw_proxy) {
        if (!view.window_settled) return Defer(UploadVerdict::NotVisible);
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "unseen_channel";
        result.detail = "no_measured_peer;tx_sum=0;empty_destination;not_rewritten_as_not_found;"
            "unresolved_not_a_clean_bill;app_settings_not_modified";
        return result;
    }
    result.verdict = UploadVerdict::NotFound;
    result.match_basis = "live_agent_observed";
    result.transfer_outcome = "live_agent_observed_no_upload";
    if (measured_offhost) result.destination = measured_offhost->destination;
    else if (loopback_peer) result.destination = loopback_peer->destination;
    result.detail = "agent_seen;file_open_observed;every_offhost_channel_measured;aggregate_below_lower_bound;" +
        SumText(sum, lower, view.file_bytes) + ";app_settings_not_modified";
    return result;
}
bool ShouldEmitCloseUpdate(int prior_rank, const std::string& prior_outcome, const LiveClose& next) noexcept {
    int rank = 0;
    switch (next.verdict) {
    case UploadVerdict::Uploaded: rank = 4; break;
    case UploadVerdict::Attempted: rank = 3; break;
    case UploadVerdict::NotVisible: rank = 2; break;
    case UploadVerdict::NotFound: rank = 1; break;
    }
    if (prior_rank <= 0) return true;
    if (rank < prior_rank) return false;
    // The same upload ticking upward (1615 then 1646) is one session.
    if (rank == prior_rank && next.verdict == UploadVerdict::Uploaded) return false;
    if (rank == prior_rank && prior_outcome == next.transfer_outcome) return false;
    if (rank == prior_rank && prior_outcome.find("loopback_not_off_host") != std::string::npos &&
        next.transfer_outcome.find("loopback_not_off_host") == std::string::npos) return false;
    return true;
}
uint64_t InitialFlowBaseline(bool process_already_sampled, uint64_t tx_bytes, uint64_t window_upper) noexcept {
    if (process_already_sampled) return 0;
    if (window_upper > 0 && tx_bytes <= window_upper) return 0;
    return tx_bytes;
}
std::string LiveVerdictSummary(const LiveClose& close, const std::string& process, const std::string& path) {
    const std::string label = UploadVerdictLabel(close.verdict);
    const std::string who = process.empty() ? "该进程" : process;
    const std::string dest = close.destination.empty() ? "（没有观察到目的地）" : close.destination;
    const std::string file = path.empty() ? "已登记文件" : path;
    switch (close.verdict) {
    case UploadVerdict::Uploaded:
        if (close.match_basis == "flow_txbytes_udp")
            return label + "。" + who + " 在打开 " + file + " 之后，向非回环地址 " + dest +
                " 发送的 UDP/QUIC 字节数落在压缩下界和文件大小加余量之间。匹配依据是 flow_txbytes_udp。这不是解密后的正文，也不是对端的独立回执。没有安装 CA 或系统代理。";
        return label + "。" + who + " 在打开 " + file + " 之后，向非回环地址 " + dest +
            " 发送的字节数落在压缩下界和文件大小加余量之间。匹配依据是 flow_txbytes（进程树上的发送字节数合计）。这不是解密后的正文，也不是对端的独立回执。没有安装 CA 或系统代理。";
    case UploadVerdict::Attempted:
        return label + "。" + who + " 打开了 " + file + "，并向 " + dest +
            " 发起了离开本机的连接，但没有把不少于压缩下界的字节送出去。结果：" + close.transfer_outcome + "。";
    case UploadVerdict::NotFound:
        if (path.empty())
            return label + "。已看到 " + who + "，没有发现它打开已登记文件，也没有看到离开本机的上传。结果：" + close.transfer_outcome + "。";
        return label + "。已看到 " + who + " 打开 " + file + "。整段观察窗口里已测量的离机发送字节数低于压缩下界。结果：" +
            close.transfer_outcome + "。";
    case UploadVerdict::NotVisible:
        return label + "。看不到能否判断 " + who + " 把 " + file + " 发出了本机。结果：" + close.transfer_outcome + "。";
    }
    return label;
}
bool ProxyBodyCoversLiveActor(const ProcessIdentity& proxy_actor, bool proxy_from_launched_tree,
    const ProcessIdentity& live_actor, bool live_in_launched_tree) noexcept {
    if (proxy_actor == live_actor) return true;
    return proxy_from_launched_tree && live_in_launched_tree;
}
bool IsProviderOrRelay(const std::string& destination) noexcept {
    std::string host = destination;
    if (!host.empty() && host[0] == '[') {
        const auto end = host.find(']');
        host = end == std::string::npos ? std::string() : host.substr(1, end - 1);
    } else {
        const auto colon = host.rfind(':');
        if (colon != std::string::npos) host.resize(colon);
    }
    for (char& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto ends = [&](const char* suffix) {
        const auto n = std::strlen(suffix);
        if (host.size() < n) return false;
        if (host.compare(host.size() - n, n, suffix) != 0) return false;
        return host.size() == n || host[host.size() - n - 1] == '.';
    };
    for (const char* suffix : {"anthropic.com", "claude.ai", "openai.com", "chatgpt.com", "azure.com",
        "googleapis.com", "amazonaws.com", "openrouter.ai", "groq.com", "together.ai", "together.xyz",
        "fireworks.ai", "mistral.ai", "cohere.com", "cohere.ai", "huggingface.co", "hf.co", "x.ai",
        "cursor.com", "cursor.sh", "githubcopilot.com"}) {
        if (ends(suffix)) return true;
    }
    return false;
}
bool Ipv4PeerOctets(bool ipv4_flag, const uint8_t address[16], uint8_t out[4]) noexcept {
    if (!out) return false;
    if (ipv4_flag) {
        std::memcpy(out, address + 12, 4);
        return true;
    }
    for (int i = 0; i < 10; ++i) if (address[i] != 0) return false;
    const bool mapped = address[10] == 0xff && address[11] == 0xff;
    const bool compatible = address[10] == 0 && address[11] == 0;
    if (!mapped && !compatible) return false;
    // :: and ::1 are IPv6. IPv4-compatible 0.0.0.0 and 0.0.0.1 use the same bytes.
    if (compatible && address[12] == 0 && address[13] == 0 && address[14] == 0) return false;
    std::memcpy(out, address + 12, 4);
    return true;
}
std::string FormatSocketPeer(bool ipv4_flag, const uint8_t address[16], uint16_t port) {
    uint8_t v4[4];
    if (Ipv4PeerOctets(ipv4_flag, address, v4)) {
        return std::to_string(v4[0]) + "." + std::to_string(v4[1]) + "." + std::to_string(v4[2]) + "." +
            std::to_string(v4[3]) + ":" + std::to_string(port);
    }
    char text[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, address, text, sizeof(text))) return "";
    return "[" + std::string(text) + "]:" + std::to_string(port);
}
} // namespace agentsec
