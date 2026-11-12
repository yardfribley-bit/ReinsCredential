#include "EgressVerdict.h"

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
bool ConsistentOffHostSend(const LiveFlow& flow, uint64_t file_bytes) {
    if (flow.kind != LiveFlowKind::TcpMeasured || flow.loopback || flow.to_local_proxy || !flow.established) return false;
    if (file_bytes == 0) return false;
    const auto delta = TxDelta(flow);
    return delta >= file_bytes && delta <= file_bytes + kFlowTxSlack;
}
bool FailedOffHostAttempt(const LiveFlow& flow, uint64_t file_bytes) {
    if (flow.kind != LiveFlowKind::TcpMeasured || flow.loopback || flow.to_local_proxy || !flow.failed) return false;
    if (flow.preexisting && TxDelta(flow) == 0) return false;
    return file_bytes == 0 || TxDelta(flow) < file_bytes;
}
std::string DeltaText(const LiveFlow& flow, uint64_t file_bytes) {
    return "tx_delta=" + std::to_string(TxDelta(flow)) + ";file_bytes=" + std::to_string(file_bytes) +
        ";slack=" + std::to_string(kFlowTxSlack);
}
} // namespace

LiveClose CloseLiveAccess(const LiveAccessView& view) {
    LiveClose result;
    if (!view.agent_visible) {
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "agent_not_visible";
        result.detail = "inspection_incomplete;not_a_clean_bill;app_settings_not_modified";
        return result;
    }
    if (view.file_open && view.file_bytes == 0) {
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "registered_file_size_unknown";
        result.detail = "file_open_observed;size_unknown;cannot_correlate_send;app_settings_not_modified";
        return result;
    }
    const LiveFlow* upload = nullptr;
    const LiveFlow* attempt = nullptr;
    const LiveFlow* loopback_send = nullptr;
    const LiveFlow* unmeasured = nullptr;
    bool measured_tcp = false;
    for (const auto& flow : view.flows) {
        if (flow.to_local_proxy) continue;
        if (flow.kind == LiveFlowKind::TcpMeasured) measured_tcp = true;
        else if (view.file_open && !unmeasured) unmeasured = &flow;
        if (!upload && ConsistentOffHostSend(flow, view.file_bytes)) upload = &flow;
        else if (!attempt && view.file_open && FailedOffHostAttempt(flow, view.file_bytes)) attempt = &flow;
        if (view.file_open && flow.kind == LiveFlowKind::TcpMeasured && flow.loopback && !flow.to_local_proxy &&
            flow.established && view.file_bytes > 0 && TxDelta(flow) >= view.file_bytes && !loopback_send) {
            loopback_send = &flow;
        }
    }
    if (upload) {
        result.verdict = UploadVerdict::Uploaded;
        result.destination = upload->destination;
        result.match_basis = "flow_txbytes";
        result.transfer_outcome = "flow_txbytes;left_host;" + DeltaText(*upload, view.file_bytes);
        result.detail = "match=flow_txbytes;plaintext_not_recovered;no_ca;no_system_proxy;app_settings_not_modified";
        return result;
    }
    if (attempt) {
        result.verdict = UploadVerdict::Attempted;
        result.destination = attempt->destination;
        result.match_basis = "flow_attempt";
        result.transfer_outcome = "flow_attempt;connect_not_completed;" + DeltaText(*attempt, view.file_bytes);
        result.detail = "match=flow_attempt;file_open_observed;off_host_payload_not_delivered;app_settings_not_modified";
        return result;
    }
    // A partial descriptor listing must not erase a UDP/QUIC peer we already
    // saw. Both conclusions are 看不到; the peer is the one the chain can show.
    if (view.file_open && unmeasured && !measured_tcp) {
        result.verdict = UploadVerdict::NotVisible;
        result.destination = unmeasured->destination;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = unmeasured->kind == LiveFlowKind::UdpOrQuic ? "udp_or_quic_body_not_visible"
                                                                              : "channel_bytes_unreadable";
        result.detail = "unmeasured_channel_while_file_open;cannot_call_this_not_found;app_settings_not_modified";
        if (!view.inspection_complete) result.detail += ";descriptors_or_flows_incomplete";
        return result;
    }
    if (!view.inspection_complete) {
        result.verdict = UploadVerdict::NotVisible;
        result.match_basis = "observation_impossible";
        result.transfer_outcome = "descriptors_or_flows_incomplete";
        result.detail = "inspection_incomplete;not_a_clean_bill;app_settings_not_modified";
        return result;
    }
    result.verdict = UploadVerdict::NotFound;
    result.match_basis = "live_agent_observed";
    if (loopback_send) {
        result.destination = loopback_send->destination;
        result.transfer_outcome = "live_agent_observed_loopback_not_off_host;" + DeltaText(*loopback_send, view.file_bytes);
        result.detail = "agent_seen;loopback_send_did_not_leave_host;app_settings_not_modified";
    } else if (view.file_open) {
        result.transfer_outcome = "live_agent_observed_no_upload";
        result.detail = "agent_seen;file_open_observed;no_offhost_upload;app_settings_not_modified";
    } else {
        result.transfer_outcome = "live_agent_observed_no_access";
        result.detail = "agent_seen;no_registered_file_open;no_offhost_upload;app_settings_not_modified";
    }
    if (view.file_open && unmeasured) result.detail += ";udp_or_quic_not_counted";
    return result;
}
std::string LiveVerdictSummary(const LiveClose& close, const std::string& process, const std::string& path) {
    const std::string label = UploadVerdictLabel(close.verdict);
    const std::string who = process.empty() ? "该进程" : process;
    const std::string dest = close.destination.empty() ? "（没有观察到目的地）" : close.destination;
    const std::string file = path.empty() ? "已登记文件" : path;
    switch (close.verdict) {
    case UploadVerdict::Uploaded:
        return label + "。" + who + " 在打开 " + file + " 之后，向非回环地址 " + dest +
            " 发送的 TCP 字节数不少于该文件，并且没有超过登记的余量。匹配依据是 flow_txbytes（同一进程上的发送字节数）。这不是解密后的正文，也不是对端的独立回执。没有安装 CA 或系统代理。";
    case UploadVerdict::Attempted:
        return label + "。" + who + " 打开了 " + file + "，并向 " + dest +
            " 发起了离开本机的连接，但没有把不少于文件大小的字节送出去。结果：" + close.transfer_outcome + "。";
    case UploadVerdict::NotFound:
        if (path.empty())
            return label + "。已看到 " + who + "，没有发现它打开已登记文件，也没有看到离开本机的上传。结果：" + close.transfer_outcome + "。";
        return label + "。已看到 " + who + " 打开 " + file + "。已查看的 TCP 发送字节数里没有离开本机的上传。结果：" +
            close.transfer_outcome + "。";
    case UploadVerdict::NotVisible:
        return label + "。看不到能否判断 " + who + " 把 " + file + " 发出了本机。结果：" + close.transfer_outcome + "。";
    }
    return label;
}
} // namespace agentsec
