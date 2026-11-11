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
} // namespace agentsec
