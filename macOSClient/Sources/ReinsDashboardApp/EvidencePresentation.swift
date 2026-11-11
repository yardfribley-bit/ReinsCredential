import EvidenceCore

/// User-facing explanations preserve the backend's observation strength.
/// They never promote a descriptor or socket observation into a proven upload.
extension EvidenceRecord {
    var findingTitle: String {
        switch sourceType {
        case "agent_discovered": return "发现 Agent 候选进程"
        case "process_discovered": return "发现本机进程"
        case "agent_changed", "process_changed": return "进程映像或分类变化"
        case "agent_no_longer_observed", "process_no_longer_observed": return "进程不再可见"
        case "filesystem_change": return "敏感路径发生变化"
        case "sensitive_network_cooccurrence": return "敏感文件与网络连接同时可见"
        case "activity_observed":
            return targetResource.isEmpty ? "进程活动快照" : "进程持有敏感文件描述符"
        case "sensitive_access_observed":
            return evidenceBasis == "inferred" ? "敏感文件访问时间与一个进程重合" : "敏感文件访问时间发生变化"
        case "sensor_gap": return "采集覆盖出现间隙"
        case "fatal_error", "gateway_fatal": return "采集服务错误"
        case "coverage": return "采集健康状态"
        case "shutdown_summary": return "监控停止汇总"
        case "sensitive_payload_observed": return "提交内容匹配敏感数据"
        case "payload_observed": return "网关收到提交内容"
        case "sensitive_content_delivery_attempt": return "准备交付敏感内容"
        case "sensitive_content_delivered": return "内容已写入本地连接"
        case "transfer_result": return "网关转发结果"
        case "gateway_request_failed": return "网关请求失败"
        case "gateway_ready": return "内容网关已启动"
        default: return actionType
        }
    }

    var recommendedAction: String? {
        switch sourceType {
        case "activity_observed" where !targetResource.isEmpty:
            return "The file was open in this process. That shows who touched it. It does not show an upload."
        case "sensitive_access_observed" where evidenceBasis == "inferred":
            return "This link is only a timing overlap. The file was not seen open, and this is not an upload."
        case "sensitive_access_observed":
            return "The file's access time changed. No process was identified, and this is not an upload."
        case "sensitive_network_cooccurrence":
            return "A sensitive file and a network connection were both open. This is not an upload."
        case "filesystem_change":
            return "检查文件变化是否符合预期。文件系统事件不提供行为进程，无法据此指定某个 Agent。"
        case "sensor_gap":
            return "这一时段的采集可能不完整。查看说明中的缺口原因，检查监控目录和服务状态。"
        case "fatal_error", "gateway_fatal":
            return "查看下方错误说明和监控状态，处理权限、空间或配置问题后重新启动监控。"
        case "sensitive_payload_observed":
            return "提交内容已匹配受监控数据。核查目的地与关联的传输结果；提交记录本身不代表远端已接收。"
        case "transfer_result":
            return "根据传输结果和证据来源核查发送是否完成；远端接收需要独立回执支持。"
        default: return nil
        }
    }
}
