import Foundation

public extension EvidenceRecord {
    /// Entirely synthetic. Never merge these records into an imported log.
    static var sampleRecords: [EvidenceRecord] {
        let actor = ProcessNode(pid: 4201, ppid: 4200, name: "Demo Agent", path: "/Applications/Demo Agent.app/Contents/MacOS/DemoAgent")
        let parent = ProcessNode(pid: 4200, ppid: 1, name: "demo-launcher", path: "/synthetic/demo-launcher")
        let now = Date()
        return [
            EvidenceRecord(timestamp: now, riskLevel: .high, targetResource: "/synthetic/project/.env",
                actionType: "SUBMIT", processTree: [actor, parent], sourceType: "sensitive_payload_observed",
                attribution: "synthetic_demo", detail: "演示：在显式接入的内容通道中匹配到了测试内容。",
                destination: "https://example.invalid/demo", chainComplete: false,
                evidenceBasis: "synthetic content match", transferOutcome: "未验证远端接收", classification: "demo_agent"),
            EvidenceRecord(timestamp: now.addingTimeInterval(-90), riskLevel: .medium, targetResource: "/synthetic/.ssh/test-key",
                actionType: "OBSERVE", processTree: [actor, parent], sourceType: "sensitive_file_open",
                attribution: "synthetic_demo", detail: "演示：文件描述符观测；不能据此证明读取或上传。", chainComplete: false),
            EvidenceRecord(timestamp: now.addingTimeInterval(-180), riskLevel: .low, targetResource: "/synthetic/project/.env",
                actionType: "CHANGE", processTree: [], sourceType: "filesystem_change", attribution: "unavailable",
                detail: "演示：FSEvents 文件变更；未提供操作进程身份。")
        ]
    }
}
