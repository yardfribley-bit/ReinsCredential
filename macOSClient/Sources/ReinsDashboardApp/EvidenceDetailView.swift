import EvidenceCore
import SwiftUI

struct EvidenceDetailView: View {
    let record: EvidenceRecord

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack {
                    Label("证据详情", systemImage: "doc.text.magnifyingglass")
                        .font(.headline)
                    Spacer()
                    RiskBadge(level: record.riskLevel)
                }
                detailSection("事件") {
                    DetailValue(title: "事件 ID", value: record.id.uuidString, monospaced: true)
                    DetailValue(title: "记录时间（本地）", value: Self.timestampFormatter.string(from: record.timestamp), monospaced: true)
                    DetailValue(title: "动作", value: record.actionType, monospaced: true)
                    if !record.sourceType.isEmpty {
                        DetailValue(title: "后端事件类型", value: record.sourceType, monospaced: true)
                    }
                    DetailValue(title: "目标资源", value: record.targetResource.isEmpty ? "未记录" : record.targetResource, monospaced: true)
                    if !record.destination.isEmpty {
                        DetailValue(title: "发送目的地", value: record.destination, monospaced: true)
                    }
                }

                detailSection("关联依据") {
                    DetailValue(title: "归因状态", value: record.attribution.isEmpty ? "未记录" : record.attribution)
                    if !record.classification.isEmpty {
                        DetailValue(title: "进程分类", value: record.classification)
                    }
                    if !record.evidenceBasis.isEmpty {
                        DetailValue(title: "证据来源", value: record.evidenceBasis)
                    }
                    if !record.transferOutcome.isEmpty {
                        DetailValue(title: "传输结果", value: record.transferOutcome)
                    }
                    if !record.detail.isEmpty {
                        DetailValue(title: "说明", value: record.detail)
                    }
                    Text("仅展示后端记录的结论。文件变化或打开的描述符本身不能证明读取或上传。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                detailSection("进程链") {
                    Text("行为进程 → 父进程 → 上层祖先")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if record.processTree.isEmpty {
                        Label("没有可归因的进程", systemImage: "person.crop.circle.badge.questionmark")
                            .font(.subheadline)
                    } else {
                        ForEach(Array(record.processTree.enumerated()), id: \.offset) { index, process in
                            ProcessNodeView(process: process, isActor: index == 0)
                            if index < record.processTree.count - 1 {
                                Image(systemName: "arrow.down")
                                    .font(.caption)
                                    .foregroundStyle(.tertiary)
                                    .padding(.leading, 12)
                                    .accessibilityHidden(true)
                            }
                        }
                    }
                    Text(chainStatus)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(20)
        }
        .background(.ultraThinMaterial)
        .textSelection(.enabled)
    }

    private var chainStatus: String {
        switch record.chainComplete {
        case .some(true): return "后端标记：进程链完整。"
        case .some(false): return "后端标记：进程链不完整，部分祖先不可用。"
        case .none: return "后端未提供进程链完整性标记。"
        }
    }

    private func detailSection<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.subheadline.weight(.semibold))
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS ZZZZZ"
        return formatter
    }()
}

private struct DetailValue: View {
    let title: String
    let value: String
    var monospaced = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .system(.caption, design: .monospaced) : .subheadline)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct ProcessNodeView: View {
    let process: ProcessNode
    let isActor: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(alignment: .firstTextBaseline) {
                Text(process.name.isEmpty ? "未知进程" : process.name)
                    .font(.subheadline.weight(.medium))
                Spacer()
                if isActor {
                    Text("行为进程").font(.caption2).foregroundStyle(.secondary)
                }
            }
            Text("PID \(String(process.pid))  ·  PPID \(String(process.ppid))")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            if let seconds = process.startSeconds, let microseconds = process.startMicroseconds {
                Text("启动世代 \(seconds).\(String(format: "%06llu", microseconds))")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
            }
            Text(process.path.isEmpty ? "可执行路径未记录" : process.path)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.primary.opacity(0.07)))
    }
}
