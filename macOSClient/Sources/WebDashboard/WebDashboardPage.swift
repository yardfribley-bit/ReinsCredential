import Foundation

struct WebBoardQuery: Equatable {
    var view: String
    var agent: String
    var risk: String
    var search: String
    var chain: String?
    var event: String?

    static func parse(_ raw: String) -> WebBoardQuery {
        let items = URLComponents(string: "/?" + raw)?.queryItems ?? []
        func value(_ name: String) -> String? { items.last { $0.name == name }?.value }
        let view = value("view") == "events" ? "events" : "chains"
        let riskRaw = (value("risk") ?? "all").lowercased()
        let risk = ["all", "high", "medium", "low"].contains(riskRaw) ? riskRaw : "all"
        let agent = String((value("agent") ?? "all").prefix(200))
        let search = String((value("q") ?? "").prefix(200))
        return WebBoardQuery(view: view, agent: agent.isEmpty ? "all" : agent, risk: risk,
                             search: search,
                             chain: value("chain").map { String($0.prefix(80)) },
                             event: value("event").map { String($0.prefix(80)) })
    }

    func url() -> String {
        var items = [
            URLQueryItem(name: "view", value: view),
            URLQueryItem(name: "agent", value: agent),
            URLQueryItem(name: "risk", value: risk)
        ]
        if !search.isEmpty { items.append(URLQueryItem(name: "q", value: search)) }
        if let chain, !chain.isEmpty { items.append(URLQueryItem(name: "chain", value: chain)) }
        if let event, !event.isEmpty { items.append(URLQueryItem(name: "event", value: event)) }
        var components = URLComponents()
        components.queryItems = items
        let query = components.percentEncodedQuery ?? ""
        return query.isEmpty ? "/" : "/?\(query)"
    }
}

enum WebDashboardPage {
    static func html(snapshot: WebDashboardSnapshot, query: WebBoardQuery, port: UInt16) -> String {
        let searched = query.search.trimmingCharacters(in: .whitespacesAndNewlines)
        let matching = snapshot.records.filter { record in
            guard riskIncludes(query.risk, record.riskLevel) else { return false }
            guard searched.isEmpty || recordMatches(record, searched) else { return false }
            return true
        }
        let chainPool = EvidenceChainBuilder.chains(from: matching)
        let sections = chainPool.groupedByOwningAgent()
        let listedChains = chainPool.filter { agentIncludes(query.agent, name: $0.owningAgentName) }
        let listedRecords = matching.filter { agentIncludes(query.agent, name: $0.owningAgentName) }
        let selectedChain = listedChains.first { idsEqual($0.id, query.chain) } ?? listedChains.first
        let selectedRecord = listedRecords.first { idsEqual($0.id, query.event) } ?? listedRecords.first
        let boardTitle = query.view == "events" ? riskTitle(query.risk) : "证据链"
        let count = query.view == "events" ? listedRecords.count : listedChains.count
        let countLabel = query.view == "events" ? "\(count) 条记录" : "\(count) 条证据链"

        var body = """
        <!DOCTYPE html>
        <html lang="zh-Hans">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="2">
        <meta name="referrer" content="no-referrer">
        <title>ReinsCredential</title>
        <style>
        \(css)
        </style>
        </head>
        <body>
        <aside>
          <header class="brand">
            <p class="mark">ReinsCredential</p>
            <h2>运行时安全</h2>
            <p class="quiet">本机 Agent 监控</p>
          </header>
          <nav aria-label="所属 Agent">
            <h2>所属 Agent</h2>
            \(agentLinks(sections: sections, total: chainPool.count, query: query))
          </nav>
          <footer class="mode">
            <p><strong>\(snapshot.live ? "本机实时监控" : "日志快照")</strong></p>
            <p class="quiet">\(WebHTML.text(statusCopy(snapshot)))</p>
            <p class="quiet">每 2 秒自动刷新。只读，不启动采集。</p>
          </footer>
        </aside>
        <main>
          <div class="toolbar">
            \(datasetNotice(snapshot))
            <div class="title-row">
              <h2>\(WebHTML.escape(boardTitle))</h2>
              <p class="count">\(WebHTML.escape(countLabel))</p>
            </div>
            <div class="switch" role="tablist" aria-label="视图">
              \(viewLink("证据链", view: "chains", query: query))
              \(viewLink("事件", view: "events", query: query))
            </div>
            <div class="filters">
              \(riskLink("全部证据", risk: "all", query: query))
              \(riskLink("高风险", risk: "high", query: query))
              \(riskLink("中风险", risk: "medium", query: query))
              \(riskLink("低风险", risk: "low", query: query))
            </div>
            <form method="get" action="/">
              <input type="hidden" name="view" value="\(WebHTML.attr(query.view))">
              <input type="hidden" name="agent" value="\(WebHTML.attr(query.agent))">
              <input type="hidden" name="risk" value="\(WebHTML.attr(query.risk))">
              <label>搜索 Agent、文件、目的地或结论
                <input type="search" name="q" value="\(WebHTML.attr(query.search))" maxlength="200">
              </label>
            </form>
            \(banners(snapshot))
          </div>
          \(query.view == "events"
            ? eventList(listedRecords, selected: selectedRecord, query: query, storeHasRecords: !snapshot.records.isEmpty, live: snapshot.live)
            : chainList(sections: listedChains.groupedByOwningAgent(), selected: selectedChain, query: query, storeHasRecords: !snapshot.records.isEmpty, live: snapshot.live))
          <p class="glossary">\(WebHTML.text(EvidenceChainExport.glossaryText))</p>
        </main>
        <section class="detail" aria-label="详情">
          \(query.view == "events" ? eventDetail(selectedRecord) : chainDetail(selectedChain, records: snapshot.records))
        </section>
        </body>
        </html>
        """
        return body + "\n<!-- http://127.0.0.1:\(port)/ -->\n"
    }

    static func snapshotJSON(_ snapshot: WebDashboardSnapshot) -> String {
        WebDashboardDisplay.redact(EvidenceChainExport.json(EvidenceChainBuilder.chains(from: snapshot.records)))
    }

    private static func idsEqual(_ id: UUID, _ raw: String?) -> Bool {
        guard let raw else { return false }
        return id.uuidString.caseInsensitiveCompare(raw) == .orderedSame
    }

    private static func riskIncludes(_ risk: String, _ level: RiskLevel) -> Bool {
        risk == "all" || risk.uppercased() == level.rawValue
    }

    private static func agentIncludes(_ agent: String, name: String) -> Bool {
        switch agent {
        case "all": return true
        case "unattributed": return name.isEmpty
        default: return name == agent
        }
    }

    private static func riskTitle(_ risk: String) -> String {
        switch risk {
        case "high": return "高风险"
        case "medium": return "中风险"
        case "low": return "低风险"
        default: return "全部证据"
        }
    }

    private static func recordMatches(_ record: EvidenceRecord, _ query: String) -> Bool {
        let fields = [record.targetResource, record.actionType, record.sourceType, record.destination,
                      record.id.uuidString, record.owningAgentName, record.uploadVerdict, record.summary,
                      UploadVerdictWord.parse(record.uploadVerdict).chineseLabel]
            + record.processTree.flatMap { [$0.name, $0.path, String($0.pid)] }
        return fields.contains { $0.localizedCaseInsensitiveContains(query) }
    }

    private static func statusCopy(_ snapshot: WebDashboardSnapshot) -> String {
        var parts: [String] = []
        if let count = snapshot.watchedDirectories { parts.append("\(count) 个监控目录") }
        if let status = snapshot.statusLine { parts.append(status) }
        parts.append(snapshot.live ? "按 Agent 分组" : "当前显示指定日志")
        if !snapshot.sourceNames.isEmpty { parts.append("读取 " + snapshot.sourceNames.joined(separator: "、")) }
        return parts.joined(separator: " · ")
    }

    private static func datasetNotice(_ snapshot: WebDashboardSnapshot) -> String {
        let title = snapshot.live ? "本机采集结果" : "日志快照"
        let body = snapshot.live
            ? "持续显示采集服务的实际记录。高风险表示需要核查的证据，不等同于已确认泄露。状态文件只说明后台进程，不证明采集覆盖。"
            : "只读显示指定的证据日志。这个页面不启动采集，也不改写证据。"
        return """
        <div class="notice"><p><strong>\(title)</strong></p><p>\(body)</p></div>
        """
    }

    private static func banners(_ snapshot: WebDashboardSnapshot) -> String {
        var parts: [String] = []
        if snapshot.records.contains(where: { $0.sourceType == "sensor_gap" }) {
            parts.append("<p class=\"banner\">这一时段的采集有缺口，证据链可能少了事件。</p>")
        }
        if snapshot.rejectedCount > 0 {
            parts.append("<p class=\"banner\">跳过 \(snapshot.rejectedCount) 行无效或重复记录</p>")
        }
        if snapshot.incompleteTail {
            parts.append("<p class=\"banner\">文件末尾有未完成记录，已忽略。</p>")
        }
        if snapshot.truncated {
            parts.append("<p class=\"banner\">只显示最新 \(WebDashboardSnapshot.recordCap) 条记录。</p>")
        }
        for error in snapshot.errors {
            parts.append("<p class=\"banner\">\(WebHTML.text(error))</p>")
        }
        return parts.joined()
    }

    private static func agentLinks(sections: [EvidenceChainSection], total: Int, query: WebBoardQuery) -> String {
        var links = navLink(title: "全部证据链", count: total, current: query.agent == "all",
                            href: query.replacing(agent: "all", chain: nil, event: nil).url())
        for section in sections {
            let agent = section.id == "unattributed" ? "unattributed" : section.title
            links += navLink(title: section.title, count: section.chains.count, current: query.agent == agent,
                             href: query.replacing(agent: agent, chain: nil, event: nil).url())
        }
        return links
    }

    private static func navLink(title: String, count: Int, current: Bool, href: String) -> String {
        let currentAttr = current ? " aria-current=\"true\"" : ""
        return "<a class=\"agent\"\(currentAttr) href=\"\(WebHTML.attr(href))\"><span>\(WebHTML.text(title))</span><span class=\"num\">\(count)</span></a>"
    }

    private static func viewLink(_ title: String, view: String, query: WebBoardQuery) -> String {
        let href = query.replacing(view: view, chain: nil, event: nil).url()
        let current = query.view == view ? " aria-current=\"true\"" : ""
        return "<a\(current) href=\"\(WebHTML.attr(href))\">\(WebHTML.escape(title))</a>"
    }

    private static func riskLink(_ title: String, risk: String, query: WebBoardQuery) -> String {
        let href = query.replacing(risk: risk, chain: nil, event: nil).url()
        let current = query.risk == risk ? " aria-current=\"true\"" : ""
        return "<a\(current) href=\"\(WebHTML.attr(href))\">\(WebHTML.escape(title))</a>"
    }

    private static func chainList(sections: [EvidenceChainSection], selected: EvidenceChain?, query: WebBoardQuery,
                                  storeHasRecords: Bool, live: Bool) -> String {
        if sections.allSatisfy({ $0.chains.isEmpty }) {
            return emptyState(query: query, storeHasRecords: storeHasRecords, live: live, chainsView: true)
        }
        var html = ""
        for section in sections where !section.chains.isEmpty {
            html += "<section class=\"group\"><h3>\(WebHTML.text(section.title))</h3>"
            if !section.subtitle.isEmpty { html += "<p class=\"quiet\">\(WebHTML.text(section.subtitle))</p>" }
            html += "<ul class=\"rows\">"
            for chain in section.chains {
                let href = query.replacing(chain: chain.id.uuidString, event: nil).url()
                let current = selected?.id == chain.id ? " aria-current=\"true\"" : ""
                let file = chain.filePath.isEmpty ? "没有对应文件" : chain.filePath
                let who = chain.owningAgentName.isEmpty ? "未归属" : chain.owningAgentName
                html += """
                <li><a\(current) href="\(WebHTML.attr(href))">
                  <span class="pill \(verdictClass(chain.verdict))">\(WebHTML.text(chain.verdictLabel))</span>
                  <time>\(WebHTML.escape(stamp(chain.timestamp)))</time>
                  <strong>\(WebHTML.text(file))</strong>
                  <span class="quiet">\(WebHTML.text(who))</span>
                </a></li>
                """
            }
            html += "</ul></section>"
        }
        return html
    }

    private static func eventList(_ records: [EvidenceRecord], selected: EvidenceRecord?, query: WebBoardQuery,
                                  storeHasRecords: Bool, live: Bool) -> String {
        if records.isEmpty { return emptyState(query: query, storeHasRecords: storeHasRecords, live: live, chainsView: false) }
        var html = "<table><thead><tr><th>风险</th><th>时间</th><th>检测项</th><th>进程 / 资源</th></tr></thead><tbody>"
        for record in records {
            let href = query.replacing(view: "events", event: record.id.uuidString, chain: nil).url()
            let current = selected?.id == record.id ? " aria-current=\"true\"" : ""
            let process = record.summary.isEmpty ? (record.processTree.first?.name ?? "未归因") : record.summary
            let resource = record.targetResource.isEmpty ? "无文件资源" : record.targetResource
            html += """
            <tr><td><a\(current) href="\(WebHTML.attr(href))"><span class="pill \(riskClass(record.riskLevel))">\(WebHTML.escape(riskLabel(record.riskLevel)))</span></a></td>
            <td><a href="\(WebHTML.attr(href))">\(WebHTML.escape(stamp(record.timestamp)))</a></td>
            <td><a href="\(WebHTML.attr(href))">\(WebHTML.text(findingTitle(record)))</a></td>
            <td><a href="\(WebHTML.attr(href))"><strong>\(WebHTML.text(process))</strong><br><span class="quiet">\(WebHTML.text(resource))</span></a></td></tr>
            """
        }
        html += "</tbody></table>"
        return html
    }

    private static func emptyState(query: WebBoardQuery, storeHasRecords: Bool, live: Bool, chainsView: Bool) -> String {
        let filtered = !query.search.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            || query.risk != "all" || query.agent != "all"
        if chainsView && storeHasRecords && !filtered {
            return "<div class=\"empty\"><h3>还没有证据链</h3><p>敏感文件访问会按所属 Agent 收在这里。进程发现和健康记录留在「事件」里，不会被编成一次访问。</p></div>"
        }
        if storeHasRecords || filtered {
            return "<div class=\"empty\"><h3>没有匹配的证据</h3><p>调整 Agent、风险或搜索条件。</p></div>"
        }
        if live {
            return "<div class=\"empty\"><h3>等待本机检测记录</h3><p>这里只读本机证据日志。采集仍由现有的 ReinsCredential 服务负责。新记录会自动出现。合成自检文件若出现，只说明描述符和本机连接同时出现，不是上传。</p></div>"
        }
        return "<div class=\"empty\"><h3>此快照没有证据记录</h3><p>这个文件里没有完整的证据记录。</p></div>"
    }

    private static func chainDetail(_ chain: EvidenceChain?, records: [EvidenceRecord]) -> String {
        guard let chain else {
            return "<h2>证据链</h2><div class=\"empty\"><h3>选择一条证据链</h3><p>一条链对应一次敏感文件访问，或一条没有看到打开的传输。缺失的环节会标出来。</p></div>"
        }
        var html = "<h2>证据链</h2><p class=\"headline\">\(WebHTML.text(chain.headline))</p>"
        html += "<p class=\"pill \(verdictClass(chain.verdict))\">\(WebHTML.text(chain.verdictLabel))</p><ol class=\"steps\">"
        for link in chain.links {
            html += """
            <li>
              <p><strong>\(WebHTML.text(link.title))</strong> <span class="quiet">\(WebHTML.text(link.presence.displayName))</span></p>
              <p>\(WebHTML.text(link.value))</p>
              \(link.note.isEmpty ? "" : "<p class=\"quiet\">\(WebHTML.text(link.note))</p>")
            </li>
            """
        }
        html += "</ol>"
        if chain.missingReferenceCount > 0 {
            html += "<p class=\"banner\">有 \(chain.missingReferenceCount) 个关联事件不在当前快照里，没有补造。</p>"
        }
        if !chain.backendSummary.isEmpty {
            html += "<h3>采集原句</h3><p>\(WebHTML.text(chain.backendSummary))</p>"
        }
        html += "<h3>相关事件</h3>"
        let members = records.filter { chain.memberIDs.contains($0.id) }
            .sorted { $0.timestamp == $1.timestamp ? $0.id.uuidString < $1.id.uuidString : $0.timestamp < $1.timestamp }
        if members.isEmpty { html += "<p class=\"quiet\">当前快照里没有展开这些事件。</p>" }
        for record in members {
            html += "<p>\(WebHTML.text(findingTitle(record))) · \(WebHTML.escape(stamp(record.timestamp)))</p>"
        }
        html += "<p class=\"quiet\">\(WebHTML.text(chainStatus(chain)))</p>"
        return html
    }

    private static func eventDetail(_ record: EvidenceRecord?) -> String {
        guard let record else {
            return "<h2>证据详情</h2><div class=\"empty\"><h3>选择一条证据</h3><p>查看资源、进程链与后端记录的关联依据。</p></div>"
        }
        let summary = record.summary.isEmpty ? findingTitle(record) : record.summary
        var html = """
        <h2>证据详情</h2>
        <p class="headline">\(WebHTML.text(summary))</p>
        <p><span class="pill \(riskClass(record.riskLevel))">\(WebHTML.escape(riskLabel(record.riskLevel)))</span>
        """
        if !record.uploadVerdict.isEmpty {
            let verdict = UploadVerdictWord.parse(record.uploadVerdict)
            html += " <span class=\"pill \(verdictClass(verdict))\">\(WebHTML.text(verdict.chineseLabel))</span>"
        }
        html += "</p>"
        if let action = recommendedAction(record) { html += "<p class=\"quiet\">\(WebHTML.escape(action))</p>" }
        html += "<h3>事件</h3>"
        html += row("事件 ID", record.id.uuidString)
        html += row("记录时间（本地）", fullStamp(record.timestamp))
        html += row("动作", record.actionType)
        if !record.sourceType.isEmpty { html += row("后端事件类型", record.sourceType) }
        html += row("目标资源", record.targetResource.isEmpty ? "未记录" : record.targetResource)
        if !record.destination.isEmpty { html += row("发送目的地", record.destination) }
        if !record.contentSHA256.isEmpty { html += row("内容摘要 SHA-256", record.contentSHA256) }
        html += "<h3>关联依据</h3>"
        html += row("归因状态", record.attribution.isEmpty ? "未记录" : record.attribution)
        if !record.owningAgentName.isEmpty {
            let agent = record.owningAgentBundle.isEmpty ? record.owningAgentName : "\(record.owningAgentName)（\(record.owningAgentBundle)）"
            html += row("所属 Agent", agent)
        }
        if !record.classification.isEmpty { html += row("进程分类", record.classification) }
        if !record.evidenceBasis.isEmpty { html += row("证据来源", record.evidenceBasis) }
        if !record.transferOutcome.isEmpty { html += row("传输结果", record.transferOutcome) }
        if !record.detail.isEmpty { html += row("说明", record.detail) }
        html += "<p class=\"quiet\">仅展示后端记录的结论。文件变化或打开的描述符本身不能证明读取或上传。</p>"
        html += "<h3>进程链</h3><p class=\"quiet\">行为进程 → 父进程 → 上层祖先</p>"
        if record.processTree.isEmpty {
            html += "<p>没有可归因的进程</p>"
        } else {
            for (index, process) in record.processTree.enumerated() {
                let name = process.name.isEmpty ? "未知进程" : process.name
                html += "<p><strong>\(WebHTML.text(name))</strong>"
                if index == 0 { html += " <span class=\"quiet\">行为进程</span>" }
                html += "<br><span class=\"quiet\">PID \(process.pid) · PPID \(process.ppid)</span>"
                if let seconds = process.startSeconds, let microseconds = process.startMicroseconds {
                    html += "<br><span class=\"quiet\">启动世代 \(seconds).\(String(format: "%06llu", microseconds))</span>"
                }
                let path = process.path.isEmpty ? "可执行路径未记录" : process.path
                html += "<br><span class=\"quiet\">\(WebHTML.text(path))</span></p>"
            }
        }
        html += "<p class=\"quiet\">\(WebHTML.text(recordChainStatus(record)))</p>"
        return html
    }

    private static func row(_ title: String, _ value: String) -> String {
        "<p><span class=\"quiet\">\(WebHTML.escape(title))</span><br>\(WebHTML.text(value))</p>"
    }

    private static func chainStatus(_ chain: EvidenceChain) -> String {
        switch chain.chainStatus {
        case "observed_chain_to_root": return "进程链到达根进程。"
        case "observed_chain_to_launchd": return "进程链到达 launchd（pid 1）。"
        case "missing_parent": return "进程链不完整：没有观察到父进程。"
        case let status where !status.isEmpty: return "进程链：\(status)。"
        default:
            switch chain.chainComplete {
            case .some(true): return "进程链标记为完整。"
            case .some(false): return "进程链不完整。"
            case .none: return "没有记录进程链状态。"
            }
        }
    }

    private static func recordChainStatus(_ record: EvidenceRecord) -> String {
        switch record.chainStatus {
        case "observed_chain_to_root": return "进程链到达根进程。"
        case "observed_chain_to_launchd": return "进程链到达 launchd（pid 1）。launchd 自己的启动时间没有读到。"
        case "missing_parent": return "进程链不完整：没有观察到父进程。"
        case let status where !status.isEmpty: return "进程链：\(status)。"
        default:
            switch record.chainComplete {
            case .some(true): return "进程链标记为完整。"
            case .some(false): return "进程链不完整。"
            case .none: return "没有记录进程链状态。"
            }
        }
    }

    private static func riskLabel(_ level: RiskLevel) -> String {
        switch level {
        case .high: return "高风险"
        case .medium: return "中风险"
        case .low: return "低风险"
        }
    }

    private static func riskClass(_ level: RiskLevel) -> String {
        switch level {
        case .high: return "high"
        case .medium: return "medium"
        case .low: return "low"
        }
    }

    private static func verdictClass(_ verdict: UploadVerdictWord) -> String {
        switch verdict {
        case .uploaded: return "high"
        case .attempted: return "medium"
        case .notFound: return "low"
        case .notVisible: return "unseen"
        case .absent, .unrecognized: return "low"
        }
    }

    private static func stamp(_ date: Date) -> String {
        clock.string(from: date)
    }

    private static func fullStamp(_ date: Date) -> String {
        full.string(from: date)
    }

    private static let clock: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "zh_CN")
        formatter.dateFormat = "HH:mm:ss"
        return formatter
    }()

    private static let full: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS ZZZZZ"
        return formatter
    }()

    private static func findingTitle(_ record: EvidenceRecord) -> String {
        switch record.sourceType {
        case "agent_discovered": return "发现 Agent 候选进程"
        case "process_discovered": return "发现本机进程"
        case "agent_changed", "process_changed": return "进程映像或分类变化"
        case "agent_no_longer_observed", "process_no_longer_observed": return "进程不再可见"
        case "filesystem_change": return "敏感路径发生变化"
        case "sensitive_network_cooccurrence": return "敏感文件与网络连接同时可见"
        case "activity_observed": return record.targetResource.isEmpty ? "进程活动快照" : "进程持有敏感文件描述符"
        case "sensitive_access_observed":
            return record.evidenceBasis == "inferred" ? "敏感文件访问时间与一个进程重合" : "敏感文件访问时间发生变化"
        case "sensor_gap": return "采集覆盖出现间隙"
        case "fatal_error", "gateway_fatal": return "采集服务错误"
        case "coverage": return "采集健康状态"
        case "shutdown_summary": return "监控停止汇总"
        case "sensitive_payload_observed": return "提交内容匹配敏感数据"
        case "payload_observed": return "网关收到提交内容"
        case "sensitive_content_delivery_attempt": return "准备交付敏感内容"
        case "sensitive_content_delivered": return "内容已写入本地连接"
        case "transfer_result": return "网关转发结果"
        case "egress_transfer": return "本地出口代理看到的传输"
        case "sensitive_access_closed": return "敏感文件访问的出口结论"
        case "egress_channel_unseen": return "出口通道内容不可见"
        case "egress_proxy_ready": return "本地出口代理已启动"
        case "egress_proxy_stopped": return "本地出口代理已停止"
        case "gateway_request_failed": return "网关请求失败"
        case "gateway_ready": return "内容网关已启动"
        default: return record.actionType
        }
    }

    private static func recommendedAction(_ record: EvidenceRecord) -> String? {
        switch record.sourceType {
        case "activity_observed" where !record.targetResource.isEmpty:
            return "文件在这个进程里打开过。这能说明是谁接触了它，不能说明已经上传。"
        case "sensitive_access_observed" where record.evidenceBasis == "inferred":
            return "这只是时间上的重合。没有看到文件被打开，也不是上传。"
        case "sensitive_access_observed":
            return "文件的访问时间变了。没有识别到进程，也不是上传。"
        case "sensitive_network_cooccurrence":
            return "敏感文件和网络连接同时开着。这不是上传。"
        case "filesystem_change":
            return "检查文件变化是否符合预期。文件系统事件不提供行为进程，无法据此指定某个 Agent。"
        case "sensor_gap":
            return "这一时段的采集可能不完整。查看说明中的缺口原因，检查监控目录和服务状态。"
        case "fatal_error", "gateway_fatal":
            return "查看下方错误说明和监控状态，处理权限、空间或配置问题后重新启动监控。"
        case "sensitive_payload_observed":
            return "提交内容已匹配受监控数据。核查目的地与关联的传输结果；提交记录本身不代表远端已接收。"
        case "transfer_result", "egress_transfer":
            return "根据传输结果和证据来源核查发送是否完成；远端接收需要独立回执支持。"
        case "sensitive_access_closed" where record.uploadVerdict == "uploaded":
            return "请求体与已登记内容匹配，并且目的地返回了成功状态。这不是对端的独立回执。"
        case "sensitive_access_closed" where record.uploadVerdict == "attempted":
            return "请求体与已登记内容匹配，但这次传输没有成功。"
        case "sensitive_access_closed" where record.uploadVerdict == "not_found":
            return "已查看的出口里没有看到已登记内容离开本机。"
        case "sensitive_access_closed" where record.uploadVerdict == "not_visible":
            return "这个通道的内容看不到。不能把它写成未发现。"
        case "egress_channel_unseen":
            return "只看到了通道或对端，没有看到字节。这不是未发现。"
        default: return nil
        }
    }

    private static let css = """
    :root { color-scheme: light; --ink:#1c1915; --paper:#f3efe6; --panel:#fffdf8; --line:#e3d9c8;
      --sidebar:#1c2830; --side:#f4efe6; --muted:#5c564c; --accent:#8c3f24; --high:#8d2f2f;
      --medium:#8a5a12; --low:#1e4d78; --unseen:#5c3d73; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; display:grid; grid-template-columns:240px minmax(0,1fr) minmax(280px,380px);
      background:var(--paper); color:var(--ink); font:15px/1.45 "PingFang SC","Hiragino Sans GB","Noto Sans SC","Source Han Sans SC",sans-serif; }
    aside { background:var(--sidebar); color:var(--side); display:flex; flex-direction:column; min-height:100vh; }
    .brand, .mode { padding:18px 16px; }
    .mark { margin:0 0 8px; font-weight:700; letter-spacing:.01em; }
    h2, h3 { margin:0 0 8px; font-size:1rem; }
    h3 { font-size:.95rem; }
    .quiet, .mode .quiet { color:#c9c0b2; font-size:.82rem; }
    main .quiet, .detail .quiet { color:var(--muted); }
    nav { padding:0 10px 12px; overflow:auto; }
    nav h2 { padding:8px 6px 4px; font-size:.78rem; letter-spacing:.04em; text-transform:none; color:#c9c0b2; }
    a { color:inherit; text-decoration:none; }
    a:hover { text-decoration:underline; }
    a:focus-visible, button:focus-visible, input:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
    .agent, .switch a, .filters a { display:flex; justify-content:space-between; gap:8px; padding:7px 8px; border-radius:8px; }
    .agent[aria-current="true"], .switch a[aria-current="true"], .filters a[aria-current="true"], .rows a[aria-current="true"] {
      background:rgba(255,255,255,.12); text-decoration:none; }
    main .switch a[aria-current="true"], main .filters a[aria-current="true"], .rows a[aria-current="true"] { background:#efe2d2; }
    .num { font-variant-numeric:tabular-nums; color:#c9c0b2; }
    .mode { margin-top:auto; border-top:1px solid rgba(255,255,255,.08); }
    main { min-width:0; padding:18px 20px 28px; }
    .detail { background:var(--panel); border-left:1px solid var(--line); padding:18px 16px 28px; min-width:0; }
    .title-row, .switch, .filters { display:flex; gap:8px; align-items:baseline; flex-wrap:wrap; }
    .title-row { justify-content:space-between; }
    .count { color:var(--muted); font-variant-numeric:tabular-nums; }
    .switch, .filters, form, .notice { margin:10px 0; }
    form label { display:block; font-size:.82rem; color:var(--muted); }
    input[type="search"] { width:100%; margin-top:4px; padding:8px 10px; border:1px solid var(--line); border-radius:8px; background:#fff; color:inherit; font:inherit; }
    .notice, .banner, .empty { padding:10px 12px; border-radius:10px; }
    .notice { background:#fff; border:1px solid var(--line); }
    .banner { background:#f8ead2; color:#6a4a12; margin:8px 0; }
    .rows { list-style:none; margin:0; padding:0; }
    .rows a, table a { display:block; padding:8px 10px; border-radius:8px; }
    table { width:100%; border-collapse:collapse; }
    th { text-align:left; font-size:.78rem; color:var(--muted); font-weight:600; padding:6px; }
    td { vertical-align:top; border-top:1px solid var(--line); }
    .pill { display:inline-block; padding:2px 8px; border-radius:999px; font-size:.75rem; font-weight:650; }
    .high { color:var(--high); background:#f8e4e4; }
    .medium { color:var(--medium); background:#f8efd8; }
    .low { color:var(--low); background:#e5eef6; }
    .unseen { color:var(--unseen); background:#f0e8f6; }
    .headline { font-size:1.05rem; font-weight:650; }
    .steps { margin:12px 0; padding-left:1.1rem; }
    .steps li { margin:0 0 10px; }
    .glossary { font-size:.75rem; color:var(--muted); }
    .group { margin-top:14px; }
    @media (max-width:960px) {
      body { grid-template-columns:1fr; }
      aside { min-height:0; }
      .detail { border-left:0; border-top:1px solid var(--line); }
    }
    """
}

private extension WebBoardQuery {
    /// `chain` and `event` replace the previous selection. Pass nil to clear it.
    func replacing(view: String? = nil, agent: String? = nil, risk: String? = nil,
                   chain: String? = nil, event: String? = nil) -> WebBoardQuery {
        var copy = self
        if let view { copy.view = view }
        if let agent { copy.agent = agent }
        if let risk { copy.risk = risk }
        copy.chain = chain
        copy.event = event
        return copy
    }
}
