import EvidenceCore
import Foundation

// Read finished collector JSONL and write the same evidence-chain JSON the
// dashboard exports. This process does not start a collector or open a socket.

var arguments = Array(CommandLine.arguments.dropFirst())
let markdown = arguments.first == "--markdown"
if markdown { arguments.removeFirst() }
if arguments.isEmpty || arguments.contains("-h") || arguments.contains("--help") {
    FileHandle.standardError.write(Data("usage: chain-export [--markdown] LOG.jsonl [LOG.jsonl ...]\n".utf8))
    exit(2)
}

do {
    var records: [EvidenceRecord] = []
    var rejected = 0
    for path in arguments {
        var data = try Data(contentsOf: URL(fileURLWithPath: path))
        if data.isEmpty { continue }
        if data.last != 0x0A { data.append(0x0A) }
        let parsed = try EvidenceLogReader.parse(data)
        records.append(contentsOf: parsed.records)
        rejected += parsed.rejectedLines.count
    }
    if rejected > 0 {
        FileHandle.standardError.write(Data("chain-export rejected \(rejected) lines\n".utf8))
    }
    let chains = EvidenceChainBuilder.chains(from: records)
    let text = markdown ? EvidenceChainExport.markdown(chains) : EvidenceChainExport.json(chains)
    print(text)
} catch {
    let message = "chain-export failed: \(error)\n"
    FileHandle.standardError.write(Data(message.utf8))
    exit(1)
}
