import SwiftUI

// MARK: - Process Lineage & Helpers

extension ProcessDetailView {

    @ViewBuilder
    var processLineage: some View {
        let chain = buildAncestorChain()
        if chain.count > 1 {
            DetailSection(title: "Process Lineage") {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(chain.indices, id: \.self) { i in
                        let ancestor = chain[i]
                        let isTarget = ancestor.pid == process.pid
                        HStack(spacing: 4) {
                            // Tree indent
                            if i > 0 {
                                HStack(spacing: 0) {
                                    ForEach(0..<(i - 1), id: \.self) { _ in
                                        Text("   ")
                                            .font(.system(size: 11, design: .monospaced))
                                    }
                                    Text(i == chain.count - 1 ? "\u{2514}\u{2500} " : "\u{251C}\u{2500} ")
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(.cyan.opacity(0.4))
                                }
                            }
                            Text(String(ancestor.pid))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.gray)
                            Text(ancestor.name)
                                .font(.system(size: 12, weight: isTarget ? .bold : .regular))
                                .foregroundColor(isTarget ? .cyan : .white)
                            if isTarget {
                                Text("(this)")
                                    .font(.system(size: 10))
                                    .foregroundColor(.cyan.opacity(0.6))
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
        }
    }

    /// Walk ppid/responsiblePid chain up from this process to the root.
    /// Uses responsiblePid when ppid is launchd (pid 1) to show the true parent app.
    func buildAncestorChain() -> [ProcessInfo] {
        let allProcesses = ProcessStore.shared.processes
        let byPid = Dictionary(allProcesses.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })

        var chain: [ProcessInfo] = [process]
        var current = process
        var visited: Set<Int32> = [process.pid]

        while true {
            // Prefer ppid if it's a real parent (not launchd)
            let nextPid: Int32
            if current.ppid > 1 {
                nextPid = current.ppid
            } else if current.responsiblePid > 1 && current.responsiblePid != current.pid {
                nextPid = current.responsiblePid
            } else {
                break
            }
            guard let parent = byPid[nextPid], !visited.contains(parent.pid) else { break }
            visited.insert(parent.pid)
            chain.append(parent)
            current = parent
        }

        return chain.reversed()
    }

    func severityColor(_ severity: SuspicionSeverity) -> Color {
        switch severity {
        case .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        }
    }
}
