import SwiftUI

/// Tree node wrapping a ProcessInfo with optional children
struct ProcessTreeNode: Identifiable {
    let id: UUID
    let process: ProcessInfo
    var children: [ProcessTreeNode]?
}

/// Hierarchical process tree view using OutlineGroup
struct ProcessTreeView: View {
    let processes: [ProcessInfo]
    let onSelect: (ProcessInfo) -> Void

    var body: some View {
        let tree = buildTree(from: processes)

        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                OutlineGroup(tree, children: \.children) { node in
                    ProcessTreeRow(process: node.process, onSelect: { onSelect(node.process) })
                    Divider().background(Color.gray.opacity(0.15))
                }
            }
            .padding()
        }
    }

    /// Build process tree from flat list using ppid relationships
    private func buildTree(from processes: [ProcessInfo]) -> [ProcessTreeNode] {
        let pidSet = Set(processes.map { $0.pid })
        let childrenByPpid = Dictionary(grouping: processes, by: { $0.ppid })

        func buildNode(_ process: ProcessInfo) -> ProcessTreeNode {
            let kids = childrenByPpid[process.pid]?.map { buildNode($0) }
            return ProcessTreeNode(
                id: process.id,
                process: process,
                children: kids?.isEmpty == true ? nil : kids
            )
        }

        // Roots: processes whose parent isn't in the list, or ppid == 0/1
        let roots = processes.filter { p in
            p.ppid <= 1 || !pidSet.contains(p.ppid)
        }

        return roots.map { buildNode($0) }
    }
}

/// Single row in the process tree
private struct ProcessTreeRow: View {
    let process: ProcessInfo
    let onSelect: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            // PID
            Text("\(process.pid)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 50, alignment: .trailing)

            // Suspicious indicator
            if process.isSuspicious {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                    .font(.system(size: 10))
            }

            // Name
            Text(process.displayName)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(process.isSuspicious ? .red : .white)
                .lineLimit(1)

            Spacer()

            // CPU/Memory if available
            if let res = process.resources {
                Text(res.formattedCPU)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.cyan)
                    .frame(width: 60, alignment: .trailing)

                Text(res.formattedMemory)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(width: 70, alignment: .trailing)
            }

            // Signing status
            signingBadge
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
    }

    private var signingBadge: some View {
        Group {
            if let cs = process.codeSigningInfo {
                if cs.isAppleSigned {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.green)
                } else if cs.teamId != nil {
                    Image(systemName: "checkmark.seal")
                        .foregroundColor(.blue)
                } else {
                    Image(systemName: "seal")
                        .foregroundColor(.orange)
                }
            } else {
                Image(systemName: "xmark.seal")
                    .foregroundColor(.red)
            }
        }
        .font(.system(size: 12))
    }
}
