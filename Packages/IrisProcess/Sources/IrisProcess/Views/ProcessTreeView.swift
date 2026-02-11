import SwiftUI

/// Tree node wrapping a ProcessInfo with optional children
struct ProcessTreeNode: Identifiable {
    let id: Int32  // PID — stable across refreshes
    let process: ProcessInfo
    var children: [ProcessTreeNode]?
}

/// Hierarchical process tree view with visual depth indentation
struct ProcessTreeView: View {
    let processes: [ProcessInfo]
    let onSelect: (ProcessInfo) -> Void

    var body: some View {
        let tree = buildTree(from: processes)
        let flat = flattenTree(tree)

        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(flat, id: \.pid) { entry in
                    ProcessTreeRow(
                        process: entry.process,
                        depth: entry.depth,
                        hasChildren: entry.hasChildren,
                        onSelect: { onSelect(entry.process) }
                    )
                    Divider().background(Color.gray.opacity(0.15))
                }
            }
            .padding(.vertical, 4)
        }
    }

    /// Flatten tree into array with depth info for LazyVStack rendering
    private func flattenTree(_ nodes: [ProcessTreeNode], depth: Int = 0) -> [FlatEntry] {
        var result: [FlatEntry] = []
        for node in nodes {
            let kids = node.children ?? []
            result.append(FlatEntry(
                pid: node.process.pid,
                process: node.process,
                depth: depth,
                hasChildren: !kids.isEmpty
            ))
            if !kids.isEmpty {
                result.append(contentsOf: flattenTree(kids, depth: depth + 1))
            }
        }
        return result
    }

    /// Build process tree from flat list using ppid relationships
    private func buildTree(from processes: [ProcessInfo]) -> [ProcessTreeNode] {
        let pidSet = Set(processes.map { $0.pid })
        let childrenByPpid = Dictionary(grouping: processes, by: { $0.ppid })

        func buildNode(_ process: ProcessInfo) -> ProcessTreeNode {
            let kids = childrenByPpid[process.pid]?.map { buildNode($0) }
            return ProcessTreeNode(
                id: process.pid,
                process: process,
                children: kids?.isEmpty == true ? nil : kids
            )
        }

        let roots = processes.filter { p in
            p.ppid <= 1 || !pidSet.contains(p.ppid)
        }

        // Sort: processes with children first (so hierarchy is visible at top)
        let sorted = roots.sorted { lhs, rhs in
            let lhsKids = childrenByPpid[lhs.pid] != nil
            let rhsKids = childrenByPpid[rhs.pid] != nil
            if lhsKids != rhsKids { return lhsKids }
            return lhs.name.caseInsensitiveCompare(rhs.name) == .orderedAscending
        }
        return sorted.map { buildNode($0) }
    }

    struct FlatEntry {
        let pid: Int32
        let process: ProcessInfo
        let depth: Int
        let hasChildren: Bool
    }
}

/// Single row in the process tree with visual depth indentation
private struct ProcessTreeRow: View {
    let process: ProcessInfo
    let depth: Int
    let hasChildren: Bool
    let onSelect: () -> Void
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 4) {
            treeIndent

            Text("\(process.pid)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 50, alignment: .trailing)

            if process.isSuspicious {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                    .font(.system(size: 10))
            }

            Text(process.displayName)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(process.isSuspicious ? .red : .white)
                .lineLimit(1)

            Spacer()

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

            signingBadge
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(isHovered ? Color.white.opacity(0.05) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
        .onHover { isHovered = $0 }
    }

    @ViewBuilder
    private var treeIndent: some View {
        if depth > 0 {
            HStack(spacing: 0) {
                ForEach(0..<(depth - 1), id: \.self) { _ in
                    Text("│  ")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.cyan.opacity(0.25))
                }
                Text("├─ ")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.cyan.opacity(0.5))
            }
        }
    }

    private var signingBadge: some View {
        Group {
            if let cs = process.codeSigningInfo {
                if cs.isAppleSigned {
                    Image(systemName: "checkmark.seal.fill").foregroundColor(.green)
                } else if cs.teamId != nil {
                    Image(systemName: "checkmark.seal").foregroundColor(.blue)
                } else {
                    Image(systemName: "seal").foregroundColor(.orange)
                }
            } else {
                Image(systemName: "xmark.seal").foregroundColor(.red)
            }
        }
        .font(.system(size: 12))
    }
}
