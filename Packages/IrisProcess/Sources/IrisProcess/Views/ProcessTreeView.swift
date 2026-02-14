import SwiftUI

/// Tree node wrapping a ProcessInfo with optional children
struct ProcessTreeNode: Identifiable {
    let id: Int32  // PID — stable across refreshes
    let process: ProcessInfo
    var children: [ProcessTreeNode]?
}

/// Flattened entry for rendering — carries depth, lineage, and group info
struct FlatTreeEntry {
    let entryId: String            // Unique ForEach ID
    let pid: Int32
    let process: ProcessInfo
    let depth: Int
    let isLast: Bool               // Last sibling at this depth?
    let ancestorIsLast: [Bool]     // For each ancestor, was it the last sibling?
    let parentBundlePath: String?  // Bundle path prefix to strip for relative paths
    let groupCount: Int            // 0 = expanded non-first, 1 = standalone, >1 = group header
    let isGroupExpanded: Bool      // Chevron direction for group headers
    let isNewRootGroup: Bool       // Draw separator above this entry
}

/// Hierarchical process tree — ps -axjf style with sibling grouping
struct ProcessTreeView: View {
    let processes: [ProcessInfo]
    let onSelect: (ProcessInfo) -> Void
    @State private var expandedGroups: Set<String> = []

    var body: some View {
        let tree = buildTree(from: processes)
        let flat = flattenTree(tree, depth: 1)

        ThemedScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(flat, id: \.entryId) { entry in
                    ProcessTreeRow(
                        entry: entry,
                        onSelect: { onSelect(entry.process) },
                        onToggleGroup: entry.groupCount > 1
                            ? { toggleGroup(entry.process.path) } : nil
                    )
                }
            }
            .padding(.vertical, 4)
        }
    }

    private func toggleGroup(_ path: String) {
        withAnimation(.easeInOut(duration: 0.15)) {
            if expandedGroups.contains(path) {
                expandedGroups.remove(path)
            } else {
                expandedGroups.insert(path)
            }
        }
    }

    // MARK: - Tree Construction

    private func buildTree(from processes: [ProcessInfo]) -> [ProcessTreeNode] {
        // Skip kernel_task (pid 0) and launchd (pid 1) — their children become roots.
        // macOS spawns nearly everything via launchd, so keeping it adds a useless wrapper.
        let visible = processes.filter { $0.pid > 1 }
        let pidSet = Set(visible.map { $0.pid })
        let childrenByPpid = Dictionary(grouping: visible, by: { $0.ppid })

        func buildNode(_ process: ProcessInfo) -> ProcessTreeNode {
            let kids = childrenByPpid[process.pid]?
                .sorted { $0.name.caseInsensitiveCompare($1.name) == .orderedAscending }
                .map { buildNode($0) }
            return ProcessTreeNode(
                id: process.pid, process: process,
                children: kids?.isEmpty == true ? nil : kids
            )
        }

        let roots = visible.filter { !pidSet.contains($0.ppid) }
        return roots
            .sorted { lhs, rhs in
                let lk = childrenByPpid[lhs.pid] != nil
                let rk = childrenByPpid[rhs.pid] != nil
                if lk != rk { return lk }
                return lhs.name.caseInsensitiveCompare(rhs.name) == .orderedAscending
            }
            .map { buildNode($0) }
    }

    // MARK: - Flattening with Sibling Grouping

    private func flattenTree(
        _ nodes: [ProcessTreeNode],
        depth: Int = 0,
        ancestorIsLast: [Bool] = [],
        parentBundlePath: String? = nil,
        isRootLevel: Bool = true
    ) -> [FlatTreeEntry] {
        var result: [FlatTreeEntry] = []
        let groups = groupConsecutiveSiblings(nodes)

        for (gi, group) in groups.enumerated() {
            let isLastGroup = gi == groups.count - 1
            let childBundlePath = parentBundlePath
                ?? extractBundlePath(from: group.nodes[0].process.path)

            if group.nodes.count == 1 {
                let node = group.nodes[0]
                result.append(FlatTreeEntry(
                    entryId: "\(node.process.pid)", pid: node.process.pid,
                    process: node.process, depth: depth,
                    isLast: isLastGroup, ancestorIsLast: ancestorIsLast,
                    parentBundlePath: parentBundlePath, groupCount: 1,
                    isGroupExpanded: false, isNewRootGroup: isRootLevel && gi > 0
                ))
                if let kids = node.children, !kids.isEmpty {
                    result += flattenTree(kids, depth: depth + 1,
                        ancestorIsLast: ancestorIsLast + [isLastGroup],
                        parentBundlePath: childBundlePath, isRootLevel: false)
                }
            } else if expandedGroups.contains(group.path) {
                for (i, node) in group.nodes.enumerated() {
                    let isLast = isLastGroup && i == group.nodes.count - 1
                    result.append(FlatTreeEntry(
                        entryId: "\(node.process.pid)", pid: node.process.pid,
                        process: node.process, depth: depth,
                        isLast: isLast, ancestorIsLast: ancestorIsLast,
                        parentBundlePath: parentBundlePath,
                        groupCount: i == 0 ? group.nodes.count : 0,
                        isGroupExpanded: true,
                        isNewRootGroup: isRootLevel && gi > 0 && i == 0
                    ))
                    if let kids = node.children, !kids.isEmpty {
                        result += flattenTree(kids, depth: depth + 1,
                            ancestorIsLast: ancestorIsLast + [isLast],
                            parentBundlePath: childBundlePath, isRootLevel: false)
                    }
                }
            } else {
                let node = group.nodes[0]
                result.append(FlatTreeEntry(
                    entryId: "\(node.process.pid)", pid: node.process.pid,
                    process: node.process, depth: depth,
                    isLast: isLastGroup, ancestorIsLast: ancestorIsLast,
                    parentBundlePath: parentBundlePath,
                    groupCount: group.nodes.count,
                    isGroupExpanded: false,
                    isNewRootGroup: isRootLevel && gi > 0
                ))
            }
        }
        return result
    }

    private func groupConsecutiveSiblings(
        _ nodes: [ProcessTreeNode]
    ) -> [(path: String, nodes: [ProcessTreeNode])] {
        var groups: [(path: String, nodes: [ProcessTreeNode])] = []
        for node in nodes {
            if !groups.isEmpty && groups[groups.count - 1].path == node.process.path {
                groups[groups.count - 1].nodes.append(node)
            } else {
                groups.append((path: node.process.path, nodes: [node]))
            }
        }
        return groups
    }

    private func extractBundlePath(from path: String) -> String? {
        guard let range = path.range(of: ".app/") else { return nil }
        return String(path[...range.upperBound])
    }
}
