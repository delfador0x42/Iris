import SwiftUI

/// Displays the disk usage tree with expandable nodes
struct DiskTreeView: View {
    let root: DiskNode
    @ObservedObject var store: DiskUsageStore

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(root.children) { child in
                    DiskNodeRow(
                        node: child,
                        totalSize: root.size,
                        store: store
                    )
                }
            }
            .padding()
        }
    }
}

/// Single row in the disk usage tree
struct DiskNodeRow: View {
    let node: DiskNode
    let totalSize: UInt64
    @ObservedObject var store: DiskUsageStore

    private var isExpanded: Bool {
        store.expandedNodes.contains(node.id)
    }

    private var hasChildren: Bool {
        node.isDirectory && !node.children.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Main row
            HStack(spacing: 8) {
                // Expansion indicator
                if hasChildren {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10))
                        .foregroundColor(.gray)
                        .frame(width: 12)
                } else {
                    Spacer()
                        .frame(width: 12)
                }

                // Icon
                Image(systemName: node.isDirectory ? "folder.fill" : "doc.fill")
                    .foregroundColor(node.isDirectory ? .blue : .gray)
                    .frame(width: 16)

                // Name
                Text(node.name)
                    .font(.system(size: 13, design: .monospaced))
                    .foregroundColor(.white)
                    .lineLimit(1)

                Spacer()

                // Permission denied indicator
                if node.permissionDenied {
                    Text("Permission denied")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.5))
                        .italic()
                }

                // Size bar (dust-style)
                DiskSizeBar(
                    percentage: node.percentageOf(total: totalSize),
                    depth: node.depth
                )
                .frame(width: 100, height: 12)

                // Size text
                Text(formatSize(node.size))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.gray)
                    .frame(width: 60, alignment: .trailing)

                // Percentage
                Text(String(format: "%.1f%%", node.percentageOf(total: totalSize) * 100))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.gray)
                    .frame(width: 50, alignment: .trailing)
            }
            .padding(.vertical, 4)
            .padding(.leading, CGFloat(node.depth) * 16)
            .contentShape(Rectangle())
            .onTapGesture {
                if hasChildren {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        store.toggleExpanded(node)
                    }
                }
            }
            .background(
                store.selectedNode?.id == node.id
                    ? Color.white.opacity(0.1)
                    : Color.clear
            )

            // Children (if expanded)
            if isExpanded {
                ForEach(node.children) { child in
                    DiskNodeRow(
                        node: child,
                        totalSize: totalSize,
                        store: store
                    )
                }
            }
        }
    }
}
