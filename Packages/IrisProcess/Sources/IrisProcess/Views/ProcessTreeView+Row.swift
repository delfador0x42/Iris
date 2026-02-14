import SwiftUI

/// Single row in the process tree — tree indentation, names, paths, badges, and grouping
struct ProcessTreeRow: View {
    let entry: FlatTreeEntry
    let onSelect: () -> Void
    let onToggleGroup: (() -> Void)?
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 4) {
            treeIndent

            Text(String(entry.process.pid))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 50, alignment: .trailing)

            if entry.process.isSuspicious {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                    .font(.system(size: 10))
            }

            VStack(alignment: .leading, spacing: 1) {
                Text(nameDisplay)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(entry.process.isSuspicious ? .red : .white)
                    .lineLimit(1)

                Text(pathDisplay)
                    .font(.system(size: 10))
                    .foregroundColor(.white.opacity(0.3))
                    .lineLimit(1)
            }

            Spacer()

            if let res = entry.process.resources {
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
            groupBadge
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(isHovered ? Color.white.opacity(0.05) : Color.clear)
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
        .onHover { isHovered = $0 }
    }

    // MARK: - Display

    /// Children show binary name; roots show bundle name
    private var nameDisplay: String {
        entry.depth > 0 ? entry.process.name : entry.process.displayName
    }

    private var pathDisplay: String {
        let args = entry.process.arguments.dropFirst()
        if args.isEmpty { return entry.process.path }
        return entry.process.path + " " + args.joined(separator: " ")
    }

    // MARK: - Tree Characters (ps -axjf style)

    @ViewBuilder
    private var treeIndent: some View {
        if entry.depth > 0 {
            HStack(spacing: 0) {
                ForEach(0..<entry.ancestorIsLast.count, id: \.self) { i in
                    Text(entry.ancestorIsLast[i] ? "   " : "│  ")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.cyan.opacity(0.2))
                }
                Text(entry.isLast ? "└─ " : "├─ ")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.cyan.opacity(0.4))
            }
        }
    }

    // MARK: - Badges

    private var signingBadge: some View {
        Group {
            if let cs = entry.process.codeSigningInfo {
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

    @ViewBuilder
    private var groupBadge: some View {
        if entry.groupCount > 1, let toggle = onToggleGroup {
            HStack(spacing: 2) {
                Text("×\(entry.groupCount)")
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                Image(systemName: entry.isGroupExpanded ? "chevron.down" : "chevron.right")
                    .font(.system(size: 8))
            }
            .foregroundColor(.cyan.opacity(0.7))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.cyan.opacity(0.1))
            .cornerRadius(4)
            .contentShape(Rectangle())
            .onTapGesture { toggle() }
        }
    }
}
