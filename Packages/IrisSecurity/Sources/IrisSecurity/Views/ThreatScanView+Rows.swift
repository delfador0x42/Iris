import SwiftUI

// MARK: - Anomaly Row

struct AnomalyRow: View {
    let anomaly: ProcessAnomaly
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityBadge(severity: anomaly.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(anomaly.technique)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(anomaly.processName)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                if let mitre = anomaly.mitreID {
                    MITREBadge(id: mitre)
                }
                ExpandChevron(isExpanded: isExpanded)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(anomaly.description)
                        .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    if !anomaly.processPath.isEmpty {
                        Text("Path: \(anomaly.processPath)")
                            .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                    }
                    if anomaly.pid > 0 {
                        Text("PID: \(anomaly.pid) | Parent: \(anomaly.parentName) (\(anomaly.parentPID))")
                            .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                    }
                }
                .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(backgroundFor(anomaly.severity))
    }
}

// MARK: - Filesystem Change Row

struct FSChangeRow: View {
    let change: FileSystemChange
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityBadge(severity: change.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(change.changeType.rawValue)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(URL(fileURLWithPath: change.path).lastPathComponent)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                changeIcon
                ExpandChevron(isExpanded: isExpanded)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(change.details)
                        .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    Text(change.path)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(backgroundFor(change.severity))
    }

    private var changeIcon: some View {
        Image(systemName: iconForType)
            .font(.system(size: 10))
            .foregroundColor(colorForType)
    }

    private var iconForType: String {
        switch change.changeType {
        case .created: return "plus.circle"
        case .modified: return "pencil.circle"
        case .deleted: return "trash.circle"
        case .permissionsChanged: return "lock.circle"
        }
    }

    private var colorForType: Color {
        switch change.changeType {
        case .created: return .green
        case .modified: return .orange
        case .deleted: return .red
        case .permissionsChanged: return .yellow
        }
    }
}

// MARK: - Supply Chain Row

struct SupplyChainRow: View {
    let finding: SupplyChainFinding
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityBadge(severity: finding.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(finding.finding)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text("\(finding.source.rawValue): \(finding.packageName)")
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                ExpandChevron(isExpanded: isExpanded)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                Text(finding.details)
                    .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(backgroundFor(finding.severity))
    }
}
