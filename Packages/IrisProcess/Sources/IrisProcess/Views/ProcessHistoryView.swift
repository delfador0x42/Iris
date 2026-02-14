import SwiftUI

/// Chronological timeline of all processes seen this session, newest first
struct ProcessHistoryView: View {
    @ObservedObject var store: ProcessStore
    let onSelect: (ProcessInfo) -> Void

    private var filteredHistory: [ProcessInfo] {
        var result = store.processHistory

        // Apply search filter
        if !store.filterText.isEmpty {
            result = result.filter { process in
                process.name.localizedCaseInsensitiveContains(store.filterText) ||
                process.path.localizedCaseInsensitiveContains(store.filterText) ||
                String(process.pid).contains(store.filterText)
            }
        }

        // Apply suspicious filter
        if store.showOnlySuspicious {
            result = result.filter { $0.isSuspicious }
        }

        // Sort by timestamp descending (newest first)
        result.sort { $0.timestamp > $1.timestamp }
        return result
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Column header
            historyHeaderRow

            Divider().background(Color.gray.opacity(0.3))

            if filteredHistory.isEmpty {
                emptyView
            } else {
                ThemedScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(filteredHistory) { process in
                            HistoryRow(process: process, isLive: isLive(process), onSelect: { onSelect(process) })
                            Divider().background(Color.gray.opacity(0.15))
                        }
                    }
                    .padding(.horizontal)
                }
            }
        }
    }

    private var historyHeaderRow: some View {
        HStack(spacing: 0) {
            Text("TIME")
                .frame(width: 80, alignment: .leading)
            Text("PID")
                .frame(width: 60, alignment: .leading)
            Text("COMMAND")
                .frame(maxWidth: .infinity, alignment: .leading)
            Text("PATH")
                .frame(width: 250, alignment: .leading)
            Text("SIGNING")
                .frame(width: 120, alignment: .leading)
            Text("STATUS")
                .frame(width: 70, alignment: .center)
        }
        .font(.system(size: 11, weight: .medium, design: .monospaced))
        .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))
        .padding(.vertical, 8)
        .padding(.horizontal, 16)
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "clock.arrow.circlepath")
                .font(.system(size: 48))
                .foregroundColor(.gray)
            Text("No process history yet")
                .font(.headline)
                .foregroundColor(.white)
            Text("Processes will appear here as they are detected")
                .font(.system(size: 14))
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// Check if a historical process is still running in the live list
    private func isLive(_ process: ProcessInfo) -> Bool {
        store.processes.contains { $0.pid == process.pid && $0.path == process.path }
    }
}

// MARK: - History Row

private struct HistoryRow: View {
    let process: ProcessInfo
    let isLive: Bool
    let onSelect: () -> Void
    @State private var isHovered = false

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
        HStack(spacing: 0) {
            // Timestamp
            Text(Self.timeFormatter.string(from: process.timestamp))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.cyan)
                .frame(width: 80, alignment: .leading)

            // PID
            Text(String(process.pid))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(rowColor)
                .frame(width: 60, alignment: .leading)

            // Name
            HStack(spacing: 6) {
                if process.isSuspicious {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 10))
                }
                Text(process.displayName)
                    .font(.system(size: 12, weight: process.isSuspicious ? .semibold : .regular))
                    .foregroundColor(rowColor)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Path (truncated)
            Text(process.path)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.gray)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: 250, alignment: .leading)

            // Signing
            Text(process.codeSigningInfo?.signerDescription ?? "Unknown")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(signingColor)
                .frame(width: 120, alignment: .leading)

            // Live/Exited status
            HStack(spacing: 4) {
                Circle()
                    .fill(isLive ? Color.green : Color.gray.opacity(0.5))
                    .frame(width: 6, height: 6)
                Text(isLive ? "Live" : "Exited")
                    .font(.system(size: 10))
                    .foregroundColor(isLive ? .green : .gray)
            }
            .frame(width: 70, alignment: .center)
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 8)
        .background(backgroundColor)
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
        .onHover { isHovered = $0 }
    }

    private var backgroundColor: Color {
        if process.isSuspicious {
            return Color.red.opacity(isHovered ? 0.15 : 0.06)
        } else if isHovered {
            return Color.white.opacity(0.05)
        }
        return Color.clear
    }

    private var rowColor: Color {
        if process.isSuspicious { return .red }
        if process.codeSigningInfo?.isAppleSigned == true { return .green.opacity(0.8) }
        return .white
    }

    private var signingColor: Color {
        guard let cs = process.codeSigningInfo else { return .orange }
        if cs.isPlatformBinary { return .green }
        if cs.isAppleSigned { return .green.opacity(0.8) }
        if cs.teamId != nil { return .blue }
        if cs.signingId != nil { return .orange }
        return .red
    }
}
