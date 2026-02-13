import SwiftUI

/// Split view: suspicious processes (left) + process tree snapshot (right)
///
/// Does NOT observe ProcessStore directly — uses independent timers to poll data.
/// This prevents HSplitView body re-evaluation on every 2s store refresh,
/// which was causing visual glitching (the entire split view re-laid out).
struct ProcessMonitorView: View {
    let onSelect: (ProcessInfo) -> Void

    @State private var treeSnapshot: [ProcessInfo] = []
    @State private var treeLastUpdate: Date?
    @State private var treeTimer: Timer?
    @State private var cachedSuspicious: [ProcessInfo] = []
    @State private var cachedPidSet: Set<Int32> = []
    @State private var suspiciousTimer: Timer?

    private let treeRefreshInterval: TimeInterval = 30

    var body: some View {
        HSplitView {
            suspiciousPane
                .frame(minWidth: 250, maxWidth: 400)

            treePaneWrapper
                .frame(minWidth: 500)
        }
        .onAppear { startMonitoring() }
        .onDisappear { stopMonitoring() }
    }

    // MARK: - Monitoring Lifecycle

    private func startMonitoring() {
        updateSuspiciousCache()
        refreshTreeSnapshot()
        suspiciousTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in
            Task { @MainActor in updateSuspiciousCache() }
        }
        treeTimer = Timer.scheduledTimer(withTimeInterval: treeRefreshInterval, repeats: true) { _ in
            Task { @MainActor in refreshTreeSnapshot() }
        }
    }

    private func stopMonitoring() {
        suspiciousTimer?.invalidate()
        suspiciousTimer = nil
        treeTimer?.invalidate()
        treeTimer = nil
    }

    /// Only update suspicious cache when the PID SET changes.
    /// Uses Set comparison so severity-driven re-sorts don't trigger rebuilds.
    /// ProcessInfo.id is a random UUID regenerated each fetch — without this guard,
    /// SwiftUI sees a "new" array every 2s and rebuilds all rows.
    private func updateSuspiciousCache() {
        let store = ProcessStore.shared
        let fresh = store.displayedProcesses
            .filter { $0.isSuspicious }
            .sorted { ($0.highestSeverity?.rawValue ?? 0) > ($1.highestSeverity?.rawValue ?? 0) }
        let freshPids = Set(fresh.map(\.pid))
        guard freshPids != cachedPidSet else { return }
        cachedPidSet = freshPids
        cachedSuspicious = fresh
    }

    private func refreshTreeSnapshot() {
        treeSnapshot = ProcessStore.shared.processes
        treeLastUpdate = Date()
    }

    // MARK: - Suspicious Pane (Left)

    private var suspiciousPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                Text("Suspicious Processes")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)
                Spacer()
                Text("\(cachedSuspicious.count)")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.red)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 2)
                    .background(Color.red.opacity(0.2))
                    .cornerRadius(4)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(Color.red.opacity(0.08))

            Divider().background(Color.red.opacity(0.3))

            if cachedSuspicious.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 36))
                        .foregroundColor(.green)
                    Text("No suspicious processes")
                        .font(.system(size: 14))
                        .foregroundColor(.gray)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ThemedScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(cachedSuspicious, id: \.pid) { process in
                            SuspiciousProcessRow(process: process, onSelect: { onSelect(process) })
                            Divider().background(Color.gray.opacity(0.15))
                        }
                    }
                }
            }
        }
    }

    // MARK: - Tree Pane (Right)

    private var treePaneWrapper: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "sidebar.left")
                    .foregroundColor(.cyan)
                Text("Process Tree")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)

                Spacer()

                if let lastUpdate = treeLastUpdate {
                    Text(lastUpdate, style: .time)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                }

                Button(action: refreshTreeSnapshot) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11))
                        .foregroundColor(.cyan)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(Color.cyan.opacity(0.05))

            Divider().background(Color.cyan.opacity(0.3))

            if treeSnapshot.isEmpty {
                VStack(spacing: 12) {
                    ProgressView().tint(.white)
                    Text("Loading process tree...")
                        .font(.system(size: 14))
                        .foregroundColor(.gray)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ProcessTreeView(processes: treeSnapshot, onSelect: onSelect)
            }
        }
    }
}

// MARK: - Suspicious Process Row

private struct SuspiciousProcessRow: View {
    let process: ProcessInfo
    let onSelect: () -> Void
    @State private var isHovered = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text("\(process.pid)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.red.opacity(0.7))
                    .frame(width: 50, alignment: .trailing)

                Text(process.displayName)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.red)
                    .lineLimit(1)

                Spacer()

                signingBadge
            }

            HStack(spacing: 6) {
                Spacer().frame(width: 50)
                ForEach(process.suspicionReasons, id: \.self) { reason in
                    Text(reason.rawValue)
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(severityColor(reason.severity).opacity(0.4))
                        .cornerRadius(3)
                }
            }
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 8)
        .background(isHovered ? Color.red.opacity(0.12) : Color.red.opacity(0.05))
        .contentShape(Rectangle())
        .onTapGesture(perform: onSelect)
        .onHover { isHovered = $0 }
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

    private func severityColor(_ severity: SuspicionSeverity) -> Color {
        switch severity {
        case .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        }
    }
}
