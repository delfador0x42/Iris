import SwiftUI

/// Live detection alert view — real-time display of alerts from the DetectionEngine.
public struct DetectionView: View {
    @State private var alerts: [SecurityAlert] = []
    @State private var isLoading = true
    @State private var stats: (events: UInt64, alerts: UInt64, rules: Int, correlations: Int)?
    @State private var refreshTimer: Timer?

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            statsHeader
            if isLoading {
                ProgressView("Loading alerts...")
                    .frame(maxHeight: .infinity)
            } else if alerts.isEmpty {
                emptyState
            } else {
                alertList
            }
        }
        .background(Color(red: 0.01, green: 0.02, blue: 0.04))
        .onAppear { startRefresh() }
        .onDisappear { stopRefresh() }
    }

    private var statsHeader: some View {
        HStack(spacing: 20) {
            if let s = stats {
                DetectionStat(label: "RULES", value: "\(s.rules + s.correlations)")
                DetectionStat(label: "EVENTS", value: s.events > 1000 ? "\(s.events/1000)K" : "\(s.events)")
                DetectionStat(label: "ALERTS", value: "\(s.alerts)")
            }
            Spacer()
            Button("Clear") {
                Task {
                    await AlertStore.shared.clear()
                    await refresh()
                }
            }
            .buttonStyle(.plain)
            .foregroundColor(.cyan)
            .font(.system(size: 11, weight: .medium, design: .monospaced))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 40))
                .foregroundColor(.green.opacity(0.5))
            Text("NO ACTIVE ALERTS")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.gray)
            Text("Detection engine monitoring \(stats?.rules ?? 0) rules")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray.opacity(0.6))
        }
        .frame(maxHeight: .infinity)
    }

    private var alertList: some View {
        ThemedScrollView {
            LazyVStack(spacing: 8) {
                ForEach(alerts) { alert in
                    AlertRow(alert: alert)
                }
            }
            .padding(16)
        }
    }

    private func startRefresh() {
        Task { await refresh() }
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            Task { await refresh() }
        }
    }

    private func stopRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    @MainActor
    private func refresh() async {
        alerts = await AlertStore.shared.recent(200)
        stats = await DetectionEngine.shared.stats()
        isLoading = false
    }
}

// MARK: - Subviews

private struct DetectionStat: View {
    let label: String
    let value: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .foregroundColor(.cyan)
            Text(label)
                .font(.system(size: 8, weight: .medium, design: .monospaced))
                .foregroundColor(.gray)
        }
    }
}

private struct AlertRow: View {
    let alert: SecurityAlert

    var severityColor: Color {
        switch alert.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .gray
        }
    }

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(severityColor)
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(alert.name)
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .foregroundColor(.white)
                    Spacer()
                    Text(alert.mitreId)
                        .font(.system(size: 9, weight: .medium, design: .monospaced))
                        .foregroundColor(.cyan.opacity(0.7))
                }

                HStack {
                    Text(alert.processName)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.cyan)
                    Text(alert.description)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                        .lineLimit(1)
                }

                Text(alert.timestamp, style: .relative)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.gray.opacity(0.5))
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color.white.opacity(0.02))
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .strokeBorder(severityColor.opacity(0.2), lineWidth: 1)
                )
        )
    }
}
