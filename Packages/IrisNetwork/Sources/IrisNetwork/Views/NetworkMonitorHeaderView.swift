import SwiftUI

/// Header view for network monitor with title, stats, and view mode toggle
struct NetworkMonitorHeaderView: View {
    @ObservedObject var store: SecurityStore
    @ObservedObject var extensionManager: ExtensionManager
    @ObservedObject var dnsStore = DNSStore.shared
    @Binding var viewMode: NetworkViewMode

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Title row
            HStack {
                Text("Network Monitor")
                    .font(.system(size: 24, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                Spacer()

                // View mode toggle buttons
                HStack(spacing: 4) {
                    ForEach(NetworkViewMode.allCases, id: \.self) { mode in
                        Button {
                            viewMode = mode
                        } label: {
                            Image(systemName: mode.icon)
                                .font(.system(size: 14))
                                .frame(width: 32, height: 24)
                        }
                        .buttonStyle(.plain)
                        .background(
                            viewMode == mode
                                ? Color.blue
                                : Color.white.opacity(0.1)
                        )
                        .foregroundColor(viewMode == mode ? .white : .gray)
                        .cornerRadius(6)
                    }
                }
                .padding(4)
                .background(Color.black.opacity(0.3))
                .cornerRadius(8)

                Spacer()
                    .frame(width: 16)

                // Status indicator — DNS uses its own extension status
                if viewMode == .dns {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(dnsStore.isActive ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(dnsStore.isActive ? "Active" : "Inactive")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }
                } else {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(store.isConnected ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(store.isConnected ? "Connected" : "Disconnected")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }
                }
            }

            // Stats row — context-sensitive based on active tab
            if viewMode == .dns {
                dnsStatsRow
            } else {
                networkStatsRow
            }
        }
        .padding(.vertical, 16)
        .padding(.horizontal, 20)
        .background(Color.black.opacity(0.3))
    }

    // MARK: - Network Stats

    private var networkStatsRow: some View {
        HStack(spacing: 24) {
            StatBox(label: "Connections", value: "\(store.connections.count)", color: .white)
            StatBox(label: "Processes", value: "\(store.processes.count)", color: .white)
            StatBox(label: "Rules", value: "\(store.rules.count)", color: .orange)
            StatBox(label: "Total Up", value: NetworkConnection.formatBytes(store.totalBytesUp), color: .orange)
            StatBox(label: "Total Down", value: NetworkConnection.formatBytes(store.totalBytesDown), color: .green)

            Spacer()

            if let lastUpdate = store.lastUpdate {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Last update")
                        .font(.system(size: 10))
                        .foregroundColor(.gray.opacity(0.7))
                    Text(lastUpdate, style: .time)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.gray)
                }
            }
        }
    }

    // MARK: - DNS Stats

    private var dnsStatsRow: some View {
        HStack(spacing: 24) {
            StatBox(label: "Queries", value: "\(dnsStore.totalQueries)", color: .blue)
            StatBox(
                label: "Avg Latency",
                value: String(format: "%.0fms", dnsStore.averageLatencyMs),
                color: dnsStore.averageLatencyMs < 50 ? .green : (dnsStore.averageLatencyMs < 100 ? .orange : .red)
            )
            StatBox(
                label: "Success",
                value: String(format: "%.0f%%", dnsStore.successRate * 100),
                color: dnsStore.successRate > 0.95 ? .green : .orange
            )
            StatBox(label: "Server", value: dnsStore.serverName, color: .blue)

            Spacer()
        }
    }
}
