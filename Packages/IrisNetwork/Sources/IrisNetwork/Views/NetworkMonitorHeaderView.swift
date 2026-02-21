import SwiftUI

/// Network monitor header — NieR aesthetic.
struct NetworkMonitorHeaderView: View {
    @ObservedObject var store: SecurityStore
    @ObservedObject var extensionManager: ExtensionManager
    @ObservedObject var dnsStore = DNSStore.shared
    @Binding var viewMode: NetworkViewMode

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Title row
            HStack {
                Text("NETWORK MONITOR")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyan.opacity(0.7))

                Spacer()

                // View mode toggle
                HStack(spacing: 2) {
                    ForEach(NetworkViewMode.allCases, id: \.self) { mode in
                        Button {
                            viewMode = mode
                        } label: {
                            Image(systemName: mode.icon)
                                .font(.system(size: 12))
                                .frame(width: 28, height: 22)
                        }
                        .buttonStyle(.plain)
                        .background(
                            viewMode == mode
                                ? Color.cyan.opacity(0.15)
                                : Color.white.opacity(0.04)
                        )
                        .foregroundColor(viewMode == mode ? .cyan : .white.opacity(0.3))
                        .overlay(
                            RoundedRectangle(cornerRadius: 3)
                                .stroke(viewMode == mode ? Color.cyan.opacity(0.3) : Color.clear, lineWidth: 0.5)
                        )
                        .cornerRadius(3)
                    }
                }
                .padding(3)
                .background(Color.black.opacity(0.3))
                .cornerRadius(4)

                Spacer().frame(width: 12)

                // Status
                if viewMode == .dns {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(dnsStore.isActive
                                ? Color(red: 0.3, green: 0.9, blue: 0.5)
                                : Color(red: 1.0, green: 0.35, blue: 0.35))
                            .frame(width: 6, height: 6)
                        Text(dnsStore.isActive ? "ACTIVE" : "INACTIVE")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundColor(.white.opacity(0.3))
                    }
                } else {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(store.isConnected
                                ? Color(red: 0.3, green: 0.9, blue: 0.5)
                                : Color(red: 1.0, green: 0.35, blue: 0.35))
                            .frame(width: 6, height: 6)
                        Text(store.isConnected ? "ONLINE" : "OFFLINE")
                            .font(.system(size: 9, weight: .bold, design: .monospaced))
                            .foregroundColor(.white.opacity(0.3))
                    }
                }
            }

            // Stats row
            if viewMode == .dns {
                dnsStatsRow
            } else {
                networkStatsRow
            }
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 16)
        .background(Color(red: 0.02, green: 0.03, blue: 0.06))
    }

    // MARK: - Network Stats

    private var networkStatsRow: some View {
        HStack(spacing: 12) {
            StatBox(label: "Connections", value: "\(store.connections.count)", color: .cyan)
            StatBox(label: "Processes", value: "\(store.processes.count)", color: .cyan)
            StatBox(label: "Rules", value: "\(store.rules.count)",
                    color: Color(red: 1.0, green: 0.6, blue: 0.2))
            StatBox(label: "Upload", value: NetworkConnection.formatBytes(store.totalBytesUp),
                    color: Color(red: 1.0, green: 0.6, blue: 0.2))
            StatBox(label: "Download", value: NetworkConnection.formatBytes(store.totalBytesDown),
                    color: Color(red: 0.3, green: 0.9, blue: 0.5))

            Spacer()

            Button {
                store.clearConnections()
            } label: {
                HStack(spacing: 4) {
                    Image(systemName: "trash")
                        .font(.system(size: 10))
                    Text("CLEAR")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                }
                .foregroundColor(.white.opacity(0.25))
            }
            .buttonStyle(.plain)
            .help("Clear all connections")

            if let lastUpdate = store.lastUpdate {
                Text(lastUpdate, style: .time)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.2))
            }
        }
    }

    // MARK: - DNS Stats

    private var dnsStatsRow: some View {
        HStack(spacing: 12) {
            StatBox(label: "Queries", value: "\(dnsStore.totalQueries)", color: .cyan)
            StatBox(
                label: "Latency",
                value: String(format: "%.0fms", dnsStore.averageLatencyMs),
                color: dnsStore.averageLatencyMs < 50
                    ? Color(red: 0.3, green: 0.9, blue: 0.5)
                    : (dnsStore.averageLatencyMs < 100
                        ? Color(red: 1.0, green: 0.6, blue: 0.2)
                        : Color(red: 1.0, green: 0.35, blue: 0.35))
            )
            StatBox(
                label: "Success",
                value: String(format: "%.0f%%", dnsStore.successRate * 100),
                color: dnsStore.successRate > 0.95
                    ? Color(red: 0.3, green: 0.9, blue: 0.5)
                    : Color(red: 1.0, green: 0.6, blue: 0.2)
            )
            StatBox(label: "Server", value: dnsStore.serverName, color: .cyan)

            Spacer()
        }
    }
}
