import SwiftUI

/// Header view for network monitor with title, stats, and view mode toggle
struct NetworkMonitorHeaderView: View {
    @ObservedObject var store: SecurityStore
    @ObservedObject var extensionManager: ExtensionManager
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

                // Status indicator
                HStack(spacing: 6) {
                    Circle()
                        .fill(store.isConnected ? Color.green : Color.red)
                        .frame(width: 8, height: 8)

                    Text(store.isConnected ? "Connected" : "Disconnected")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
            }

            // Stats row
            HStack(spacing: 24) {
                // Connection count
                StatBox(
                    label: "Connections",
                    value: "\(store.connections.count)",
                    color: .white
                )

                // Processes
                StatBox(
                    label: "Processes",
                    value: "\(store.processes.count)",
                    color: .white
                )

                // Total up
                StatBox(
                    label: "Total Up",
                    value: NetworkConnection.formatBytes(store.totalBytesUp),
                    color: .orange
                )

                // Total down
                StatBox(
                    label: "Total Down",
                    value: NetworkConnection.formatBytes(store.totalBytesDown),
                    color: .green
                )

                Spacer()

                // Last update
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
        .padding(.vertical, 16)
        .padding(.horizontal, 20)
        .background(Color.black.opacity(0.3))
    }
}
