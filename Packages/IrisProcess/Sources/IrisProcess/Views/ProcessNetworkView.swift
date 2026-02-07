import SwiftUI

/// Displays network connections filtered for a specific process PID.
/// Designed to be embedded in ProcessDetailView.
struct ProcessNetworkView: View {
    let pid: Int32
    let connections: [ProcessNetworkConnection]

    var body: some View {
        if connections.isEmpty {
            HStack(spacing: 8) {
                Image(systemName: "network.slash")
                    .foregroundColor(.gray)
                Text("No active connections")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)
            }
        } else {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(connections) { conn in
                    HStack(spacing: 8) {
                        // Protocol
                        Text(conn.proto)
                            .font(.system(size: 10, weight: .medium, design: .monospaced))
                            .foregroundColor(.cyan)
                            .frame(width: 35, alignment: .leading)

                        // Local address
                        Text("\(conn.localAddress):\(conn.localPort)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.gray)
                            .lineLimit(1)

                        Image(systemName: "arrow.right")
                            .font(.system(size: 8))
                            .foregroundColor(.gray)

                        // Remote address
                        Text("\(conn.remoteAddress):\(conn.remotePort)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.white)
                            .lineLimit(1)

                        Spacer()

                        // State
                        Text(conn.state)
                            .font(.system(size: 9, weight: .medium))
                            .foregroundColor(stateColor(conn.state))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(stateColor(conn.state).opacity(0.15))
                            .cornerRadius(3)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
    }

    private func stateColor(_ state: String) -> Color {
        switch state.uppercased() {
        case "ESTABLISHED": return .green
        case "LISTEN": return .blue
        case "TIME_WAIT", "CLOSE_WAIT": return .orange
        case "SYN_SENT": return .yellow
        default: return .gray
        }
    }
}

/// Lightweight model for process-specific network connections
public struct ProcessNetworkConnection: Identifiable, Sendable {
    public let id = UUID()
    public let proto: String
    public let localAddress: String
    public let localPort: Int
    public let remoteAddress: String
    public let remotePort: Int
    public let state: String

    public init(
        proto: String,
        localAddress: String,
        localPort: Int,
        remoteAddress: String,
        remotePort: Int,
        state: String
    ) {
        self.proto = proto
        self.localAddress = localAddress
        self.localPort = localPort
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.state = state
    }
}
