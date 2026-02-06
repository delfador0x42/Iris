import SwiftUI

/// Individual connection detail row within an expanded process
struct ConnectionDetailRow: View {
    let aggregated: AggregatedConnection
    @State private var isHovering = false
    @State private var showDetailPopover = false

    private var connection: NetworkConnection { aggregated.representative }

    var body: some View {
        HStack(spacing: 0) {
            // Indent + connection info
            HStack(spacing: 8) {
                Spacer()
                    .frame(width: 40) // Indent

                Text("→")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)

                // Remote endpoint (IP only) - clickable to show detail popover
                Button {
                    showDetailPopover = true
                } label: {
                    HStack(spacing: 4) {
                        Text(connection.remoteEndpoint)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(isHovering ? .cyan : .white.opacity(0.8))
                            .underline(isHovering)

                        // Vulnerability indicator
                        if connection.hasCriticalVulns {
                            Image(systemName: "exclamationmark.shield.fill")
                                .foregroundColor(.red)
                                .font(.system(size: 10))
                                .help("\(connection.remoteCVEs?.count ?? 0) known vulnerabilities")
                        }

                        // Location badge if available
                        if let location = connection.locationDescription {
                            Text("(\(location))")
                                .font(.system(size: 10))
                                .foregroundColor(.cyan.opacity(0.7))
                        }
                    }
                }
                .buttonStyle(.plain)
                .pointerCursor()
                .onHover { hovering in
                    isHovering = hovering
                }
                .help("View IP details")
                .popover(isPresented: $showDetailPopover) {
                    IPDetailPopover(aggregated: aggregated)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Protocol
            Text(connection.protocol.rawValue)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 60)

            // Interface
            Text(connection.interface ?? "-")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 70)

            // State
            Text(connection.state.rawValue)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(stateColor)
                .frame(width: 90)

            // Bytes up (aggregated total)
            Text(NetworkConnection.formatBytes(aggregated.totalBytesUp))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 80, alignment: .trailing)

            // Bytes down (aggregated total)
            Text(NetworkConnection.formatBytes(aggregated.totalBytesDown))
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 80, alignment: .trailing)
        }
        .padding(.vertical, 4)
    }

    private var stateColor: Color {
        switch connection.state {
        case .established: return .green
        case .listen: return .blue
        case .closed: return .gray
        default: return .orange
        }
    }
}
