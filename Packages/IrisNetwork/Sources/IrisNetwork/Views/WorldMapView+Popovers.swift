import SwiftUI
import AppKit

// MARK: - Endpoint Popover & Supporting Views

struct EndpointPopover: View {
    let endpoint: ConnectionEndpoint

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Location
            HStack {
                Image(systemName: "mappin.circle.fill")
                    .foregroundColor(.red)
                Text(endpoint.label)
                    .font(.headline)
            }

            Divider()

            // Stats
            LabeledContent("Connections", value: "\(endpoint.connectionCount)")
            LabeledContent("Upload", value: NetworkConnection.formatBytes(endpoint.totalBytesUp))
            LabeledContent("Download", value: NetworkConnection.formatBytes(endpoint.totalBytesDown))

            // IP addresses with Shodan links
            if !endpoint.uniqueIPs.isEmpty {
                Divider()
                Text("IP Addresses:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                ForEach(Array(endpoint.uniqueIPs.prefix(5)).sorted(), id: \.self) { ip in
                    IPAddressRow(ip: ip)
                }
                if endpoint.uniqueIPs.count > 5 {
                    Text("... and \(endpoint.uniqueIPs.count - 5) more")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            if !endpoint.processes.isEmpty {
                Divider()
                Text("Processes:")
                    .font(.caption)
                    .foregroundColor(.secondary)
                ForEach(Array(endpoint.processes.prefix(5)), id: \.self) { process in
                    Text("• \(process)")
                        .font(.caption)
                }
                if endpoint.processes.count > 5 {
                    Text("... and \(endpoint.processes.count - 5) more")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .frame(minWidth: 220)
    }
}

struct IPAddressRow: View {
    let ip: String
    @State private var isHovering = false

    var body: some View {
        Button {
            openShodan(for: ip)
        } label: {
            Text("• \(ip)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(isHovering ? .cyan : .primary)
                .underline(isHovering)
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .onHover { hovering in
            isHovering = hovering
        }
        .help("View on Shodan")
    }

    private func openShodan(for ip: String) {
        let urlString = "https://www.shodan.io/host/\(ip)"
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
        }
    }
}

struct StatBadge: View {
    let label: String
    let value: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 16, weight: .bold, design: .rounded))
                .foregroundColor(.primary)
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}
