import SwiftUI

/// Row showing a process and its aggregated network connections
struct ProcessConnectionRow: View {
    let process: SecurityStore.ProcessSummary
    let connections: [NetworkConnection]
    let isExpanded: Bool
    let onToggle: () -> Void
    var onViewTraffic: ((NetworkConnection) -> Void)?
    var onViewPlaintext: ((NetworkConnection) -> Void)?
    @EnvironmentObject private var store: SecurityStore

    /// Aggregate connections by remote IP for deduplication
    private var aggregatedConnections: [AggregatedConnection] {
        let grouped = Dictionary(grouping: connections) { $0.remoteAddress }
        return grouped.map { (ip, conns) in
            AggregatedConnection(id: ip, remoteAddress: ip, connections: conns)
        }
        .sorted { compareIPAddresses($0.remoteAddress, $1.remoteAddress) }
    }

    /// Compare two IP addresses numerically
    /// IPv4 addresses are sorted before IPv6, then numerically within each type
    private func compareIPAddresses(_ ip1: String, _ ip2: String) -> Bool {
        let parts1 = ip1.split(separator: ".").compactMap { Int($0) }
        let parts2 = ip2.split(separator: ".").compactMap { Int($0) }

        // If both are valid IPv4 (4 octets), compare numerically
        if parts1.count == 4 && parts2.count == 4 {
            for i in 0..<4 {
                if parts1[i] != parts2[i] {
                    return parts1[i] < parts2[i]
                }
            }
            return false // Equal
        }

        // IPv4 comes before IPv6
        if parts1.count == 4 && parts2.count != 4 {
            return true
        }
        if parts1.count != 4 && parts2.count == 4 {
            return false
        }

        // Fall back to string comparison for IPv6 or other formats
        return ip1 < ip2
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Process row
            HStack(spacing: 8) {
                // Expand indicator
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .font(.system(size: 10))
                    .foregroundColor(.gray)
                    .frame(width: 12)

                // Process icon (placeholder)
                Image(systemName: "app.fill")
                    .foregroundColor(.blue)
                    .frame(width: 20)

                // Process name and path
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(process.name)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.white)

                        if process.pids.count > 1 {
                            Text("\(process.pids.count) instances")
                                .font(.system(size: 10))
                                .foregroundColor(.gray)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .background(Color.white.opacity(0.1))
                                .cornerRadius(3)
                        }

                        Text("\(process.connectionCount)")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundColor(.cyan)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.cyan.opacity(0.15))
                            .cornerRadius(3)
                    }

                    Text(process.path)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.7))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                // Rule status + quick actions
                HStack(spacing: 4) {
                    if let action = store.effectiveAction(for: process.identityKey) {
                        Image(systemName: action == .allow
                              ? "checkmark.shield.fill" : "xmark.shield.fill")
                            .foregroundColor(action == .allow ? .green : .red)
                            .font(.system(size: 14))
                            .help(action == .allow ? "Allowed" : "Blocked")
                    }

                    Button {
                        Task {
                            await store.allowProcess(
                                identityKey: process.identityKey,
                                path: process.path,
                                signingId: process.signingId
                            )
                        }
                    } label: {
                        Image(systemName: "checkmark.circle")
                            .foregroundColor(.green.opacity(0.7))
                            .font(.system(size: 12))
                    }
                    .buttonStyle(.plain)
                    .help("Allow all connections")

                    Button {
                        Task {
                            await store.blockProcess(
                                identityKey: process.identityKey,
                                path: process.path,
                                signingId: process.signingId
                            )
                        }
                    } label: {
                        Image(systemName: "xmark.circle")
                            .foregroundColor(.red.opacity(0.7))
                            .font(.system(size: 12))
                    }
                    .buttonStyle(.plain)
                    .help("Block all connections")
                }

                Spacer()

                // Total bytes
                Text(process.formattedBytesUp)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.gray)
                    .frame(width: 80, alignment: .trailing)

                Text(process.formattedBytesDown)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.gray)
                    .frame(width: 80, alignment: .trailing)
            }
            .padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture {
                onToggle()
            }

            // Connection rows (when expanded) - deduplicated by IP
            if isExpanded {
                ForEach(aggregatedConnections) { aggregated in
                    ConnectionDetailRow(aggregated: aggregated, onViewTraffic: onViewTraffic, onViewPlaintext: onViewPlaintext)
                }
            }
        }
        .background(
            isExpanded ? Color.white.opacity(0.03) : Color.clear
        )
    }
}
