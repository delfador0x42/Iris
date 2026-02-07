import SwiftUI
import AppKit

/// Rich inline detail view showing IP enrichment data (geolocation + security)
struct IPDetailPopover: View {
    let aggregated: AggregatedConnection
    @Environment(\.dismiss) private var dismiss
    @State var showHTTPRawDetail = false

    var connection: NetworkConnection { aggregated.representative }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header with IP and hostname
                headerSection

                Divider()

                // HTTP Request/Response details (if available)
                if connection.hasHTTPData {
                    httpSection
                    Divider()
                }

                // Location & Organization
                if connection.hasGeolocation {
                    locationSection
                    Divider()
                }

                // Open Ports
                if let ports = connection.remoteOpenPorts, !ports.isEmpty {
                    portsSection(ports)
                    Divider()
                }

                // Hostnames
                if let hostnames = connection.remoteHostnames, !hostnames.isEmpty {
                    hostnamesSection(hostnames)
                    Divider()
                }

                // Vulnerabilities (CVEs)
                if let cves = connection.remoteCVEs, !cves.isEmpty {
                    vulnerabilitiesSection(cves)
                    Divider()
                }

                // Service Tags
                if let tags = connection.remoteServiceTags, !tags.isEmpty {
                    tagsSection(tags)
                    Divider()
                }

                // Threat Intelligence
                if connection.hasThreatData {
                    threatIntelligenceSection
                    Divider()
                }

                // External link to Shodan for full details
                shodanLink
            }
            .padding()
        }
        .frame(width: 360, height: 480)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Header Section

    var headerSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(connection.remoteAddress)
                    .font(.system(size: 18, weight: .bold, design: .monospaced))
                    .textSelection(.enabled)

                if aggregated.connectionCount > 1 {
                    Text("(\(aggregated.connectionCount) connections)")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                }
            }

            // Hostname (moved from connection row to popover)
            if let hostname = connection.remoteHostnames?.first ?? connection.remoteHostname {
                Text(hostname)
                    .font(.system(size: 14))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }

            // Connection info
            HStack(spacing: 12) {
                Label("Port \(connection.remotePort)", systemImage: "network")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Label(connection.protocol.rawValue, systemImage: "arrow.left.arrow.right")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Label(connection.state.rawValue, systemImage: "circle.fill")
                    .font(.caption)
                    .foregroundColor(stateColor)
            }
            .padding(.top, 4)

            // Process info with full path
            VStack(alignment: .leading, spacing: 2) {
                Text("\(connection.processName) (pid: \(connection.processId))")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.secondary)

                Text(connection.processPath)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary.opacity(0.8))
                    .textSelection(.enabled)
            }
            .padding(.top, 8)
        }
    }

    var stateColor: Color {
        switch connection.state {
        case .established: return .green
        case .listen: return .blue
        case .closed: return .gray
        default: return .orange
        }
    }
}
