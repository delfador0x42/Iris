import SwiftUI
import AppKit

/// Rich inline detail view showing IP enrichment data (geolocation + security)
struct IPDetailPopover: View {
    let aggregated: AggregatedConnection
    @Environment(\.dismiss) private var dismiss

    private var connection: NetworkConnection { aggregated.representative }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header with IP and hostname
                headerSection

                Divider()

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

                // External link to Shodan for full details
                shodanLink
            }
            .padding()
        }
        .frame(width: 360, height: 480)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Header Section

    private var headerSection: some View {
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
        }
    }

    private var stateColor: Color {
        switch connection.state {
        case .established: return .green
        case .listen: return .blue
        case .closed: return .gray
        default: return .orange
        }
    }

    // MARK: - Location Section

    private var locationSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Location", systemImage: "mappin.circle.fill")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 4) {
                if let location = connection.locationDescription {
                    Text(location)
                        .font(.body)
                }

                if let org = connection.remoteOrganization {
                    Text(org)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                if let asn = connection.remoteASN {
                    Text(asn)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
    }

    // MARK: - Ports Section

    private func portsSection(_ ports: [UInt16]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Open Ports (\(ports.count))", systemImage: "network")
                .font(.headline)
                .foregroundColor(.primary)

            FlowLayout(spacing: 6) {
                ForEach(ports.sorted(), id: \.self) { port in
                    PortBadge(port: port)
                }
            }
        }
    }

    // MARK: - Hostnames Section

    private func hostnamesSection(_ hostnames: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Hostnames (\(hostnames.count))", systemImage: "globe")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 4) {
                ForEach(hostnames, id: \.self) { hostname in
                    Text(hostname)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }

    // MARK: - Vulnerabilities Section

    private func vulnerabilitiesSection(_ cves: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Vulnerabilities (\(cves.count))", systemImage: "exclamationmark.shield.fill")
                .font(.headline)
                .foregroundColor(.red)

            FlowLayout(spacing: 6) {
                ForEach(cves, id: \.self) { cve in
                    CVEBadge(cve: cve)
                }
            }
        }
    }

    // MARK: - Tags Section

    private func tagsSection(_ tags: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Service Tags", systemImage: "tag.fill")
                .font(.headline)
                .foregroundColor(.primary)

            FlowLayout(spacing: 6) {
                ForEach(tags, id: \.self) { tag in
                    ServiceTagBadge(tag: tag)
                }
            }
        }
    }

    // MARK: - Shodan Link

    private var shodanLink: some View {
        Button {
            let urlString = "https://www.shodan.io/host/\(connection.remoteAddress)"
            if let url = URL(string: urlString) {
                NSWorkspace.shared.open(url)
            }
        } label: {
            HStack {
                Label("View Full Details on Shodan", systemImage: "arrow.up.right.square")
                Spacer()
            }
        }
        .buttonStyle(.link)
        .pointerCursor()
    }
}

// MARK: - Port Badge

struct PortBadge: View {
    let port: UInt16
    @State private var isHovering = false

    var body: some View {
        Text("\(port)")
            .font(.system(size: 11, weight: .medium, design: .monospaced))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(portColor.opacity(isHovering ? 0.3 : 0.2))
            .foregroundColor(portColor)
            .cornerRadius(4)
            .onHover { isHovering = $0 }
            .help(portDescription)
    }

    private var portColor: Color {
        switch port {
        case 22: return .green         // SSH
        case 80, 8080: return .blue    // HTTP
        case 443, 8443: return .cyan   // HTTPS
        case 21: return .orange        // FTP
        case 23: return .red           // Telnet (insecure)
        case 25, 587: return .purple   // SMTP
        case 53: return .teal          // DNS
        case 3389: return .red         // RDP
        case 3306: return .yellow      // MySQL
        case 5432: return .blue        // PostgreSQL
        case 27017: return .green      // MongoDB
        case 6379: return .red         // Redis
        default: return .gray
        }
    }

    private var portDescription: String {
        switch port {
        case 21: return "FTP"
        case 22: return "SSH"
        case 23: return "Telnet"
        case 25: return "SMTP"
        case 53: return "DNS"
        case 80: return "HTTP"
        case 110: return "POP3"
        case 143: return "IMAP"
        case 443: return "HTTPS"
        case 587: return "SMTP (submission)"
        case 993: return "IMAPS"
        case 995: return "POP3S"
        case 3306: return "MySQL"
        case 3389: return "RDP"
        case 5432: return "PostgreSQL"
        case 5900: return "VNC"
        case 6379: return "Redis"
        case 8080: return "HTTP Alt"
        case 8443: return "HTTPS Alt"
        case 27017: return "MongoDB"
        default: return "Port \(port)"
        }
    }
}

// MARK: - CVE Badge

struct CVEBadge: View {
    let cve: String
    @State private var isHovering = false

    var body: some View {
        Button {
            // Open CVE details on NVD
            let urlString = "https://nvd.nist.gov/vuln/detail/\(cve)"
            if let url = URL(string: urlString) {
                NSWorkspace.shared.open(url)
            }
        } label: {
            Text(cve)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(Color.red.opacity(isHovering ? 0.3 : 0.2))
                .foregroundColor(.red)
                .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .onHover { isHovering = $0 }
        .help("View CVE details on NVD")
    }
}

// MARK: - Service Tag Badge

struct ServiceTagBadge: View {
    let tag: String

    var body: some View {
        Text(tag)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(tagColor.opacity(0.2))
            .foregroundColor(tagColor)
            .cornerRadius(4)
    }

    private var tagColor: Color {
        switch tag.lowercased() {
        case "vpn": return .purple
        case "proxy": return .orange
        case "botnet", "malware", "compromised": return .red
        case "tor": return .indigo
        case "honeypot": return .yellow
        case "self-signed": return .orange
        case "cloud": return .cyan
        case "iot": return .teal
        case "database": return .blue
        case "starttls": return .green
        default: return .gray
        }
    }
}

// MARK: - Flow Layout for Badges

struct FlowLayout: Layout {
    var spacing: CGFloat = 8

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let containerWidth = proposal.width ?? .infinity
        var currentX: CGFloat = 0
        var currentY: CGFloat = 0
        var lineHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)

            if currentX + size.width > containerWidth && currentX > 0 {
                currentX = 0
                currentY += lineHeight + spacing
                lineHeight = 0
            }

            currentX += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }

        return CGSize(width: containerWidth, height: currentY + lineHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var currentX: CGFloat = bounds.minX
        var currentY: CGFloat = bounds.minY
        var lineHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)

            if currentX + size.width > bounds.maxX && currentX > bounds.minX {
                currentX = bounds.minX
                currentY += lineHeight + spacing
                lineHeight = 0
            }

            subview.place(
                at: CGPoint(x: currentX, y: currentY),
                proposal: ProposedViewSize(size)
            )

            currentX += size.width + spacing
            lineHeight = max(lineHeight, size.height)
        }
    }
}

// MARK: - Preview

#Preview {
    let sampleConnection = NetworkConnection(
        processId: 1234,
        processPath: "/usr/bin/curl",
        processName: "curl",
        localAddress: "192.168.1.100",
        localPort: 54321,
        remoteAddress: "17.248.192.3",
        remotePort: 443,
        protocol: .tcp,
        state: .established,
        remoteCountry: "United States",
        remoteCountryCode: "US",
        remoteCity: "Cupertino",
        remoteLatitude: 37.3230,
        remoteLongitude: -122.0322,
        remoteASN: "AS714 Apple Inc.",
        remoteOrganization: "Apple Inc.",
        remoteOpenPorts: [80, 443, 22, 8080],
        remoteHostnames: ["apple.com", "www.apple.com"],
        remoteCVEs: ["CVE-2023-1234", "CVE-2023-5678"],
        remoteServiceTags: ["cloud", "starttls"]
    )

    return IPDetailPopover(
        aggregated: AggregatedConnection(
            id: "17.248.192.3",
            remoteAddress: "17.248.192.3",
            connections: [sampleConnection, sampleConnection, sampleConnection, sampleConnection]
        )
    )
}
