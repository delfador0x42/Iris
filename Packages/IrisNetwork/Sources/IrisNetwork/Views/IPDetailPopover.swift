import SwiftUI
import AppKit

/// Rich inline detail view showing IP enrichment data (geolocation + security)
struct IPDetailPopover: View {
    let aggregated: AggregatedConnection
    @Environment(\.dismiss) private var dismiss
    @State private var showHTTPRawDetail = false

    private var connection: NetworkConnection { aggregated.representative }

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

    private var stateColor: Color {
        switch connection.state {
        case .established: return .green
        case .listen: return .blue
        case .closed: return .gray
        default: return .orange
        }
    }

    // MARK: - HTTP Section

    private var httpSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("HTTP Details", systemImage: "globe")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 6) {
                // Request info
                if let method = connection.httpMethod {
                    HStack(spacing: 8) {
                        HTTPMethodBadge(method: method)

                        if let path = connection.httpPath {
                            Text(path)
                                .font(.system(size: 12, design: .monospaced))
                                .lineLimit(2)
                                .textSelection(.enabled)
                        }
                    }
                }

                // Host
                if let host = connection.httpHost {
                    HStack(spacing: 4) {
                        Text("Host:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(host)
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                // Response status
                if let statusCode = connection.httpStatusCode {
                    HStack(spacing: 8) {
                        Text("Response:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        HTTPStatusBadge(statusCode: statusCode)
                        if let reason = connection.httpStatusReason {
                            Text(reason)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }

                // Content types
                if let contentType = connection.httpContentType {
                    HStack(spacing: 4) {
                        Text("Request Content-Type:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(contentType)
                            .font(.system(size: 11, design: .monospaced))
                            .lineLimit(1)
                    }
                }

                if let responseContentType = connection.httpResponseContentType {
                    HStack(spacing: 4) {
                        Text("Response Content-Type:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(responseContentType)
                            .font(.system(size: 11, design: .monospaced))
                            .lineLimit(1)
                    }
                }

                // User Agent
                if let userAgent = connection.httpUserAgent {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("User-Agent:")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(userAgent)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(2)
                            .textSelection(.enabled)
                    }
                }

                // Full details button (shows raw request/response)
                if connection.httpRawRequest != nil || connection.httpRawResponse != nil {
                    Button {
                        showHTTPRawDetail = true
                    } label: {
                        HStack {
                            Label("View Full Request/Response", systemImage: "doc.text.magnifyingglass")
                            Spacer()
                            Image(systemName: "arrow.up.right.square")
                                .font(.caption)
                        }
                    }
                    .buttonStyle(.bordered)
                    .padding(.top, 8)
                    .sheet(isPresented: $showHTTPRawDetail) {
                        HTTPRawDetailView(connection: connection)
                    }
                }
            }
        }
    }

    // MARK: - General Information Section

    private var locationSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("General Information", systemImage: "info.circle.fill")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 8) {
                // Hostnames
                if let hostnames = connection.remoteHostnames, !hostnames.isEmpty {
                    InfoRow(label: "Hostnames") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(hostnames.prefix(5), id: \.self) { hostname in
                                Text(hostname)
                                    .font(.system(size: 12, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            if hostnames.count > 5 {
                                Text("+\(hostnames.count - 5) more")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                } else if let hostname = connection.remoteHostname {
                    SimpleInfoRow(label: "Hostname", value: hostname)
                }

                // Domains (extracted from hostnames)
                let domains = extractDomains()
                if !domains.isEmpty {
                    InfoRow(label: "Domains") {
                        FlowLayout(spacing: 4) {
                            ForEach(domains, id: \.self) { domain in
                                Text(domain)
                                    .font(.system(size: 11, design: .monospaced))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.blue.opacity(0.15))
                                    .cornerRadius(4)
                            }
                        }
                    }
                }

                Divider()

                // Country
                if let country = connection.remoteCountry {
                    InfoRow(label: "Country") {
                        HStack(spacing: 6) {
                            if let code = connection.remoteCountryCode {
                                Text(countryFlag(for: code))
                            }
                            Text(country)
                                .font(.system(size: 12))
                        }
                    }
                }

                // City
                if let city = connection.remoteCity, !city.isEmpty {
                    SimpleInfoRow(label: "City", value: city)
                }

                Divider()

                // Organization / ISP
                if let org = connection.remoteOrganization {
                    SimpleInfoRow(label: "Organization", value: org)
                }

                // ASN
                if let asn = connection.remoteASN {
                    SimpleInfoRow(label: "ASN", value: asn)
                }
            }
        }
    }

    /// Extract unique domains from hostnames
    private func extractDomains() -> [String] {
        guard let hostnames = connection.remoteHostnames else { return [] }

        var domains = Set<String>()
        for hostname in hostnames {
            let parts = hostname.split(separator: ".")
            if parts.count >= 2 {
                // Get last two parts as domain (e.g., github.com from www.github.com)
                let domain = parts.suffix(2).joined(separator: ".")
                domains.insert(domain)
            }
        }
        return Array(domains).sorted()
    }

    /// Convert country code to flag emoji
    private func countryFlag(for code: String) -> String {
        let base: UInt32 = 127397
        var flag = ""
        for scalar in code.uppercased().unicodeScalars {
            if let flagScalar = UnicodeScalar(base + scalar.value) {
                flag.append(Character(flagScalar))
            }
        }
        return flag
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

    // MARK: - Threat Intelligence Section

    private var threatIntelligenceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Threat Intelligence", systemImage: "shield.checkerboard")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 8) {
                // Abuse score with color indicator and progress bar
                if let score = connection.abuseScore {
                    InfoRow(label: "Abuse Score") {
                        HStack(spacing: 6) {
                            Text("\(score)%")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(abuseScoreColor(score))
                            ProgressView(value: Double(score), total: 100)
                                .progressViewStyle(.linear)
                                .frame(width: 60)
                                .tint(abuseScoreColor(score))
                        }
                    }
                }

                // Scanner status
                if let isScanner = connection.isKnownScanner {
                    SimpleInfoRow(
                        label: "Scanner",
                        value: isScanner ? "Yes (known scanner)" : "No"
                    )
                }

                // Benign service status
                if let isBenign = connection.isBenignService {
                    SimpleInfoRow(
                        label: "Benign Service",
                        value: isBenign ? "Yes (CDN/Cloud)" : "No"
                    )
                }

                // Tor exit node
                if let isTor = connection.isTor, isTor {
                    InfoRow(label: "Tor Exit") {
                        HStack(spacing: 4) {
                            Image(systemName: "eye.slash.fill")
                                .foregroundColor(.purple)
                            Text("Yes")
                                .font(.system(size: 12))
                        }
                    }
                }

                // Classification badge
                if let classification = connection.threatClassification {
                    InfoRow(label: "Classification") {
                        ThreatBadge(classification: classification)
                    }
                }

                // Data sources
                if let sources = connection.enrichmentSources, !sources.isEmpty {
                    InfoRow(label: "Sources") {
                        Text(sources.joined(separator: ", "))
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
    }

    /// Color for abuse score based on severity
    private func abuseScoreColor(_ score: Int) -> Color {
        switch score {
        case 0..<25: return .green
        case 25..<50: return .yellow
        case 50..<75: return .orange
        default: return .red
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

// MARK: - Info Row Helper

/// A row displaying a label and value in a consistent format
private struct InfoRow<Content: View>: View {
    let label: String
    let content: Content

    init(label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .trailing)

            content
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// Simple info row for string values
private struct SimpleInfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(.secondary)
                .frame(width: 80, alignment: .trailing)

            Text(value)
                .font(.system(size: 12))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
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
        remoteAddress: "140.82.113.22",
        remotePort: 443,
        protocol: .tcp,
        state: .established,
        remoteCountry: "United States",
        remoteCountryCode: "US",
        remoteCity: "South Riding",
        remoteLatitude: 38.9242,
        remoteLongitude: -77.5074,
        remoteASN: "AS36459",
        remoteOrganization: "GitHub, Inc.",
        remoteOpenPorts: [80, 443, 22, 8080],
        remoteHostnames: ["git.io", "www.git.io", "lb-140-82-113-22-iad.github.com", "api.github.com"],
        remoteCVEs: ["CVE-2023-1234", "CVE-2023-5678"],
        remoteServiceTags: ["cloud", "starttls"],
        httpMethod: "GET",
        httpPath: "/api/v2/users/profile?include=settings",
        httpHost: "api.apple.com",
        httpContentType: nil,
        httpUserAgent: "curl/8.0.1",
        httpStatusCode: 200,
        httpStatusReason: "OK",
        httpResponseContentType: "application/json; charset=utf-8",
        httpRawRequest: "GET /api/v2/users/profile?include=settings HTTP/1.1\r\nHost: api.apple.com\r\nUser-Agent: curl/8.0.1\r\nAccept: */*\r\n",
        httpRawResponse: "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 1234\r\nDate: Thu, 06 Feb 2026 12:00:00 GMT\r\n"
    )

    return IPDetailPopover(
        aggregated: AggregatedConnection(
            id: "140.82.113.22",
            remoteAddress: "140.82.113.22",
            connections: [sampleConnection, sampleConnection, sampleConnection, sampleConnection]
        )
    )
}
