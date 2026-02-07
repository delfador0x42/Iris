import SwiftUI

// MARK: - Info Row Helpers

/// A row displaying a label and value in a consistent format
struct InfoRow<Content: View>: View {
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
struct SimpleInfoRow: View {
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
