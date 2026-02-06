import SwiftUI
import AppKit

/// Full detail view showing raw HTTP request and response data
struct HTTPRawDetailView: View {
    let connection: NetworkConnection
    @Environment(\.dismiss) private var dismiss
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Header
            header

            Divider()

            // Tab selector
            Picker("", selection: $selectedTab) {
                Text("Request").tag(0)
                Text("Response").tag(1)
            }
            .pickerStyle(.segmented)
            .padding()

            // Content
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if selectedTab == 0 {
                        requestView
                    } else {
                        responseView
                    }
                }
                .padding()
            }

            Divider()

            // Footer with copy button
            footer
        }
        .frame(width: 700, height: 500)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    if let method = connection.httpMethod {
                        HTTPMethodBadge(method: method)
                    }
                    Text(connection.httpHost ?? connection.remoteAddress)
                        .font(.headline)
                }

                if let path = connection.httpPath {
                    Text(path)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            if let statusCode = connection.httpStatusCode {
                HStack(spacing: 8) {
                    HTTPStatusBadge(statusCode: statusCode)
                    if let reason = connection.httpStatusReason {
                        Text(reason)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding()
    }

    // MARK: - Request View

    private var requestView: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let rawRequest = connection.httpRawRequest {
                // Request line highlight
                if let method = connection.httpMethod, let path = connection.httpPath {
                    HStack(spacing: 8) {
                        HTTPMethodBadge(method: method)
                        Text(path)
                            .font(.system(size: 13, weight: .medium, design: .monospaced))
                            .foregroundColor(.primary)
                    }
                    .padding(.bottom, 8)
                }

                // Raw headers
                SectionHeader(title: "Request Headers", icon: "arrow.up.doc")

                RawTextView(text: rawRequest)
            } else {
                noDataView(message: "No HTTP request data captured")
            }
        }
    }

    // MARK: - Response View

    private var responseView: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let rawResponse = connection.httpRawResponse {
                // Status line highlight
                if let statusCode = connection.httpStatusCode {
                    HStack(spacing: 8) {
                        HTTPStatusBadge(statusCode: statusCode)
                        if let reason = connection.httpStatusReason {
                            Text(reason)
                                .font(.system(size: 13, weight: .medium))
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.bottom, 8)
                }

                // Raw headers
                SectionHeader(title: "Response Headers", icon: "arrow.down.doc")

                RawTextView(text: rawResponse)
            } else {
                noDataView(message: "No HTTP response data captured")
            }
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button {
                copyToClipboard()
            } label: {
                Label("Copy All", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)

            Spacer()

            Button("Close") {
                dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    // MARK: - Helpers

    private func noDataView(message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 32))
                .foregroundColor(.secondary)
            Text(message)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 200)
    }

    private func copyToClipboard() {
        var content = ""

        if let rawRequest = connection.httpRawRequest {
            content += "=== REQUEST ===\n\n"
            content += rawRequest
            content += "\n\n"
        }

        if let rawResponse = connection.httpRawResponse {
            content += "=== RESPONSE ===\n\n"
            content += rawResponse
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(content, forType: .string)
    }
}

// MARK: - Supporting Views

private struct SectionHeader: View {
    let title: String
    let icon: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 12))
            Text(title)
                .font(.system(size: 12, weight: .semibold))
        }
        .foregroundColor(.secondary)
    }
}

private struct RawTextView: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced))
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.gray.opacity(0.2), lineWidth: 1)
            )
    }
}

// MARK: - Preview

#Preview {
    HTTPRawDetailView(
        connection: NetworkConnection(
            processId: 1234,
            processPath: "/usr/bin/curl",
            processName: "curl",
            localAddress: "192.168.1.100",
            localPort: 54321,
            remoteAddress: "93.184.216.34",
            remotePort: 443,
            protocol: .tcp,
            state: .established,
            httpMethod: "GET",
            httpPath: "/api/v2/users/profile",
            httpHost: "api.example.com",
            httpUserAgent: "curl/8.0.1",
            httpStatusCode: 200,
            httpStatusReason: "OK",
            httpResponseContentType: "application/json",
            httpRawRequest: """
            GET /api/v2/users/profile HTTP/1.1\r
            Host: api.example.com\r
            User-Agent: curl/8.0.1\r
            Accept: application/json\r
            Authorization: Bearer eyJhbGciOiJIUzI1...\r
            X-Request-ID: abc123\r
            """,
            httpRawResponse: """
            HTTP/1.1 200 OK\r
            Content-Type: application/json; charset=utf-8\r
            Content-Length: 256\r
            Date: Thu, 06 Feb 2026 12:00:00 GMT\r
            Server: nginx/1.24.0\r
            X-RateLimit-Remaining: 99\r
            Cache-Control: no-cache\r
            """
        )
    )
}
