import SwiftUI

// MARK: - HTTP Section

extension IPDetailPopover {

    var httpSection: some View {
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
}
