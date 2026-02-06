//
//  HTTPFlowDetailView.swift
//  IrisProxy
//
//  Detail view for a single HTTP flow showing request and response.
//

import SwiftUI

/// Detail view for displaying an HTTP flow's request and response.
public struct HTTPFlowDetailView: View {
    let flow: ProxyCapturedFlow
    @State private var selectedTab: DetailTab = .overview

    public init(flow: ProxyCapturedFlow) {
        self.flow = flow
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Header
            detailHeader

            Divider()

            // Tab picker
            Picker("Tab", selection: $selectedTab) {
                ForEach(DetailTab.allCases) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .padding()

            Divider()

            // Tab content
            ScrollView {
                tabContent
                    .padding()
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
    }

    // MARK: - Header

    private var detailHeader: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Method and URL
            HStack {
                MethodBadge(method: flow.request.method)

                if let response = flow.response {
                    StatusBadge(statusCode: response.statusCode)
                } else if flow.error != nil {
                    ErrorBadge()
                } else {
                    PendingBadge()
                }

                Spacer()

                // Copy URL button
                Button(action: copyURL) {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copy URL")
            }

            // Full URL
            Text(flow.request.url)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.secondary)
                .lineLimit(2)
                .textSelection(.enabled)

            // Metadata row
            HStack(spacing: 16) {
                if let process = flow.processName {
                    Label(process, systemImage: "app")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Label(formatTimestamp(flow.timestamp), systemImage: "clock")
                    .font(.caption)
                    .foregroundColor(.secondary)

                if let duration = flow.duration {
                    Label(formatDuration(duration), systemImage: "stopwatch")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                let totalSize = flow.request.bodySize + (flow.response?.bodySize ?? 0)
                if totalSize > 0 {
                    Label(formatBytes(totalSize), systemImage: "arrow.up.arrow.down")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
    }

    // MARK: - Tab Content

    @ViewBuilder
    private var tabContent: some View {
        switch selectedTab {
        case .overview:
            overviewTab
        case .request:
            requestTab
        case .response:
            responseTab
        case .headers:
            headersTab
        }
    }

    // MARK: - Overview Tab

    private var overviewTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Request summary
            GroupBox("Request") {
                VStack(alignment: .leading, spacing: 8) {
                    DetailRow(label: "Method", value: flow.request.method)
                    DetailRow(label: "URL", value: flow.request.url)
                    DetailRow(label: "HTTP Version", value: flow.request.httpVersion)
                    DetailRow(label: "Body Size", value: formatBytes(flow.request.bodySize))
                    if let host = flow.request.host {
                        DetailRow(label: "Host", value: host)
                    }
                }
                .padding(.vertical, 4)
            }

            // Response summary
            if let response = flow.response {
                GroupBox("Response") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Status")
                                .foregroundColor(.secondary)
                                .frame(width: 100, alignment: .leading)
                            StatusBadge(statusCode: response.statusCode)
                            Text(response.reason)
                                .foregroundColor(.secondary)
                        }
                        DetailRow(label: "HTTP Version", value: response.httpVersion)
                        DetailRow(label: "Body Size", value: formatBytes(response.bodySize))
                        if let contentType = response.contentType {
                            DetailRow(label: "Content-Type", value: contentType)
                        }
                        DetailRow(label: "Duration", value: formatDuration(response.duration))
                    }
                    .padding(.vertical, 4)
                }
            } else if let error = flow.error {
                GroupBox("Error") {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text(error)
                            .foregroundColor(.red)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                GroupBox("Response") {
                    HStack {
                        ProgressView()
                            .scaleEffect(0.8)
                        Text("Waiting for response...")
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }

            // Process info
            if flow.processName != nil || flow.processId != nil {
                GroupBox("Process") {
                    VStack(alignment: .leading, spacing: 8) {
                        if let name = flow.processName {
                            DetailRow(label: "Name", value: name)
                        }
                        if let pid = flow.processId {
                            DetailRow(label: "PID", value: "\(pid)")
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }

    // MARK: - Request Tab

    private var requestTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Request line
            GroupBox("Request Line") {
                Text("\(flow.request.method) \(flow.request.path) \(flow.request.httpVersion)")
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(.vertical, 4)
            }

            // Headers
            GroupBox("Headers") {
                headersView(flow.request.headers)
            }

            // Body preview
            if let preview = flow.request.bodyPreview {
                GroupBox("Body Preview (\(formatBytes(flow.request.bodySize)))") {
                    bodyPreviewView(preview)
                }
            } else if flow.request.bodySize > 0 {
                GroupBox("Body") {
                    Text("\(formatBytes(flow.request.bodySize)) (no preview available)")
                        .foregroundColor(.secondary)
                        .padding(.vertical, 4)
                }
            }
        }
    }

    // MARK: - Response Tab

    private var responseTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let response = flow.response {
                // Status line
                GroupBox("Status Line") {
                    HStack {
                        Text("\(response.httpVersion) \(response.statusCode) \(response.reason)")
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                        Spacer()
                        StatusBadge(statusCode: response.statusCode)
                    }
                    .padding(.vertical, 4)
                }

                // Headers
                GroupBox("Headers") {
                    headersView(response.headers)
                }

                // Body preview
                if let preview = response.bodyPreview {
                    GroupBox("Body Preview (\(formatBytes(response.bodySize)))") {
                        bodyPreviewView(preview)
                    }
                } else if response.bodySize > 0 {
                    GroupBox("Body") {
                        Text("\(formatBytes(response.bodySize)) (no preview available)")
                            .foregroundColor(.secondary)
                            .padding(.vertical, 4)
                    }
                }
            } else if let error = flow.error {
                GroupBox("Error") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text("Request Failed")
                                .font(.headline)
                                .foregroundColor(.red)
                        }
                        Text(error)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                VStack(spacing: 16) {
                    ProgressView()
                    Text("Waiting for response...")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    // MARK: - Headers Tab

    private var headersTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Request Headers (\(flow.request.headers.count))") {
                headersView(flow.request.headers)
            }

            if let response = flow.response {
                GroupBox("Response Headers (\(response.headers.count))") {
                    headersView(response.headers)
                }
            }
        }
    }

    // MARK: - Helper Views

    private func headersView(_ headers: [[String]]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            if headers.isEmpty {
                Text("No headers")
                    .foregroundColor(.secondary)
                    .padding(.vertical, 4)
            } else {
                ForEach(Array(headers.enumerated()), id: \.offset) { _, header in
                    if header.count >= 2 {
                        HStack(alignment: .top, spacing: 8) {
                            Text(header[0])
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(.blue)
                            Text(header[1])
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.primary)
                                .textSelection(.enabled)
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func bodyPreviewView(_ preview: String) -> some View {
        ScrollView(.horizontal, showsIndicators: true) {
            Text(preview)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .padding(.vertical, 4)
        }
        .frame(maxHeight: 300)
    }

    // MARK: - Actions

    private func copyURL() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(flow.request.url, forType: .string)
    }

    // MARK: - Formatting

    private func formatTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: date)
    }

    private func formatDuration(_ duration: TimeInterval) -> String {
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        } else {
            return String(format: "%.2fs", duration)
        }
    }

    private func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

// MARK: - Detail Tab

enum DetailTab: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case request = "Request"
    case response = "Response"
    case headers = "Headers"

    var id: String { rawValue }
}

// MARK: - Preview
// Note: DetailRow is defined in IrisApp/Components/DetailRow.swift

#Preview {
    HTTPFlowDetailView(
        flow: ProxyCapturedFlow(
            id: UUID(),
            timestamp: Date(),
            request: ProxyCapturedRequest(
                method: "GET",
                url: "https://api.example.com/v1/users?page=1&limit=10",
                httpVersion: "HTTP/1.1",
                headers: [
                    ["Host", "api.example.com"],
                    ["User-Agent", "Mozilla/5.0"],
                    ["Accept", "application/json"]
                ],
                bodySize: 0,
                bodyPreview: nil
            ),
            response: ProxyCapturedResponse(
                statusCode: 200,
                reason: "OK",
                httpVersion: "HTTP/1.1",
                headers: [
                    ["Content-Type", "application/json"],
                    ["Content-Length", "1234"]
                ],
                bodySize: 1234,
                bodyPreview: "{\"users\": [{\"id\": 1, \"name\": \"John\"}]}",
                duration: 0.245
            ),
            processName: "Safari",
            processId: 1234
        )
    )
    .frame(width: 500, height: 600)
}
