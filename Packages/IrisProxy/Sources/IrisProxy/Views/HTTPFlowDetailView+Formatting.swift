//
//  HTTPFlowDetailView+Helpers.swift
//  IrisProxy
//
//  Helper views, actions, and formatting for HTTPFlowDetailView.
//

import SwiftUI

extension HTTPFlowDetailView {

    // MARK: - Helper Views

    func headersView(_ headers: [[String]]) -> some View {
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

    func bodyPreviewView(_ preview: String) -> some View {
        ThemedScrollView(.horizontal) {
            Text(preview)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .padding(.vertical, 4)
        }
        .frame(maxHeight: 300)
    }

    // MARK: - Actions

    func copyURL() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(flow.request.url, forType: .string)
    }

    // MARK: - Formatting

    func formatTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: date)
    }

    func formatDuration(_ duration: TimeInterval) -> String {
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        } else {
            return String(format: "%.2fs", duration)
        }
    }

    func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

// MARK: - Preview

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
