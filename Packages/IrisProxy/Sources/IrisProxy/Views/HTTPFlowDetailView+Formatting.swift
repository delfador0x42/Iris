//
//  HTTPFlowDetailView+Formatting.swift
//  IrisProxy
//
//  Helper views, actions, formatting — NieR aesthetic.
//

import SwiftUI

// Shared timestamp formatter — avoid recreation per view body
private let timestampFormatter: DateFormatter = {
  let f = DateFormatter()
  f.dateFormat = "HH:mm:ss.SSS"
  return f
}()

extension HTTPFlowDetailView {

  // MARK: - Helper Views

  func headersView(_ headers: [[String]]) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      if headers.isEmpty {
        Text("No headers")
          .font(.system(size: 10, design: .monospaced))
          .foregroundColor(.white.opacity(0.15))
      } else {
        ForEach(Array(headers.enumerated()), id: \.offset) { _, header in
          if header.count >= 2 {
            HStack(alignment: .top, spacing: 6) {
              Text(header[0])
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundColor(.cyan.opacity(0.6))
              Text(header[1])
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.55))
                .textSelection(.enabled)
            }
            .padding(.vertical, 1)
          }
        }
      }
    }
  }

  func bodyPreviewView(_ preview: String) -> some View {
    ThemedScrollView(.horizontal) {
      Text(preview)
        .font(.system(size: 10, design: .monospaced))
        .foregroundColor(.white.opacity(0.6))
        .textSelection(.enabled)
    }
    .frame(maxHeight: 300)
  }

  // MARK: - Actions

  func copyURL() {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(request.url, forType: .string)
  }

  // MARK: - Formatting

  func formatTimestamp(_ date: Date) -> String {
    timestampFormatter.string(from: date)
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
      flowType: .https,
      host: "api.example.com",
      port: 443,
      request: ProxyCapturedRequest(
        method: "GET",
        url: "https://api.example.com/v1/users?page=1&limit=10",
        httpVersion: "HTTP/1.1",
        headers: [
          ["Host", "api.example.com"],
          ["User-Agent", "Mozilla/5.0"],
          ["Accept", "application/json"],
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
          ["Content-Length", "1234"],
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
