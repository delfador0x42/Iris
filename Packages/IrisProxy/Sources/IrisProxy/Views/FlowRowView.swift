//
//  FlowRowView.swift
//  IrisProxy
//
//  Row view for displaying a single flow (HTTP, TCP, or UDP) in the flow list.
//

import SwiftUI

struct FlowRowView: View {
  let flow: ProxyCapturedFlow

  var body: some View {
    HStack(spacing: 12) {
      // Protocol/method badge
      protocolBadge

      // Status badge or pending/error
      statusView

      // Host and details
      VStack(alignment: .leading, spacing: 2) {
        Text(flow.host)
          .font(.system(size: 12, weight: .medium))
          .lineLimit(1)

        if let request = flow.request {
          Text(request.path)
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(.secondary)
            .lineLimit(1)
        } else {
          Text(":\(flow.port)")
            .font(.system(size: 11, design: .monospaced))
            .foregroundColor(.secondary)
        }
      }

      Spacer()

      // Process name
      if let process = flow.processName {
        Text(process)
          .font(.caption)
          .foregroundColor(.secondary)
          .padding(.horizontal, 6)
          .padding(.vertical, 2)
          .background(Color.secondary.opacity(0.1))
          .cornerRadius(4)
      }

      // Duration
      if let duration = flow.duration {
        Text(formatDuration(duration))
          .font(.system(size: 11, design: .monospaced))
          .foregroundColor(.secondary)
      }

      // Size
      sizeLabel
    }
    .padding(.vertical, 4)
  }

  @ViewBuilder
  private var protocolBadge: some View {
    if let request = flow.request {
      MethodBadge(method: request.method)
    } else {
      Text(flow.flowType.rawValue.uppercased())
        .font(.system(size: 10, weight: .bold, design: .monospaced))
        .foregroundColor(.white)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(flow.flowType == .udp ? Color.purple : Color.teal)
        .cornerRadius(4)
    }
  }

  @ViewBuilder
  private var statusView: some View {
    if let error = flow.error {
      ErrorBadge(message: error)
    } else if let response = flow.response {
      StatusBadge(statusCode: response.statusCode)
    } else if flow.isComplete {
      // Non-HTTP completed flow
      Image(systemName: "checkmark.circle.fill")
        .foregroundColor(.green)
        .font(.system(size: 12))
    } else {
      PendingBadge()
    }
  }

  @ViewBuilder
  private var sizeLabel: some View {
    let bytes = totalBytes
    if bytes > 0 {
      Text(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file))
        .font(.system(size: 11))
        .foregroundColor(.secondary)
    }
  }

  private var totalBytes: Int64 {
    let httpBytes = Int64(flow.request?.bodySize ?? 0) + Int64(flow.response?.bodySize ?? 0)
    return flow.bytesIn + flow.bytesOut + httpBytes
  }

  private func formatDuration(_ duration: TimeInterval) -> String {
    if duration < 1 {
      return String(format: "%.0fms", duration * 1000)
    } else {
      return String(format: "%.2fs", duration)
    }
  }
}
