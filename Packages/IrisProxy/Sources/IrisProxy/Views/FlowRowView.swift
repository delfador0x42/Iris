//
//  FlowRowView.swift
//  IrisProxy
//
//  Compact flow row — NieR aesthetic. Information-dense, outline style.
//

import SwiftUI

struct FlowRowView: View {
  let flow: ProxyCapturedFlow

  var body: some View {
    HStack(spacing: 0) {
      // Left accent — 2px thin line
      Rectangle()
        .fill(accentColor)
        .frame(width: 2, height: 32)
        .padding(.trailing, 8)

      // Method/protocol
      protocolBadge
        .frame(width: 52, alignment: .leading)

      // Status
      statusView
        .frame(width: 40, alignment: .leading)

      // Host + path
      VStack(alignment: .leading, spacing: 1) {
        Text(flow.host)
          .font(.system(size: 11, weight: .medium, design: .monospaced))
          .foregroundColor(.white.opacity(0.85))
          .lineLimit(1)

        if let request = flow.request {
          Text(request.path)
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.3))
            .lineLimit(1)
        } else {
          Text(":\(flow.port)")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.3))
        }
      }
      .padding(.leading, 6)

      Spacer(minLength: 8)

      // Threat indicator
      if isSuspicious {
        Image(systemName: "exclamationmark.triangle")
          .font(.system(size: 10))
          .foregroundColor(Color(red: 1.0, green: 0.6, blue: 0.2))
          .help(suspiciousReason)
          .padding(.trailing, 6)
      }

      // Process
      if let process = flow.processName {
        Text(process)
          .font(.system(size: 9, weight: .medium, design: .monospaced))
          .foregroundColor(.white.opacity(0.25))
          .lineLimit(1)
          .frame(maxWidth: 80, alignment: .trailing)
          .padding(.trailing, 8)
      }

      // Duration
      if let duration = flow.duration {
        Text(formatDuration(duration))
          .font(.system(size: 10, design: .monospaced))
          .foregroundColor(durationColor(duration))
          .frame(width: 52, alignment: .trailing)
      } else {
        Text("---")
          .font(.system(size: 10, design: .monospaced))
          .foregroundColor(.white.opacity(0.1))
          .frame(width: 52, alignment: .trailing)
      }

      // Size
      sizeLabel
        .frame(width: 56, alignment: .trailing)
    }
    .padding(.vertical, 3)
  }

  // MARK: - Accent

  private var accentColor: Color {
    if flow.error != nil { return Color(red: 1.0, green: 0.35, blue: 0.35) }
    if let r = flow.response {
      if r.statusCode >= 500 { return Color(red: 1.0, green: 0.35, blue: 0.35) }
      if r.statusCode >= 400 { return Color(red: 1.0, green: 0.6, blue: 0.2) }
      if r.statusCode >= 300 { return .cyan }
      return Color(red: 0.3, green: 0.9, blue: 0.5)
    }
    if flow.isComplete { return Color(red: 0.3, green: 0.9, blue: 0.5).opacity(0.4) }
    return Color.white.opacity(0.08)
  }

  private func durationColor(_ duration: TimeInterval) -> Color {
    if duration > 5 { return Color(red: 1.0, green: 0.35, blue: 0.35) }
    if duration > 2 { return Color(red: 1.0, green: 0.6, blue: 0.2) }
    if duration > 1 { return Color(red: 1.0, green: 0.85, blue: 0.3) }
    return .white.opacity(0.35)
  }

  // MARK: - Security

  private var isSuspicious: Bool {
    if flow.requestBodySize > 10_000 {
      let responseSize = Int64(flow.response?.bodySize ?? 0)
      if responseSize > 0 && flow.requestBodySize > responseSize * 5 { return true }
    }
    if let method = flow.request?.method,
       (method == "POST" || method == "PUT"),
       flow.requestBodySize > 1_000_000 { return true }
    return false
  }

  private var suspiciousReason: String {
    if flow.requestBodySize > 1_000_000 {
      return "Large upload: \(ByteCountFormatter.string(fromByteCount: flow.requestBodySize, countStyle: .file))"
    }
    return "Request >> Response (potential exfil)"
  }

  // MARK: - Subviews

  @ViewBuilder
  private var protocolBadge: some View {
    if let request = flow.request {
      MethodBadge(method: request.method)
    } else {
      Text(flow.flowType.rawValue.uppercased())
        .font(.system(size: 10, weight: .bold, design: .monospaced))
        .foregroundColor(flow.flowType == .udp
          ? Color(red: 0.7, green: 0.5, blue: 1.0)
          : Color(red: 0.4, green: 0.8, blue: 0.8))
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Color.white.opacity(0.04))
        .overlay(
          RoundedRectangle(cornerRadius: 3)
            .stroke(Color.white.opacity(0.1), lineWidth: 0.5)
        )
        .cornerRadius(3)
    }
  }

  @ViewBuilder
  private var statusView: some View {
    if let error = flow.error {
      ErrorBadge(message: error)
    } else if let response = flow.response {
      StatusBadge(statusCode: response.statusCode)
    } else if flow.isComplete {
      Text("OK")
        .font(.system(size: 10, weight: .bold, design: .monospaced))
        .foregroundColor(Color(red: 0.3, green: 0.9, blue: 0.5).opacity(0.6))
    } else {
      PendingBadge()
    }
  }

  @ViewBuilder
  private var sizeLabel: some View {
    let bytes = totalBytes
    if bytes > 0 {
      Text(ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file))
        .font(.system(size: 10, design: .monospaced))
        .foregroundColor(.white.opacity(0.3))
    }
  }

  private var totalBytes: Int64 {
    let reqBytes = max(flow.requestBodySize, Int64(flow.request?.bodySize ?? 0))
    let respBytes = Int64(flow.response?.bodySize ?? 0)
    return flow.bytesIn + flow.bytesOut + reqBytes + respBytes
  }

  private func formatDuration(_ duration: TimeInterval) -> String {
    if duration < 1 {
      return String(format: "%.0fms", duration * 1000)
    } else {
      return String(format: "%.2fs", duration)
    }
  }
}
