//
//  GenericFlowDetailView.swift
//  IrisProxy
//
//  Non-HTTP flow detail (TCP/UDP) — NieR aesthetic.
//

import SwiftUI

private let timeFormatter: DateFormatter = {
  let f = DateFormatter()
  f.dateFormat = "HH:mm:ss.SSS"
  return f
}()

struct GenericFlowDetailView: View {
  let flow: ProxyCapturedFlow

  var body: some View {
    VStack(spacing: 0) {
      header
      thinDivider
      ThemedScrollView {
        detailContent
          .padding(12)
      }
    }
    .background(Color(red: 0.01, green: 0.02, blue: 0.04))
  }

  private var thinDivider: some View {
    Rectangle()
      .fill(Color.cyan.opacity(0.12))
      .frame(height: 0.5)
  }

  private var header: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 8) {
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

        statusIndicator

        Spacer()
      }

      Text("\(flow.host):\(flow.port)")
        .font(.system(size: 12, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(0.7))
        .textSelection(.enabled)
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 10)
    .background(Color(red: 0.02, green: 0.03, blue: 0.06))
  }

  @ViewBuilder
  private var statusIndicator: some View {
    if flow.isComplete {
      Text("OK")
        .font(.system(size: 10, weight: .bold, design: .monospaced))
        .foregroundColor(Color(red: 0.3, green: 0.9, blue: 0.5).opacity(0.6))
    } else if flow.error != nil {
      Text("ERR")
        .font(.system(size: 10, weight: .bold, design: .monospaced))
        .foregroundColor(Color(red: 1.0, green: 0.35, blue: 0.35))
    } else {
      ProgressView().scaleEffect(0.5)
    }
  }

  private var detailContent: some View {
    VStack(alignment: .leading, spacing: 10) {
      panel("Connection") {
        VStack(alignment: .leading, spacing: 6) {
          DetailRow(label: "Protocol", value: flow.flowType.rawValue.uppercased())
          DetailRow(label: "Host", value: flow.host)
          DetailRow(label: "Port", value: "\(flow.port)")
          if let process = flow.processName {
            DetailRow(label: "Process", value: process)
          }
          if let pid = flow.processId {
            DetailRow(label: "PID", value: "\(pid)")
          }
        }
      }

      panel("Transfer") {
        VStack(alignment: .leading, spacing: 6) {
          DetailRow(
            label: "Sent",
            value: ByteCountFormatter.string(fromByteCount: flow.bytesOut, countStyle: .file))
          DetailRow(
            label: "Received",
            value: ByteCountFormatter.string(fromByteCount: flow.bytesIn, countStyle: .file))
          DetailRow(
            label: "Total",
            value: ByteCountFormatter.string(
              fromByteCount: flow.bytesIn + flow.bytesOut, countStyle: .file))
        }
      }

      panel("Timing") {
        VStack(alignment: .leading, spacing: 6) {
          DetailRow(label: "Started", value: timeFormatter.string(from: flow.timestamp))
          if let end = flow.endTimestamp {
            DetailRow(label: "Ended", value: timeFormatter.string(from: end))
          }
          if let duration = flow.duration {
            DetailRow(
              label: "Duration",
              value: duration < 1
                ? String(format: "%.0fms", duration * 1000)
                : String(format: "%.2fs", duration))
          }
          DetailRow(
            label: "Status",
            value: flow.isComplete ? "Complete" : (flow.error != nil ? "Error" : "Active"))
        }
      }

      if let error = flow.error {
        panel("Error") {
          HStack(spacing: 8) {
            Text("ERR")
              .font(.system(size: 10, weight: .bold, design: .monospaced))
              .foregroundColor(Color(red: 1.0, green: 0.35, blue: 0.35))
            Text(error)
              .font(.system(size: 10, design: .monospaced))
              .foregroundColor(.white.opacity(0.4))
              .textSelection(.enabled)
          }
        }
      }
    }
  }

  /// Dark panel with thin cyan border.
  private func panel<Content: View>(
    _ title: String, @ViewBuilder content: () -> Content
  ) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      Text(title.uppercased())
        .font(.system(size: 9, weight: .bold, design: .monospaced))
        .foregroundColor(.cyan.opacity(0.5))
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(Color.cyan.opacity(0.04))
        .frame(maxWidth: .infinity, alignment: .leading)

      Rectangle()
        .fill(Color.cyan.opacity(0.1))
        .frame(height: 0.5)

      content()
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
    }
    .background(Color.white.opacity(0.02))
    .overlay(
      RoundedRectangle(cornerRadius: 3)
        .stroke(Color.cyan.opacity(0.08), lineWidth: 0.5)
    )
    .cornerRadius(3)
  }
}
