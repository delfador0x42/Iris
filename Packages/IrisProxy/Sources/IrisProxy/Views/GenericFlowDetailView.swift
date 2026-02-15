//
//  GenericFlowDetailView.swift
//  IrisProxy
//
//  Detail view for non-HTTP flows (TCP/UDP) showing connection metadata.
//

import SwiftUI

struct GenericFlowDetailView: View {
  let flow: ProxyCapturedFlow

  var body: some View {
    VStack(spacing: 0) {
      header
      Divider()
      ThemedScrollView {
        detailContent
          .padding()
      }
    }
    .background(Color(NSColor.controlBackgroundColor))
  }

  private var header: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack {
        Text(flow.flowType.rawValue.uppercased())
          .font(.system(size: 12, weight: .bold, design: .monospaced))
          .foregroundColor(.white)
          .padding(.horizontal, 8)
          .padding(.vertical, 3)
          .background(flow.flowType == .udp ? Color.purple : Color.teal)
          .cornerRadius(4)

        statusIndicator

        Spacer()
      }

      Text("\(flow.host):\(flow.port)")
        .font(.system(size: 14, weight: .medium, design: .monospaced))
        .textSelection(.enabled)
    }
    .padding()
  }

  @ViewBuilder
  private var statusIndicator: some View {
    if flow.isComplete {
      Image(systemName: "checkmark.circle.fill")
        .foregroundColor(.green)
    } else if flow.error != nil {
      Image(systemName: "exclamationmark.triangle.fill")
        .foregroundColor(.red)
    } else {
      ProgressView()
        .scaleEffect(0.7)
    }
  }

  private var detailContent: some View {
    VStack(alignment: .leading, spacing: 16) {
      connectionSection
      transferSection
      timingSection
      if let error = flow.error {
        errorSection(error)
      }
    }
  }

  private var connectionSection: some View {
    GroupBox("Connection") {
      VStack(alignment: .leading, spacing: 8) {
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
      .padding(.vertical, 4)
    }
  }

  private var transferSection: some View {
    GroupBox("Transfer") {
      VStack(alignment: .leading, spacing: 8) {
        DetailRow(
          label: "Bytes Sent",
          value: ByteCountFormatter.string(fromByteCount: flow.bytesOut, countStyle: .file))
        DetailRow(
          label: "Bytes Received",
          value: ByteCountFormatter.string(fromByteCount: flow.bytesIn, countStyle: .file))
        DetailRow(
          label: "Total",
          value: ByteCountFormatter.string(
            fromByteCount: flow.bytesIn + flow.bytesOut, countStyle: .file))
      }
      .padding(.vertical, 4)
    }
  }

  private var timingSection: some View {
    GroupBox("Timing") {
      VStack(alignment: .leading, spacing: 8) {
        DetailRow(label: "Started", value: formatTime(flow.timestamp))
        if let end = flow.endTimestamp {
          DetailRow(label: "Ended", value: formatTime(end))
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
      .padding(.vertical, 4)
    }
  }

  private func errorSection(_ error: String) -> some View {
    GroupBox("Error") {
      HStack {
        Image(systemName: "exclamationmark.triangle.fill")
          .foregroundColor(.red)
        Text(error)
          .foregroundColor(.red)
          .textSelection(.enabled)
      }
      .padding(.vertical, 4)
    }
  }

  private func formatTime(_ date: Date) -> String {
    let f = DateFormatter()
    f.dateFormat = "HH:mm:ss.SSS"
    return f.string(from: date)
  }
}
