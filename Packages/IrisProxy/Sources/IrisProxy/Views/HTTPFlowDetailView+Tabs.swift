//
//  HTTPFlowDetailView+Tabs.swift
//  IrisProxy
//
//  Tab content — NieR aesthetic. Dark panels, thin cyan borders, monospaced.
//

import SwiftUI

extension HTTPFlowDetailView {

  // MARK: - Section Box (replaces GroupBox)

  /// Dark panel with thin cyan border and monospaced label.
  func sectionBox<Content: View>(
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

  // MARK: - Overview Tab

  var overviewTab: some View {
    VStack(alignment: .leading, spacing: 10) {
      if hasSecurityConcern {
        securityAssessment
      }

      sectionBox("Request") {
        VStack(alignment: .leading, spacing: 6) {
          DetailRow(label: "Method", value: request.method)
          DetailRow(label: "URL", value: request.url)
          DetailRow(label: "HTTP", value: request.httpVersion)
          if flow.requestBodySize > 0 {
            DetailRow(
              label: "Body",
              value: ByteCountFormatter.string(fromByteCount: flow.requestBodySize, countStyle: .file)
            )
          } else if request.bodySize > 0 {
            DetailRow(label: "Body", value: formatBytes(request.bodySize))
          }
          if let host = request.host {
            DetailRow(label: "Host", value: host)
          }
          if let te = request.headers.first(where: { $0.first?.lowercased() == "transfer-encoding" })?.last {
            DetailRow(label: "Transfer", value: te)
          }
        }
      }

      if let response = flow.response {
        sectionBox("Response") {
          VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
              Text("Status")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.3))
                .frame(width: 80, alignment: .leading)
              StatusBadge(statusCode: response.statusCode)
              Text(response.reason)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.3))
            }
            DetailRow(label: "HTTP", value: response.httpVersion)
            DetailRow(label: "Body", value: formatBytes(response.bodySize))
            if let contentType = response.contentType {
              DetailRow(label: "Type", value: contentType)
            }
            DetailRow(label: "Duration", value: formatDuration(response.duration))
          }
        }
      } else if let error = flow.error {
        sectionBox("Error") {
          HStack(spacing: 8) {
            Text("ERR")
              .font(.system(size: 10, weight: .bold, design: .monospaced))
              .foregroundColor(Color(red: 1.0, green: 0.35, blue: 0.35))
            Text(error)
              .font(.system(size: 10, design: .monospaced))
              .foregroundColor(.white.opacity(0.4))
          }
        }
      } else {
        sectionBox("Response") {
          HStack(spacing: 8) {
            ProgressView().scaleEffect(0.6)
            Text("Awaiting response...")
              .font(.system(size: 10, design: .monospaced))
              .foregroundColor(.white.opacity(0.2))
          }
        }
      }

      // Transfer
      if flow.requestBodySize > 0 || flow.bytesIn > 0 || flow.bytesOut > 0 {
        sectionBox("Transfer") {
          VStack(alignment: .leading, spacing: 6) {
            if flow.bytesOut > 0 {
              DetailRow(
                label: "Sent",
                value: ByteCountFormatter.string(fromByteCount: flow.bytesOut, countStyle: .file))
            }
            if flow.bytesIn > 0 {
              DetailRow(
                label: "Received",
                value: ByteCountFormatter.string(fromByteCount: flow.bytesIn, countStyle: .file))
            }
            if flow.requestBodySize > 0 && flow.response != nil {
              let ratio = flow.response!.bodySize > 0
                ? Double(flow.requestBodySize) / Double(flow.response!.bodySize)
                : 0
              if ratio > 1 {
                DetailRow(label: "Up/Down", value: String(format: "%.1fx", ratio))
              }
            }
          }
        }
      }

      // Process
      if flow.processName != nil || flow.processId != nil {
        sectionBox("Process") {
          VStack(alignment: .leading, spacing: 6) {
            if let name = flow.processName {
              DetailRow(label: "Name", value: name)
            }
            if let pid = flow.processId {
              DetailRow(label: "PID", value: "\(pid)")
            }
          }
        }
      }
    }
  }

  // MARK: - Security Assessment

  private var hasSecurityConcern: Bool {
    if flow.requestBodySize > 10_000,
       let resp = flow.response,
       resp.bodySize > 0,
       flow.requestBodySize > Int64(resp.bodySize) * 5 { return true }
    if let method = request.method.uppercased() as String?,
       (method == "POST" || method == "PUT"),
       flow.requestBodySize > 1_000_000 { return true }
    return false
  }

  @ViewBuilder
  private var securityAssessment: some View {
    HStack(spacing: 10) {
      Image(systemName: "exclamationmark.triangle")
        .font(.system(size: 16, weight: .light))
        .foregroundColor(Color(red: 1.0, green: 0.6, blue: 0.2))
      VStack(alignment: .leading, spacing: 3) {
        Text("THREAT INDICATOR")
          .font(.system(size: 9, weight: .bold, design: .monospaced))
          .foregroundColor(Color(red: 1.0, green: 0.6, blue: 0.2))
        if flow.requestBodySize > 1_000_000 {
          Text("Large upload: \(ByteCountFormatter.string(fromByteCount: flow.requestBodySize, countStyle: .file)) via \(request.method)")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.35))
        } else {
          Text("Request \(flow.requestBodySize / max(1, Int64(flow.response?.bodySize ?? 1)))x larger than response — possible exfiltration")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.35))
        }
      }
    }
    .padding(10)
    .background(Color(red: 1.0, green: 0.6, blue: 0.2).opacity(0.05))
    .overlay(
      RoundedRectangle(cornerRadius: 3)
        .stroke(Color(red: 1.0, green: 0.6, blue: 0.2).opacity(0.2), lineWidth: 0.5)
    )
    .cornerRadius(3)
  }

  // MARK: - Request Tab

  var requestTab: some View {
    VStack(alignment: .leading, spacing: 10) {
      sectionBox("Request Line") {
        Text("\(request.method) \(request.path) \(request.httpVersion)")
          .font(.system(size: 11, design: .monospaced))
          .foregroundColor(.white.opacity(0.7))
          .textSelection(.enabled)
      }

      sectionBox("Headers") {
        headersView(request.headers)
      }

      if let preview = request.bodyPreview {
        sectionBox("Body (\(formatBytes(request.bodySize)))") {
          bodyPreviewView(preview)
        }
      } else if request.bodySize > 0 {
        sectionBox("Body") {
          Text("\(formatBytes(request.bodySize)) — no preview")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.2))
        }
      }
    }
  }

  // MARK: - Response Tab

  var responseTab: some View {
    VStack(alignment: .leading, spacing: 10) {
      if let response = flow.response {
        sectionBox("Status Line") {
          HStack {
            Text("\(response.httpVersion) \(response.statusCode) \(response.reason)")
              .font(.system(size: 11, design: .monospaced))
              .foregroundColor(.white.opacity(0.7))
              .textSelection(.enabled)
            Spacer()
            StatusBadge(statusCode: response.statusCode)
          }
        }

        sectionBox("Headers") {
          headersView(response.headers)
        }

        if let preview = response.bodyPreview {
          sectionBox("Body (\(formatBytes(response.bodySize)))") {
            bodyPreviewView(preview)
          }
        } else if response.bodySize > 0 {
          sectionBox("Body") {
            Text("\(formatBytes(response.bodySize)) — no preview")
              .font(.system(size: 10, design: .monospaced))
              .foregroundColor(.white.opacity(0.2))
          }
        }
      } else if let error = flow.error {
        sectionBox("Error") {
          VStack(alignment: .leading, spacing: 6) {
            Text("FAILED")
              .font(.system(size: 10, weight: .bold, design: .monospaced))
              .foregroundColor(Color(red: 1.0, green: 0.35, blue: 0.35))
            Text(error)
              .font(.system(size: 10, design: .monospaced))
              .foregroundColor(.white.opacity(0.4))
              .textSelection(.enabled)
          }
        }
      } else {
        VStack(spacing: 12) {
          ProgressView().scaleEffect(0.7)
          Text("Awaiting response...")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.2))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
      }
    }
  }

  // MARK: - Headers Tab

  var headersTab: some View {
    VStack(alignment: .leading, spacing: 10) {
      sectionBox("Request Headers (\(request.headers.count))") {
        headersView(request.headers)
      }

      if let response = flow.response {
        sectionBox("Response Headers (\(response.headers.count))") {
          headersView(response.headers)
        }
      }
    }
  }
}
