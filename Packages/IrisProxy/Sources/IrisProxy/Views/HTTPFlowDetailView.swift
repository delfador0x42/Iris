//
//  HTTPFlowDetailView.swift
//  IrisProxy
//
//  Detail view for a single HTTP flow showing request and response.
//

import SwiftUI

// MARK: - Detail Tab

enum DetailTab: String, CaseIterable, Identifiable {
  case overview = "Overview"
  case request = "Request"
  case response = "Response"
  case headers = "Headers"

  var id: String { rawValue }
}

/// Detail view for displaying an HTTP flow's request and response.
public struct HTTPFlowDetailView: View {
  let flow: ProxyCapturedFlow
  @State private var selectedTab: DetailTab = .overview

  /// Non-optional request — only show this view when flow.request != nil.
  var request: ProxyCapturedRequest { flow.request! }

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
      ThemedScrollView {
        tabContent
          .padding()
      }
    }
    .background(Color(NSColor.controlBackgroundColor))
  }

  // MARK: - Header

  var detailHeader: some View {
    VStack(alignment: .leading, spacing: 8) {
      // Method and URL
      HStack {
        MethodBadge(method: request.method)

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
      Text(request.url)
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

        let totalSize = request.bodySize + (flow.response?.bodySize ?? 0)
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
  var tabContent: some View {
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
}
