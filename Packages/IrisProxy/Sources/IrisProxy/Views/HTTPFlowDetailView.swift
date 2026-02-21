//
//  HTTPFlowDetailView.swift
//  IrisProxy
//
//  Flow detail view — NieR aesthetic. Dark, monospaced, outline accents.
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

  var request: ProxyCapturedRequest { flow.request! }

  public init(flow: ProxyCapturedFlow) {
    self.flow = flow
  }

  public var body: some View {
    VStack(spacing: 0) {
      detailHeader
      thinDivider

      // Tab picker — segmented, tight
      Picker("Tab", selection: $selectedTab) {
        ForEach(DetailTab.allCases) { tab in
          Text(tab.rawValue.uppercased()).tag(tab)
        }
      }
      .pickerStyle(.segmented)
      .padding(.horizontal, 12)
      .padding(.vertical, 8)

      thinDivider

      ThemedScrollView {
        tabContent
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

  // MARK: - Header

  var detailHeader: some View {
    VStack(alignment: .leading, spacing: 6) {
      // Method + Status + Copy
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

        Button(action: copyURL) {
          Image(systemName: "doc.on.doc")
            .font(.system(size: 11))
            .foregroundColor(.cyan.opacity(0.4))
        }
        .buttonStyle(.borderless)
        .help("Copy URL")
      }

      // URL
      Text(request.url)
        .font(.system(size: 11, design: .monospaced))
        .foregroundColor(.white.opacity(0.5))
        .lineLimit(2)
        .textSelection(.enabled)

      // Metadata row
      HStack(spacing: 12) {
        if let process = flow.processName {
          Label(process, systemImage: "app")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.white.opacity(0.25))
        }

        Label(formatTimestamp(flow.timestamp), systemImage: "clock")
          .font(.system(size: 9, design: .monospaced))
          .foregroundColor(.white.opacity(0.25))

        if let duration = flow.duration {
          Label(formatDuration(duration), systemImage: "stopwatch")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.white.opacity(0.25))
        }

        let totalSize = request.bodySize + (flow.response?.bodySize ?? 0)
        if totalSize > 0 {
          Label(formatBytes(totalSize), systemImage: "arrow.up.arrow.down")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.white.opacity(0.25))
        }
      }
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 10)
    .background(Color(red: 0.02, green: 0.03, blue: 0.06))
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
