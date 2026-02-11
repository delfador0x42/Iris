import SwiftUI
import AppKit

/// Full detail view showing raw captured data for a network connection.
/// Fetches raw bytes on-demand from the extension via XPC.
struct HTTPRawDetailView: View {
    let connection: NetworkConnection
    @EnvironmentObject private var store: SecurityStore
    @Environment(\.dismiss) private var dismiss
    @State private var selectedTab = 0
    @State var rawOutbound: Data?
    @State var rawInbound: Data?
    @State private var isLoading = true
    @State private var outboundDisplayLimit = 1_048_576  // 1MB initial
    @State private var inboundDisplayLimit = 1_048_576

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            tabPicker
            content
            Divider()
            footer
        }
        .frame(width: 750, height: 550)
        .background(Color(nsColor: .windowBackgroundColor))
        .task { await loadRawData() }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    if let method = connection.httpMethod {
                        HTTPMethodBadge(method: method)
                    }
                    Text(connection.httpHost ?? connection.remoteAddress)
                        .font(.headline)
                }
                if let path = connection.httpPath {
                    Text(path)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            if let statusCode = connection.httpStatusCode {
                HStack(spacing: 8) {
                    HTTPStatusBadge(statusCode: statusCode)
                    if let reason = connection.httpStatusReason {
                        Text(reason)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding()
    }

    // MARK: - Tabs

    private var tabPicker: some View {
        Picker("", selection: $selectedTab) {
            Text(outboundTabLabel).tag(0)
            Text(inboundTabLabel).tag(1)
            Text("Headers").tag(2)
        }
        .pickerStyle(.segmented)
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    private var outboundTabLabel: String {
        if let data = rawOutbound, !data.isEmpty {
            return "Request (\(ByteFormatter.format(UInt64(data.count), style: .abbreviated)))"
        }
        return "Request"
    }

    private var inboundTabLabel: String {
        if let data = rawInbound, !data.isEmpty {
            return "Response (\(ByteFormatter.format(UInt64(data.count), style: .abbreviated)))"
        }
        return "Response"
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if isLoading {
            loadingView
        } else {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    switch selectedTab {
                    case 0: rawDataView(data: rawOutbound, label: "outbound", limit: $outboundDisplayLimit)
                    case 1: rawDataView(data: rawInbound, label: "inbound", limit: $inboundDisplayLimit)
                    default: headersView
                    }
                }
                .padding()
            }
        }
    }

    private var loadingView: some View {
        VStack(spacing: 12) {
            ProgressView()
                .controlSize(.large)
            Text("Fetching captured data...")
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Raw Data Tab

    @ViewBuilder
    private func rawDataView(data: Data?, label: String, limit: Binding<Int>) -> some View {
        if let data, !data.isEmpty {
            let displayData = data.prefix(limit.wrappedValue)
            let text = String(data: displayData, encoding: .utf8)

            if let text, Self.isPrintable(text) {
                // UTF-8 text display
                Text(text)
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                    .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
                    .cornerRadius(8)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.gray.opacity(0.2), lineWidth: 1)
                    )
            } else {
                // Binary / non-printable: hex dump
                hexDumpView(data: displayData)
            }

            // "Load more" if truncated
            if data.count > limit.wrappedValue {
                let remaining = data.count - limit.wrappedValue
                Button {
                    limit.wrappedValue += 1_048_576  // Load 1MB more
                } label: {
                    let remainingStr = ByteFormatter.format(UInt64(remaining), style: .full)
                    Text("Load more (\(remainingStr) remaining)")
                }
                .buttonStyle(.bordered)
                .padding(.top, 8)
                .frame(maxWidth: .infinity, alignment: .center)
            }
        } else {
            noDataView(message: "No \(label) data captured")
        }
    }

    // MARK: - Hex Dump

    private func hexDumpView(data: Data.SubSequence) -> some View {
        let lines = Self.hexDumpLines(data)
        return VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.gray.opacity(0.2), lineWidth: 1)
        )
    }

    // MARK: - Headers Tab (existing parsed data)

    private var headersView: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let rawRequest = connection.httpRawRequest {
                SectionHeader(title: "Request Headers", icon: "arrow.up.doc")
                RawTextView(text: rawRequest)
            }
            if let rawResponse = connection.httpRawResponse {
                SectionHeader(title: "Response Headers", icon: "arrow.down.doc")
                RawTextView(text: rawResponse)
            }
            if connection.httpRawRequest == nil && connection.httpRawResponse == nil {
                noDataView(message: "No HTTP headers captured")
            }
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            Button {
                copyToClipboard()
            } label: {
                Label("Copy All", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)

            Spacer()

            Button("Close") {
                dismiss()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    // MARK: - Helpers

    private func loadRawData() async {
        let (outbound, inbound) = await store.fetchRawData(for: connection.id)
        rawOutbound = outbound
        rawInbound = inbound
        isLoading = false
    }

    private func noDataView(message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 32))
                .foregroundColor(.secondary)
            Text(message)
                .font(.subheadline)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity, minHeight: 200)
    }

}
