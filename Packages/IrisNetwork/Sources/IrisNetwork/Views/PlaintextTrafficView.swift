//
//  PlaintextTrafficView.swift
//  IrisNetwork
//
//  Shows decrypted HTTP flows from the proxy extension that match a network connection.
//  Bridges the network filter (encrypted) and proxy (decrypted) capture systems.
//

import SwiftUI

/// Modal view showing decrypted HTTP traffic for a network connection.
/// Queries ProxyStore for flows matching the connection's hostname.
struct PlaintextTrafficView: View {
    let connection: NetworkConnection
    var onDismiss: () -> Void = {}

    @State private var matchingFlows: [ProxyCapturedFlow] = []
    @State private var expandedFlowId: UUID?
    @State private var isLoading = true

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().background(Color.gray.opacity(0.3))
            statsBar
            Divider().background(Color.gray.opacity(0.3))
            flowList
        }
        .background(Color(red: 0.04, green: 0.05, blue: 0.08))
        .task { loadMatchingFlows() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Image(systemName: "lock.open")
                        .foregroundColor(.green)
                    Text("Decrypted Traffic")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.white)
                }

                HStack(spacing: 6) {
                    Text(connection.remoteHostname ?? connection.remoteAddress)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.cyan)
                        .textSelection(.enabled)

                    Text(":\(connection.remotePort)")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.gray)

                    Text(connection.processName)
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(0.1))
                        .cornerRadius(3)
                }
            }

            Spacer()

            Button("Close") { onDismiss() }
                .foregroundColor(.blue)
        }
        .padding(16)
    }

    // MARK: - Stats Bar

    private var statsBar: some View {
        HStack(spacing: 16) {
            Label("\(matchingFlows.count) flows", systemImage: "arrow.left.arrow.right")
                .font(.system(size: 11))
                .foregroundColor(.gray)

            if !matchingFlows.isEmpty {
                let totalReqBytes = matchingFlows.reduce(0) { $0 + $1.request.bodySize }
                let totalRespBytes = matchingFlows.reduce(0) { $0 + ($1.response?.bodySize ?? 0) }
                Label(formatBytes(totalReqBytes + totalRespBytes), systemImage: "arrow.up.arrow.down")
                    .font(.system(size: 11))
                    .foregroundColor(.gray)
            }

            Spacer()

            Button {
                loadMatchingFlows()
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain)
            .foregroundColor(.gray)
            .help("Refresh")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.3))
    }

    // MARK: - Flow List

    @ViewBuilder
    private var flowList: some View {
        if isLoading {
            VStack(spacing: 12) {
                ProgressView().tint(.white)
                Text("Looking for decrypted flows...")
                    .font(.system(size: 13))
                    .foregroundColor(.gray)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if matchingFlows.isEmpty {
            emptyState
        } else {
            ThemedScrollView {
                LazyVStack(alignment: .leading, spacing: 1) {
                    ForEach(matchingFlows) { flow in
                        flowRow(flow)
                    }
                }
                .padding(.vertical, 8)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.slash")
                .font(.system(size: 36))
                .foregroundColor(.gray.opacity(0.5))
            Text("No decrypted data available")
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(.gray)
            Text("Ensure the HTTPS proxy extension is running and intercepting this host")
                .font(.system(size: 12))
                .foregroundColor(.gray.opacity(0.7))
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Flow Row

    private func flowRow(_ flow: ProxyCapturedFlow) -> some View {
        let isExpanded = expandedFlowId == flow.id

        return VStack(alignment: .leading, spacing: 0) {
            // Summary row (always visible)
            Button {
                withAnimation(.easeInOut(duration: 0.15)) {
                    expandedFlowId = isExpanded ? nil : flow.id
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9))
                        .foregroundColor(.gray)
                        .frame(width: 12)

                    MethodBadge(method: flow.request.method)

                    if let response = flow.response {
                        StatusBadge(statusCode: response.statusCode)
                    } else if flow.error != nil {
                        ErrorBadge()
                    } else {
                        PendingBadge()
                    }

                    Text(flow.request.path)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.9))
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Spacer()

                    if let duration = flow.duration {
                        Text(formatDuration(duration))
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.gray)
                    }

                    Text(formatTime(flow.timestamp))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.7))
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
            }
            .buttonStyle(.plain)

            // Expanded detail (request + response)
            if isExpanded {
                expandedDetail(flow)
            }
        }
        .background(isExpanded ? Color.white.opacity(0.03) : Color.clear)
    }

    // MARK: - Expanded Detail

    private func expandedDetail(_ flow: ProxyCapturedFlow) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // Request
            GroupBox {
                VStack(alignment: .leading, spacing: 6) {
                    Text("\(flow.request.method) \(flow.request.path) \(flow.request.httpVersion)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.orange)
                        .textSelection(.enabled)

                    if !flow.request.headers.isEmpty {
                        ForEach(Array(flow.request.headers.enumerated()), id: \.offset) { _, header in
                            if header.count >= 2 {
                                HStack(alignment: .top, spacing: 4) {
                                    Text(header[0] + ":")
                                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                        .foregroundColor(.blue.opacity(0.8))
                                    Text(header[1])
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.white.opacity(0.7))
                                        .textSelection(.enabled)
                                }
                            }
                        }
                    }

                    if let body = flow.request.bodyPreview {
                        Divider().background(Color.gray.opacity(0.3))
                        Text(body)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.orange.opacity(0.8))
                            .textSelection(.enabled)
                            .lineLimit(20)
                    }
                }
                .padding(4)
            } label: {
                Label("Request", systemImage: "arrow.up")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(.orange)
            }

            // Response
            if let response = flow.response {
                GroupBox {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("\(response.httpVersion) \(response.statusCode) \(response.reason)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.cyan)
                            .textSelection(.enabled)

                        if !response.headers.isEmpty {
                            ForEach(Array(response.headers.enumerated()), id: \.offset) { _, header in
                                if header.count >= 2 {
                                    HStack(alignment: .top, spacing: 4) {
                                        Text(header[0] + ":")
                                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                            .foregroundColor(.blue.opacity(0.8))
                                        Text(header[1])
                                            .font(.system(size: 10, design: .monospaced))
                                            .foregroundColor(.white.opacity(0.7))
                                            .textSelection(.enabled)
                                    }
                                }
                            }
                        }

                        if let body = response.bodyPreview {
                            Divider().background(Color.gray.opacity(0.3))
                            Text(body)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.cyan.opacity(0.8))
                                .textSelection(.enabled)
                                .lineLimit(30)
                        }
                    }
                    .padding(4)
                } label: {
                    Label("Response (\(formatDuration(response.duration)))", systemImage: "arrow.down")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.cyan)
                }
            } else if let error = flow.error {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                    Text(error)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.red.opacity(0.8))
                }
            }
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
    }

    // MARK: - Data Loading

    private func loadMatchingFlows() {
        isLoading = true

        // Build set of hostnames to match against
        var hostnames = Set<String>()
        if let hostname = connection.remoteHostname {
            hostnames.insert(hostname.lowercased())
        }
        if let resolved = connection.remoteHostnames {
            for h in resolved { hostnames.insert(h.lowercased()) }
        }
        // Also match by raw IP for direct connections
        hostnames.insert(connection.remoteAddress.lowercased())

        // Query ProxyStore for matching flows
        let allFlows = ProxyStore.shared.flows
        matchingFlows = allFlows.filter { flow in
            guard let flowHost = flow.request.host?.lowercased() else { return false }
            return hostnames.contains(flowHost)
        }
        .sorted { $0.timestamp > $1.timestamp }

        isLoading = false
    }

    // MARK: - Formatting

    private func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private func formatDuration(_ duration: TimeInterval) -> String {
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        }
        return String(format: "%.2fs", duration)
    }

    private func formatTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}
