//
//  ProxyMonitorView.swift
//  IrisProxy
//
//  Main view for monitoring HTTP flows captured by the proxy.
//

import SwiftUI

/// Main view for the HTTP proxy monitor.
public struct ProxyMonitorView: View {
    @StateObject private var store = ProxyStore.shared
    @State private var showingClearConfirmation = false

    public init() {}

    public var body: some View {
        HSplitView {
            // Left: Flow list
            flowListView
                .frame(minWidth: 400)

            // Right: Flow detail (if selected)
            if let flow = store.selectedFlow {
                HTTPFlowDetailView(flow: flow)
                    .frame(minWidth: 350)
            } else {
                emptyDetailView
                    .frame(minWidth: 350)
            }
        }
        .toolbar {
            toolbarContent
        }
        .onAppear {
            store.connect()
        }
        .alert("Clear All Flows?", isPresented: $showingClearConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Clear", role: .destructive) {
                Task {
                    await store.clearFlows()
                }
            }
        } message: {
            Text("This will remove all \(store.totalFlowCount) captured flows. This action cannot be undone.")
        }
    }

    // MARK: - Flow List

    private var flowListView: some View {
        VStack(spacing: 0) {
            // Header with stats
            flowListHeader

            Divider()

            // Filter bar
            filterBar

            Divider()

            // Flow list
            if store.filteredFlows.isEmpty {
                emptyListView
            } else {
                List(store.filteredFlows, selection: $store.selectedFlow) { flow in
                    FlowRowView(flow: flow)
                        .tag(flow)
                }
                .listStyle(.plain)
            }
        }
    }

    private var flowListHeader: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("HTTP Flows")
                    .font(.headline)
                Text("\(store.filteredFlows.count) of \(store.totalFlowCount) flows")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            // Statistics
            HStack(spacing: 16) {
                StatItem(
                    title: "Success",
                    value: "\(store.statistics.successful)",
                    color: .green
                )
                StatItem(
                    title: "Errors",
                    value: "\(store.statistics.failed + store.statistics.errors)",
                    color: .red
                )
                StatItem(
                    title: "Pending",
                    value: "\(store.statistics.pending)",
                    color: .orange
                )
                StatItem(
                    title: "Total",
                    value: store.statistics.totalBytesFormatted,
                    color: .blue
                )
            }
        }
        .padding()
    }

    private var filterBar: some View {
        HStack(spacing: 12) {
            // Search field
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search flows...", text: $store.searchQuery)
                    .textFieldStyle(.plain)
                if !store.searchQuery.isEmpty {
                    Button(action: { store.searchQuery = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)

            // Method filter
            if !store.availableMethods.isEmpty {
                Picker("Method", selection: $store.methodFilter) {
                    Text("All Methods").tag(nil as String?)
                    Divider()
                    ForEach(store.availableMethods, id: \.self) { method in
                        Text(method).tag(method as String?)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 120)
            }

            // Status filter
            Picker("Status", selection: $store.statusFilter) {
                ForEach(StatusFilter.allCases) { filter in
                    Text(filter.rawValue).tag(filter)
                }
            }
            .pickerStyle(.menu)
            .frame(width: 100)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    private var emptyListView: some View {
        VStack(spacing: 16) {
            Image(systemName: "network.slash")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("No Flows Captured")
                .font(.headline)
            Text(emptyMessage)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var emptyMessage: String {
        if !store.searchQuery.isEmpty || store.methodFilter != nil || store.statusFilter != .all {
            return "No flows match your filters.\nTry adjusting your search criteria."
        } else if !store.isEnabled {
            return "Proxy extension is not enabled.\nEnable it in Settings to start capturing traffic."
        } else {
            return "Waiting for HTTP traffic...\nBrowse the web to see captured requests."
        }
    }

    // MARK: - Empty Detail View

    private var emptyDetailView: some View {
        VStack(spacing: 16) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("Select a Flow")
                .font(.headline)
            Text("Choose a request from the list\nto view its details.")
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
    }

    // MARK: - Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            // Refresh button
            Button(action: {
                Task {
                    await store.refreshFlows()
                }
            }) {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(store.isLoading)

            // Clear button
            Button(action: {
                showingClearConfirmation = true
            }) {
                Label("Clear", systemImage: "trash")
            }
            .disabled(store.flows.isEmpty)

            Divider()

            // Connection status indicator
            HStack(spacing: 4) {
                Circle()
                    .fill(store.isEnabled ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(store.isEnabled ? "Connected" : "Disconnected")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Flow Row View

struct FlowRowView: View {
    let flow: ProxyCapturedFlow

    var body: some View {
        HStack(spacing: 12) {
            // Method badge
            MethodBadge(method: flow.request.method)

            // Status badge or pending/error
            statusView

            // URL and details
            VStack(alignment: .leading, spacing: 2) {
                Text(flow.request.host ?? "unknown")
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)

                Text(flow.request.path)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
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
            let size = flow.request.bodySize + (flow.response?.bodySize ?? 0)
            if size > 0 {
                Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var statusView: some View {
        if let error = flow.error {
            ErrorBadge(message: error)
        } else if let response = flow.response {
            StatusBadge(statusCode: response.statusCode)
        } else {
            PendingBadge()
        }
    }

    private func formatDuration(_ duration: TimeInterval) -> String {
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        } else {
            return String(format: "%.2fs", duration)
        }
    }
}

// MARK: - Stat Item

struct StatItem: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                .foregroundColor(color)
            Text(title)
                .font(.system(size: 10))
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Preview

#Preview {
    ProxyMonitorView()
        .frame(width: 1000, height: 600)
}
