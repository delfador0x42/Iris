import SwiftUI

extension DNSMonitorView {

    // MARK: - Query List

    var queryListView: some View {
        VStack(spacing: 0) {
            queryListHeader

            Divider()

            filterBar

            Divider()

            if store.filteredQueries.isEmpty {
                emptyListView
            } else {
                List(store.filteredQueries, selection: $store.selectedQuery) { query in
                    DNSQueryRowView(query: query)
                        .tag(query)
                }
                .listStyle(.plain)
            }
        }
    }

    var queryListHeader: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("DNS Queries")
                    .font(.headline)
                Text("\(store.filteredQueries.count) of \(store.totalQueries) queries")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            HStack(spacing: 16) {
                DNSStatItem(
                    title: "Latency",
                    value: String(format: "%.0fms", store.averageLatencyMs),
                    color: store.averageLatencyMs < 50 ? .green : (store.averageLatencyMs < 100 ? .orange : .red)
                )
                DNSStatItem(
                    title: "Success",
                    value: String(format: "%.0f%%", store.successRate * 100),
                    color: store.successRate > 0.95 ? .green : .orange
                )
                DNSStatItem(
                    title: "Server",
                    value: store.serverName,
                    color: .blue
                )
            }
        }
        .padding()
    }

    var filterBar: some View {
        HStack(spacing: 12) {
            // Search field
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)
                TextField("Search domains...", text: $store.searchQuery)
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

            // Record type filter
            if !store.availableTypes.isEmpty {
                Picker("Type", selection: $store.typeFilter) {
                    Text("All Types").tag(nil as String?)
                    Divider()
                    ForEach(store.availableTypes, id: \.self) { type in
                        Text(type).tag(type as String?)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 100)
            }

            // Blocked filter
            Toggle("Blocked", isOn: $store.showBlockedOnly)
                .toggleStyle(.switch)
                .controlSize(.small)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    var emptyListView: some View {
        VStack(spacing: 16) {
            Image(systemName: "network.slash")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("No DNS Queries")
                .font(.headline)
            Text(emptyMessage)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    var emptyMessage: String {
        if !store.searchQuery.isEmpty || store.typeFilter != nil || store.showBlockedOnly {
            return "No queries match your filters.\nTry adjusting your search criteria."
        } else if !store.isActive {
            return "DNS proxy extension is not active.\nEnable encrypted DNS to start monitoring."
        } else {
            return "Waiting for DNS queries...\nBrowse the web to see DNS resolutions."
        }
    }
}
