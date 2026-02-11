import SwiftUI

extension DNSTabView {

    var queryListPane: some View {
        VStack(spacing: 0) {
            queryListHeader
            Divider()
            filterBar
            Divider()

            if store.filteredQueries.isEmpty {
                emptyQueryView
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
                    .foregroundColor(.white)
                Text("\(store.filteredQueries.count) of \(store.totalQueries) queries")
                    .font(.caption)
                    .foregroundColor(.gray)
            }

            Spacer()

            // Inline actions (no toolbar in tab context)
            HStack(spacing: 8) {
                Button {
                    Task { await store.refreshQueries() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 12))
                }
                .buttonStyle(.plain)
                .foregroundColor(.gray)
                .disabled(store.isLoading)

                Button {
                    showingClearConfirmation = true
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 12))
                }
                .buttonStyle(.plain)
                .foregroundColor(.gray)
                .disabled(store.queries.isEmpty)
            }

            Spacer().frame(width: 12)

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

            Toggle("Blocked", isOn: $store.showBlockedOnly)
                .toggleStyle(.switch)
                .controlSize(.small)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
    }

    var emptyQueryView: some View {
        VStack(spacing: 16) {
            Image(systemName: "network.slash")
                .font(.system(size: 48))
                .foregroundColor(.gray)
            Text("No DNS Queries")
                .font(.headline)
                .foregroundColor(.white)
            Text(emptyMessage)
                .font(.caption)
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
