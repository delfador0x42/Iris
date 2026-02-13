import SwiftUI

extension DNSMonitorView {

    // MARK: - Stats Overview

    var statsView: some View {
        ThemedScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // DoH status card
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Image(systemName: "lock.shield.fill")
                                .font(.title2)
                                .foregroundColor(store.isEnabled ? .green : .secondary)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Encrypted DNS")
                                    .font(.headline)
                                Text(store.isEnabled ? "Active - \(store.serverName)" : "Disabled")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            Toggle("", isOn: Binding(
                                get: { store.isEnabled },
                                set: { newValue in
                                    Task { await store.setEnabled(newValue) }
                                }
                            ))
                            .toggleStyle(.switch)
                        }

                        Divider()

                        HStack(spacing: 24) {
                            VStack(spacing: 4) {
                                Text("\(store.totalQueries)")
                                    .font(.system(size: 24, weight: .bold, design: .monospaced))
                                    .foregroundColor(.blue)
                                Text("Total Queries")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            VStack(spacing: 4) {
                                Text(String(format: "%.1fms", store.averageLatencyMs))
                                    .font(.system(size: 24, weight: .bold, design: .monospaced))
                                    .foregroundColor(store.averageLatencyMs < 50 ? .green : .orange)
                                Text("Avg Latency")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            VStack(spacing: 4) {
                                Text(String(format: "%.1f%%", store.successRate * 100))
                                    .font(.system(size: 24, weight: .bold, design: .monospaced))
                                    .foregroundColor(store.successRate > 0.95 ? .green : .orange)
                                Text("Success Rate")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .padding(.vertical, 4)
                }

                // Top domains
                if !store.topDomains.isEmpty {
                    GroupBox("Top Domains") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(store.topDomains.enumerated()), id: \.offset) { index, entry in
                                HStack {
                                    Text("\(index + 1).")
                                        .font(.system(size: 11, design: .monospaced))
                                        .foregroundColor(.secondary)
                                        .frame(width: 20, alignment: .trailing)
                                    Text(entry.domain)
                                        .font(.system(size: 12, design: .monospaced))
                                        .lineLimit(1)
                                    Spacer()
                                    Text("\(entry.count)")
                                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                        .foregroundColor(.blue)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }

                // Record type breakdown
                if !store.availableTypes.isEmpty {
                    GroupBox("Record Types") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(store.availableTypes, id: \.self) { type in
                                let count = store.queries.filter { $0.recordType == type }.count
                                HStack {
                                    RecordTypeBadge(type: type)
                                    Spacer()
                                    Text("\(count)")
                                        .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                        .foregroundColor(.secondary)
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }

                // Server info
                GroupBox("DoH Server") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Server")
                                .foregroundColor(.secondary)
                                .frame(width: 80, alignment: .leading)
                            Text(store.serverName)
                                .font(.system(size: 12, design: .monospaced))
                        }
                        Button("Change Server...") {
                            showingServerPicker = true
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
            .padding()
        }
        .background(Color(NSColor.controlBackgroundColor))
    }
}
