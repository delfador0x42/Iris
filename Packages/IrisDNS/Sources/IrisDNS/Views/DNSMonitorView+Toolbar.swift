import SwiftUI

extension DNSMonitorView {

    // MARK: - Toolbar

    @ToolbarContentBuilder
    var toolbarContent: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button(action: {
                Task {
                    await store.refreshQueries()
                }
            }) {
                Label("Refresh", systemImage: "arrow.clockwise")
            }
            .disabled(store.isLoading)

            Button(action: {
                showingClearConfirmation = true
            }) {
                Label("Clear", systemImage: "trash")
            }
            .disabled(store.queries.isEmpty)

            Divider()

            // Connection status
            HStack(spacing: 4) {
                Circle()
                    .fill(store.isActive ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
                Text(store.isActive ? "Active" : "Inactive")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}
