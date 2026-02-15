//
//  ProxyMonitorView+Toolbar.swift
//  IrisProxy
//
//  Toolbar content and empty detail view for ProxyMonitorView.
//

import SwiftUI

extension ProxyMonitorView {

  // MARK: - Empty Detail View

  var emptyDetailView: some View {
    VStack(spacing: 16) {
      Image(systemName: "doc.text.magnifyingglass")
        .font(.system(size: 48))
        .foregroundColor(.secondary)
      Text("Select a Flow")
        .font(.headline)
      Text("Choose a flow from the list\nto view its details.")
        .font(.caption)
        .foregroundColor(.secondary)
        .multilineTextAlignment(.center)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(Color(NSColor.controlBackgroundColor))
  }

  // MARK: - Toolbar

  @ToolbarContentBuilder
  var toolbarContent: some ToolbarContent {
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
