//
//  ProxyMonitorView+FlowList.swift
//  IrisProxy
//
//  Flow list, header, filter bar, and empty state for ProxyMonitorView.
//

import SwiftUI

extension ProxyMonitorView {

  // MARK: - Flow List

  var flowListView: some View {
    VStack(spacing: 0) {
      flowListHeader
      Divider()
      filterBar
      Divider()

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

  var flowListHeader: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text("Network Flows")
          .font(.headline)
        Text("\(store.filteredFlows.count) of \(store.totalFlowCount) flows")
          .font(.caption)
          .foregroundColor(.secondary)
      }

      Spacer()

      HStack(spacing: 16) {
        StatItem(title: "Success", value: "\(store.statistics.successful)", color: .green)
        StatItem(
          title: "Errors", value: "\(store.statistics.failed + store.statistics.errors)",
          color: .red)
        StatItem(title: "Pending", value: "\(store.statistics.pending)", color: .orange)
        StatItem(title: "Total", value: store.statistics.totalBytesFormatted, color: .blue)
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

      // Protocol filter
      Picker("Protocol", selection: $store.protocolFilter) {
        Text("All Protocols").tag(nil as ProxyFlowType?)
        Divider()
        Text("HTTP").tag(ProxyFlowType.http as ProxyFlowType?)
        Text("HTTPS").tag(ProxyFlowType.https as ProxyFlowType?)
        Text("TCP").tag(ProxyFlowType.tcp as ProxyFlowType?)
        Text("UDP").tag(ProxyFlowType.udp as ProxyFlowType?)
      }
      .pickerStyle(.menu)
      .frame(width: 130)

      // Method filter (HTTP flows only)
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

  var emptyListView: some View {
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

  var emptyMessage: String {
    if !store.searchQuery.isEmpty || store.methodFilter != nil
      || store.statusFilter != .all || store.protocolFilter != nil
    {
      return "No flows match your filters.\nTry adjusting your search criteria."
    } else if !store.isEnabled {
      return "Proxy extension is not enabled.\nEnable it in Settings to start capturing traffic."
    } else {
      return "Waiting for network traffic...\nAll TCP and UDP flows will appear here."
    }
  }
}
