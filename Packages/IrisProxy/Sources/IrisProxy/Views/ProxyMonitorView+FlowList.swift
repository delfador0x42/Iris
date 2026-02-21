//
//  ProxyMonitorView+FlowList.swift
//  IrisProxy
//
//  Flow list, header, filter bar — NieR aesthetic.
//

import SwiftUI

extension ProxyMonitorView {

  // MARK: - Flow List

  var flowListView: some View {
    VStack(spacing: 0) {
      flowListHeader
      thinDivider
      filterBar
      thinDivider

      if store.filteredFlows.isEmpty {
        emptyListView
      } else {
        List(store.filteredFlows, selection: $store.selectedFlow) { flow in
          FlowRowView(flow: flow)
            .tag(flow)
            .listRowSeparator(.hidden)
            .listRowBackground(Color.clear)
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(Color(red: 0.01, green: 0.02, blue: 0.04))
      }
    }
    .background(Color(red: 0.01, green: 0.02, blue: 0.04))
  }

  private var thinDivider: some View {
    Rectangle()
      .fill(Color.cyan.opacity(0.12))
      .frame(height: 0.5)
  }

  var flowListHeader: some View {
    HStack {
      VStack(alignment: .leading, spacing: 2) {
        Text("NETWORK FLOWS")
          .font(.system(size: 10, weight: .bold, design: .monospaced))
          .foregroundColor(.cyan.opacity(0.7))
        Text("\(store.filteredFlows.count)/\(store.totalFlowCount)")
          .font(.system(size: 9, design: .monospaced))
          .foregroundColor(.white.opacity(0.3))
      }

      Spacer()

      HStack(spacing: 12) {
        StatItem(title: "OK", value: "\(store.statistics.successful)",
                 color: Color(red: 0.3, green: 0.9, blue: 0.5))
        StatItem(title: "ERR", value: "\(store.statistics.failed + store.statistics.errors)",
                 color: Color(red: 1.0, green: 0.35, blue: 0.35))
        StatItem(title: "WAIT", value: "\(store.statistics.pending)",
                 color: Color(red: 1.0, green: 0.6, blue: 0.2))
        StatItem(title: "DATA", value: store.statistics.totalBytesFormatted,
                 color: .cyan)
      }
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 8)
    .background(Color(red: 0.02, green: 0.03, blue: 0.06))
  }

  var filterBar: some View {
    HStack(spacing: 8) {
      // Search field — dark themed
      HStack(spacing: 6) {
        Image(systemName: "magnifyingglass")
          .font(.system(size: 10))
          .foregroundColor(.cyan.opacity(0.4))
        TextField("Filter...", text: $store.searchQuery)
          .textFieldStyle(.plain)
          .font(.system(size: 11, design: .monospaced))
          .foregroundColor(.white.opacity(0.8))
        if !store.searchQuery.isEmpty {
          Button(action: { store.searchQuery = "" }) {
            Image(systemName: "xmark")
              .font(.system(size: 8, weight: .bold))
              .foregroundColor(.white.opacity(0.3))
          }
          .buttonStyle(.plain)
        }
      }
      .padding(.horizontal, 8)
      .padding(.vertical, 5)
      .background(Color.white.opacity(0.04))
      .overlay(
        RoundedRectangle(cornerRadius: 3)
          .stroke(Color.cyan.opacity(0.1), lineWidth: 0.5)
      )
      .cornerRadius(3)

      // Protocol
      Picker("Protocol", selection: $store.protocolFilter) {
        Text("ALL").tag(nil as ProxyFlowType?)
        Divider()
        Text("HTTP").tag(ProxyFlowType.http as ProxyFlowType?)
        Text("HTTPS").tag(ProxyFlowType.https as ProxyFlowType?)
        Text("TCP").tag(ProxyFlowType.tcp as ProxyFlowType?)
        Text("UDP").tag(ProxyFlowType.udp as ProxyFlowType?)
      }
      .pickerStyle(.menu)
      .frame(width: 90)

      // Method
      if !store.availableMethods.isEmpty {
        Picker("Method", selection: $store.methodFilter) {
          Text("ALL").tag(nil as String?)
          Divider()
          ForEach(store.availableMethods, id: \.self) { method in
            Text(method).tag(method as String?)
          }
        }
        .pickerStyle(.menu)
        .frame(width: 80)
      }

      // Status
      Picker("Status", selection: $store.statusFilter) {
        ForEach(StatusFilter.allCases) { filter in
          Text(filter.rawValue).tag(filter)
        }
      }
      .pickerStyle(.menu)
      .frame(width: 80)
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 6)
    .background(Color(red: 0.02, green: 0.03, blue: 0.06))
  }

  var emptyListView: some View {
    VStack(spacing: 12) {
      Image(systemName: "network.slash")
        .font(.system(size: 32, weight: .thin))
        .foregroundColor(.cyan.opacity(0.2))
      Text("NO FLOWS")
        .font(.system(size: 11, weight: .bold, design: .monospaced))
        .foregroundColor(.white.opacity(0.3))
      Text(emptyMessage)
        .font(.system(size: 10, design: .monospaced))
        .foregroundColor(.white.opacity(0.15))
        .multilineTextAlignment(.center)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .background(Color(red: 0.01, green: 0.02, blue: 0.04))
  }

  var emptyMessage: String {
    if !store.searchQuery.isEmpty || store.methodFilter != nil
      || store.statusFilter != .all || store.protocolFilter != nil
    {
      return "No flows match filters"
    } else if !store.isEnabled {
      return "Extension offline"
    } else {
      return "Awaiting traffic..."
    }
  }
}
