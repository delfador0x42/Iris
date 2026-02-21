//
//  ProxyMonitorView+Toolbar.swift
//  IrisProxy
//
//  Toolbar and empty detail view — NieR aesthetic.
//

import SwiftUI

extension ProxyMonitorView {

  // MARK: - Empty Detail View

  var emptyDetailView: some View {
    ZStack {
      Color(red: 0.01, green: 0.02, blue: 0.04)

      // Subtle grid
      Canvas { context, size in
        let gs: CGFloat = 40
        var path = Path()
        stride(from: CGFloat(0), to: size.width, by: gs).forEach { x in
          path.move(to: CGPoint(x: x, y: 0))
          path.addLine(to: CGPoint(x: x, y: size.height))
        }
        stride(from: CGFloat(0), to: size.height, by: gs).forEach { y in
          path.move(to: CGPoint(x: 0, y: y))
          path.addLine(to: CGPoint(x: size.width, y: y))
        }
        context.stroke(path, with: .color(.cyan.opacity(0.03)), lineWidth: 0.5)
      }

      VStack(spacing: 20) {
        Image(systemName: "network")
          .font(.system(size: 40, weight: .ultraLight))
          .foregroundColor(.cyan.opacity(0.15))

        VStack(spacing: 6) {
          Text("SELECT FLOW")
            .font(.system(size: 12, weight: .bold, design: .monospaced))
            .foregroundColor(.white.opacity(0.3))
          Text("Choose a flow to inspect headers, body, and timing")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.15))
            .multilineTextAlignment(.center)
        }

        // Quick stats when flows exist
        if store.totalFlowCount > 0 {
          Rectangle()
            .fill(Color.cyan.opacity(0.1))
            .frame(width: 80, height: 0.5)
            .padding(.vertical, 4)

          HStack(spacing: 20) {
            VStack(spacing: 2) {
              Text("\(store.statistics.successful)")
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .foregroundColor(Color(red: 0.3, green: 0.9, blue: 0.5))
              Text("OK")
                .font(.system(size: 8, weight: .medium, design: .monospaced))
                .foregroundColor(.white.opacity(0.2))
            }
            VStack(spacing: 2) {
              Text("\(store.statistics.failed + store.statistics.errors)")
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .foregroundColor(Color(red: 1.0, green: 0.35, blue: 0.35))
              Text("ERR")
                .font(.system(size: 8, weight: .medium, design: .monospaced))
                .foregroundColor(.white.opacity(0.2))
            }
            VStack(spacing: 2) {
              Text(store.statistics.totalBytesFormatted)
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .foregroundColor(.cyan)
              Text("DATA")
                .font(.system(size: 8, weight: .medium, design: .monospaced))
                .foregroundColor(.white.opacity(0.2))
            }
          }
        }
      }
    }
  }

  // MARK: - Toolbar

  @ToolbarContentBuilder
  var toolbarContent: some ToolbarContent {
    ToolbarItemGroup(placement: .primaryAction) {
      Button(action: {
        Task { await store.refreshFlows() }
      }) {
        Label("Refresh", systemImage: "arrow.clockwise")
      }
      .disabled(store.isLoading)

      Button(action: { showingClearConfirmation = true }) {
        Label("Clear", systemImage: "trash")
      }
      .disabled(store.flows.isEmpty)

      Divider()

      // Connection status
      HStack(spacing: 4) {
        Circle()
          .fill(store.isEnabled
            ? Color(red: 0.3, green: 0.9, blue: 0.5)
            : Color(red: 1.0, green: 0.35, blue: 0.35))
          .frame(width: 6, height: 6)
        Text(store.isEnabled ? "ONLINE" : "OFFLINE")
          .font(.system(size: 9, weight: .bold, design: .monospaced))
          .foregroundColor(.white.opacity(0.4))
      }
    }
  }
}
