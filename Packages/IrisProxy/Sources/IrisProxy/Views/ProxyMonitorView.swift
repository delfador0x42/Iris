//
//  ProxyMonitorView.swift
//  IrisProxy
//
//  Main view for monitoring HTTP flows captured by the proxy.
//

import SwiftUI

/// Main view for the HTTP proxy monitor.
public struct ProxyMonitorView: View {
    @StateObject var store = ProxyStore.shared
    @State var showingClearConfirmation = false

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
            store.startMonitoring()
        }
        .onDisappear {
            store.stopMonitoring()
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
}

// MARK: - Preview

#Preview {
    ProxyMonitorView()
        .frame(width: 1000, height: 600)
}
