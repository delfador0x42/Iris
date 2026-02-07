//
//  DNSMonitorView.swift
//  IrisDNS
//
//  Main view for monitoring DNS queries and managing encrypted DNS.
//

import SwiftUI

/// Main view for the DNS query monitor.
public struct DNSMonitorView: View {
    @StateObject var store = DNSStore.shared
    @State var showingClearConfirmation = false
    @State var showingServerPicker = false

    public init() {}

    public var body: some View {
        HSplitView {
            // Left: Query list
            queryListView
                .frame(minWidth: 450)

            // Right: Query detail or stats
            if let query = store.selectedQuery {
                DNSQueryDetailView(query: query)
                    .frame(minWidth: 350)
            } else {
                statsView
                    .frame(minWidth: 350)
            }
        }
        .toolbar {
            toolbarContent
        }
        .onAppear {
            store.connect()
        }
        .alert("Clear All Queries?", isPresented: $showingClearConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Clear", role: .destructive) {
                Task {
                    await store.clearQueries()
                }
            }
        } message: {
            Text("This will remove all \(store.totalQueries) captured DNS queries. This action cannot be undone.")
        }
        .sheet(isPresented: $showingServerPicker) {
            DoHServerPickerView(store: store)
        }
    }
}

// MARK: - Preview

#Preview {
    DNSMonitorView()
        .frame(width: 1000, height: 600)
}
