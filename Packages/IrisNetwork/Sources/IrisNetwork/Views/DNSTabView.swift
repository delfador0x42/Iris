import SwiftUI

/// DNS monitoring embedded as a tab within Network Monitor.
/// Uses DNSStore from IrisDNS package (same module, no import needed).
struct DNSTabView: View {
    @ObservedObject var store = DNSStore.shared
    @State var showingClearConfirmation = false
    @State var showingServerPicker = false

    var body: some View {
        HSplitView {
            queryListPane
                .frame(minWidth: 450)

            if let query = store.selectedQuery {
                DNSQueryDetailView(query: query)
                    .frame(minWidth: 350)
            } else {
                statsPane
                    .frame(minWidth: 350)
            }
        }
        .onAppear {
            store.connect()
            store.startMonitoring()
        }
        .onDisappear {
            store.stopMonitoring()
        }
        .alert("Clear All Queries?", isPresented: $showingClearConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Clear", role: .destructive) {
                Task { await store.clearQueries() }
            }
        } message: {
            Text("This will remove all \(store.totalQueries) captured DNS queries.")
        }
        .sheet(isPresented: $showingServerPicker) {
            DoHServerPickerView(store: store)
        }
    }
}
