import SwiftUI

/// Toolbar with search, filters, and sort options for the process list
struct ProcessListToolbar: View {
    @ObservedObject var store: ProcessStore

    var body: some View {
        HStack(spacing: 16) {
            // Search field
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)

                TextField("Search processes...", text: $store.filterText)
                    .textFieldStyle(.plain)
                    .foregroundColor(.white)

                if !store.filterText.isEmpty {
                    Button(action: { store.filterText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.gray)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(Color.white.opacity(0.1))
            .cornerRadius(8)
            .frame(maxWidth: 300)

            // Suspicious filter toggle
            Button(action: {
                store.showOnlySuspicious.toggle()
            }) {
                HStack(spacing: 4) {
                    Image(systemName: "exclamationmark.triangle")
                    Text("Suspicious Only")
                }
                .font(.system(size: 12))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(store.showOnlySuspicious ? Color.red.opacity(0.3) : Color.white.opacity(0.1))
                .foregroundColor(store.showOnlySuspicious ? .red : .white)
                .cornerRadius(6)
            }
            .buttonStyle(.plain)

            // View mode toggle (Monitor / History)
            Picker("", selection: $store.viewMode) {
                ForEach(ProcessStore.ViewMode.allCases, id: \.self) { mode in
                    Label(mode.rawValue, systemImage: mode == .monitor ? "shield.lefthalf.filled" : "clock.arrow.circlepath")
                        .tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 160)

            Spacer()

            // Sort picker
            HStack(spacing: 8) {
                Text("Sort:")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)

                Picker("", selection: $store.sortOrder) {
                    ForEach(ProcessStore.SortOrder.allCases, id: \.self) { order in
                        Text(order.rawValue).tag(order)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 120)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(Color.black.opacity(0.2))
    }
}
