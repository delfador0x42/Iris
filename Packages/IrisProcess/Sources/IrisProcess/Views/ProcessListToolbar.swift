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

            // ExecPolicy enforcement toggle
            Button(action: {
                Task {
                    await store.setEnforcementMode(!store.enforcementEnabled)
                }
            }) {
                HStack(spacing: 4) {
                    Image(systemName: store.enforcementEnabled ? "lock.shield.fill" : "lock.shield")
                    Text(store.enforcementEnabled ? "Enforcing" : "Audit")
                }
                .font(.system(size: 12))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(store.enforcementEnabled ? Color.orange.opacity(0.3) : Color.white.opacity(0.1))
                .foregroundColor(store.enforcementEnabled ? .orange : .gray)
                .cornerRadius(6)
            }
            .buttonStyle(.plain)
            .help(store.enforcementEnabled
                ? "ExecPolicy is ENFORCING — blocked processes will be denied"
                : "ExecPolicy is in AUDIT mode — decisions are logged but not enforced")

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

            // View mode toggle — custom buttons for dark theme visibility
            HStack(spacing: 0) {
                modeButton("Monitor", icon: "shield.lefthalf.filled", mode: .monitor)
                modeButton("History", icon: "clock.arrow.circlepath", mode: .history)
            }
            .background(Color.white.opacity(0.06))
            .cornerRadius(6)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(Color.black.opacity(0.2))
    }

    private func modeButton(_ title: String, icon: String, mode: ProcessStore.ViewMode) -> some View {
        let selected = store.viewMode == mode
        return Button(action: { store.viewMode = mode }) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                Text(title)
            }
            .font(.system(size: 12, weight: selected ? .semibold : .regular))
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(selected ? Color.cyan.opacity(0.3) : Color.clear)
            .foregroundColor(selected ? .cyan : .gray)
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
    }
}
