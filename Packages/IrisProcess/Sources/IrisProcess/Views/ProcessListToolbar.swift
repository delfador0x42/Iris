import SwiftUI

/// Process toolbar — NieR aesthetic.
struct ProcessListToolbar: View {
    @ObservedObject var store: ProcessStore

    var body: some View {
        HStack(spacing: 10) {
            // Search
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 10))
                    .foregroundColor(.cyan.opacity(0.4))
                TextField("Filter...", text: $store.filterText)
                    .textFieldStyle(.plain)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.white.opacity(0.8))
                if !store.filterText.isEmpty {
                    Button(action: { store.filterText = "" }) {
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
            .frame(maxWidth: 240)

            // Suspicious filter
            Button(action: { store.showOnlySuspicious.toggle() }) {
                HStack(spacing: 4) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 10))
                    Text("SUSPECT")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                }
                .foregroundColor(store.showOnlySuspicious
                    ? Color(red: 1.0, green: 0.35, blue: 0.35)
                    : .white.opacity(0.3))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(store.showOnlySuspicious
                    ? Color.red.opacity(0.08)
                    : Color.white.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 3)
                        .stroke(store.showOnlySuspicious
                            ? Color.red.opacity(0.3)
                            : Color.white.opacity(0.06), lineWidth: 0.5)
                )
                .cornerRadius(3)
            }
            .buttonStyle(.plain)

            // ExecPolicy toggle
            Button(action: {
                Task { await store.setEnforcementMode(!store.enforcementEnabled) }
            }) {
                HStack(spacing: 4) {
                    Image(systemName: store.enforcementEnabled ? "lock.shield.fill" : "lock.shield")
                        .font(.system(size: 10))
                    Text(store.enforcementEnabled ? "ENFORCE" : "AUDIT")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                }
                .foregroundColor(store.enforcementEnabled
                    ? Color(red: 1.0, green: 0.6, blue: 0.2)
                    : .white.opacity(0.3))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(store.enforcementEnabled
                    ? Color.orange.opacity(0.08)
                    : Color.white.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 3)
                        .stroke(store.enforcementEnabled
                            ? Color.orange.opacity(0.3)
                            : Color.white.opacity(0.06), lineWidth: 0.5)
                )
                .cornerRadius(3)
            }
            .buttonStyle(.plain)
            .help(store.enforcementEnabled
                ? "ExecPolicy ENFORCING — blocked processes denied"
                : "ExecPolicy AUDIT — decisions logged only")

            Spacer()

            // Sort
            HStack(spacing: 4) {
                Text("SORT")
                    .font(.system(size: 8, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.2))
                Picker("", selection: $store.sortOrder) {
                    ForEach(ProcessStore.SortOrder.allCases, id: \.self) { order in
                        Text(order.rawValue).tag(order)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 100)
            }

            // View mode toggle
            HStack(spacing: 2) {
                modeButton("MON", icon: "shield.lefthalf.filled", mode: .monitor)
                modeButton("HIST", icon: "clock.arrow.circlepath", mode: .history)
            }
            .padding(2)
            .background(Color.black.opacity(0.3))
            .cornerRadius(4)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color(red: 0.015, green: 0.025, blue: 0.045))
    }

    private func modeButton(_ title: String, icon: String, mode: ProcessStore.ViewMode) -> some View {
        let selected = store.viewMode == mode
        return Button(action: { store.viewMode = mode }) {
            HStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: 10))
                Text(title)
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(selected ? Color.cyan.opacity(0.12) : Color.clear)
            .foregroundColor(selected ? .cyan : .white.opacity(0.25))
            .overlay(
                RoundedRectangle(cornerRadius: 3)
                    .stroke(selected ? Color.cyan.opacity(0.25) : Color.clear, lineWidth: 0.5)
            )
            .cornerRadius(3)
        }
        .buttonStyle(.plain)
    }
}
