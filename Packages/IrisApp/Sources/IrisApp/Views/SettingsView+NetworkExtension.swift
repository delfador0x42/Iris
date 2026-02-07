import SwiftUI

// MARK: - Network Extension Section

extension SettingsView {

    var networkExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Network Extension", icon: "network")

            VStack(alignment: .leading, spacing: 12) {
                // Extension Status Row
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Network Filter")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Monitors and filters network connections")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    networkExtensionStatusBadge
                }

                // Extension Action Button
                networkExtensionActionButton

                // Filter Status Row (only when extension is installed)
                if extensionManager.networkExtensionState == .installed {
                    Divider()
                        .background(Color.gray.opacity(0.3))

                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Filter Active")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundColor(.white)

                            Text("Enable or disable network filtering")
                                .font(.system(size: 12))
                                .foregroundColor(.gray)
                        }

                        Spacer()

                        filterStatusBadge

                        Toggle("", isOn: Binding(
                            get: { extensionManager.filterState == .enabled },
                            set: { enabled in
                                Task {
                                    if enabled {
                                        await extensionManager.enableFilter()
                                    } else {
                                        await extensionManager.disableFilter()
                                    }
                                }
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .disabled(extensionManager.filterState == .configuring)
                    }
                }

                // Error display
                if let error = extensionManager.lastError {
                    errorView(error: error)
                }
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }

    var networkExtensionStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor(for: extensionManager.networkExtensionState))
                .frame(width: 8, height: 8)

            Text(extensionManager.networkExtensionState.description)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    @ViewBuilder
    var networkExtensionActionButton: some View {
        extensionActionButton(for: .network, state: extensionManager.networkExtensionState)
    }

    var filterStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(filterStatusColor)
                .frame(width: 8, height: 8)

            Text(extensionManager.filterState.description)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    var filterStatusColor: Color {
        switch extensionManager.filterState {
        case .enabled: return .green
        case .disabled: return .gray
        case .configuring: return .yellow
        default: return .gray
        }
    }
}
