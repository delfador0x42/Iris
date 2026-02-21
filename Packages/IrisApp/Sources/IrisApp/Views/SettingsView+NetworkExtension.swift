import SwiftUI

// MARK: - Network Extension Section (unified proxy + DNS + firewall)

extension SettingsView {

    var networkExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Network Extension", icon: "network")

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Network Monitor")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Monitors traffic, encrypts DNS, and inspects HTTPS")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    networkExtensionStatusBadge
                }

                networkExtensionActionButton

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
}
