import SwiftUI

// MARK: - Endpoint Extension Section

extension SettingsView {

    var endpointExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Endpoint Extension", icon: "cpu")

            VStack(alignment: .leading, spacing: 12) {
                // Extension Status Row
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Process Monitor")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Monitors process execution via Endpoint Security")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    endpointExtensionStatusBadge
                }

                // Extension Action Button
                endpointExtensionActionButton
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }

    var endpointExtensionStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor(for: extensionManager.endpointExtensionState))
                .frame(width: 8, height: 8)

            Text(extensionManager.endpointExtensionState.description)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    @ViewBuilder
    var endpointExtensionActionButton: some View {
        extensionActionButton(for: .endpoint, state: extensionManager.endpointExtensionState)
    }
}
