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

                        Text("Real-time process monitoring via Endpoint Security")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    endpointExtensionStatusBadge
                }

                // Extension Action Button
                endpointExtensionActionButton

                // ES health details when extension is installed
                if extensionManager.endpointExtensionState == .installed {
                    Divider()
                        .background(Color.gray.opacity(0.3))

                    HStack(spacing: 12) {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundColor(.green)
                            .font(.system(size: 14))

                        VStack(alignment: .leading, spacing: 2) {
                            Text("Endpoint Security Active")
                                .font(.system(size: 13, weight: .medium))
                                .foregroundColor(.green)
                            Text("Monitoring EXEC, FORK, EXIT events")
                                .font(.system(size: 11))
                                .foregroundColor(.gray)
                        }
                    }
                }

                // Show error details when ES failed
                if case .failed(let reason) = extensionManager.endpointExtensionState {
                    esFailedWarning(reason: reason)
                }

                // Full Disk Access requirement
                if !extensionManager.hasFullDiskAccess {
                    fullDiskAccessWarning
                }
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

    // MARK: - ES Warning Views

    func esFailedWarning(reason: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                    .font(.system(size: 14))
                Text("Endpoint Security Failed")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(.red)
            }

            Text(reason)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.red.opacity(0.8))
                .textSelection(.enabled)

            Text("The extension is running but ES could not initialize. Check that the app has been approved in System Settings > Privacy & Security.")
                .font(.system(size: 11))
                .foregroundColor(.gray)

            Button(action: { extensionManager.openSystemSettings() }) {
                HStack {
                    Image(systemName: "gear")
                    Text("Open Privacy & Security")
                }
            }
            .buttonStyle(.bordered)
            .tint(.orange)
        }
        .padding(12)
        .background(Color.red.opacity(0.1))
        .cornerRadius(8)
    }

    var fullDiskAccessWarning: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "lock.trianglebadge.exclamationmark")
                    .foregroundColor(.orange)
                    .font(.system(size: 14))
                Text("Full Disk Access Recommended")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.orange)
            }

            Text("Grant Full Disk Access to the Iris endpoint extension for complete file system visibility.")
                .font(.system(size: 11))
                .foregroundColor(.gray)

            Button(action: { extensionManager.openFullDiskAccessSettings() }) {
                HStack {
                    Image(systemName: "lock.open")
                    Text("Open Full Disk Access Settings")
                }
            }
            .buttonStyle(.bordered)
            .tint(.orange)
        }
        .padding(12)
        .background(Color.orange.opacity(0.1))
        .cornerRadius(8)
    }
}
