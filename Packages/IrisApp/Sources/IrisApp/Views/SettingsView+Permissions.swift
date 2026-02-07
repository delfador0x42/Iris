import SwiftUI

// MARK: - Permissions Section

extension SettingsView {

    var permissionsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Permissions", icon: "lock.shield")

            VStack(alignment: .leading, spacing: 12) {
                // Full Disk Access
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Full Disk Access")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Required for Endpoint Security process monitoring")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    fullDiskAccessStatusBadge

                    if !extensionManager.hasFullDiskAccess {
                        Button(action: { extensionManager.openFullDiskAccessSettings() }) {
                            Text("Grant Access")
                                .font(.system(size: 12))
                        }
                        .buttonStyle(.bordered)
                    }
                }

                if !extensionManager.hasFullDiskAccess {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundColor(.blue)
                            .font(.system(size: 12))

                        Text("Add the Iris Security Extension to Full Disk Access in System Settings > Privacy & Security")
                            .font(.system(size: 11))
                            .foregroundColor(.gray)
                    }
                    .padding(12)
                    .background(Color.blue.opacity(0.1))
                    .cornerRadius(8)
                }
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }

    var fullDiskAccessStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(extensionManager.hasFullDiskAccess ? Color.green : Color.orange)
                .frame(width: 8, height: 8)

            Text(extensionManager.hasFullDiskAccess ? "Granted" : "Not Granted")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }
}
