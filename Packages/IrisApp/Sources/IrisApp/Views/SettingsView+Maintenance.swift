import SwiftUI

extension SettingsView {

    var maintenanceSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Maintenance", icon: "wrench.and.screwdriver")

            VStack(alignment: .leading, spacing: 12) {
                Text("If extensions are outdated or stuck, a clean reinstall will uninstall all four, clean configurations, then reinstall from the latest build.")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)

                Button {
                    extensionManager.cleanReinstallExtensions()
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                        Text("Clean Reinstall All Extensions")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .tint(.orange)
                .disabled(extensionManager.isAnyExtensionInstalling)
            }
            .padding(16)
            .background(Color.white.opacity(0.03))
            .cornerRadius(10)
        }
    }
}
