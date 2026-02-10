import SwiftUI

// MARK: - Proxy Extension Section

extension SettingsView {

    var proxyExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Proxy Extension", icon: "lock.shield")

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("HTTPS Proxy")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Intercepts HTTPS traffic for TLS inspection")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    HStack(spacing: 6) {
                        Circle()
                            .fill(statusColor(for: extensionManager.proxyExtensionState))
                            .frame(width: 8, height: 8)

                        Text(extensionManager.proxyExtensionState.description)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }

                extensionActionButton(for: .proxy, state: extensionManager.proxyExtensionState)
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }
}

// MARK: - DNS Extension Section

extension SettingsView {

    var dnsExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "DNS Extension", icon: "globe")

            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("DNS Proxy")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Encrypts DNS queries via DNS-over-HTTPS")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    HStack(spacing: 6) {
                        Circle()
                            .fill(statusColor(for: extensionManager.dnsExtensionState))
                            .frame(width: 8, height: 8)

                        Text(extensionManager.dnsExtensionState.description)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }

                extensionActionButton(for: .dns, state: extensionManager.dnsExtensionState)
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }
}
