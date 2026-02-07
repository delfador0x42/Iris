import SwiftUI

// MARK: - Threat Intelligence Section

extension SettingsView {

    var threatIntelligenceSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Threat Intelligence", icon: "shield.checkerboard")

            VStack(alignment: .leading, spacing: 16) {
                // AbuseIPDB API Key
                VStack(alignment: .leading, spacing: 8) {
                    Text("AbuseIPDB API Key")
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.white)

                    SecureField("Enter API key...", text: $abuseIPDBKey)
                        .textFieldStyle(.roundedBorder)
                        .onChange(of: abuseIPDBKey) { _, newValue in
                            Task {
                                await AbuseIPDBService.shared.setAPIKey(newValue.isEmpty ? nil : newValue)
                            }
                        }

                    Text("Get a free API key at abuseipdb.com (1,000 lookups/day)")
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                }

                Divider()
                    .background(Color.gray.opacity(0.3))

                // GreyNoise (no key needed)
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("GreyNoise")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Detects benign scanners vs malicious IPs (100/day)")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    HStack(spacing: 6) {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 8, height: 8)

                        Text("Active (no key needed)")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }

                // Status information
                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundColor(.blue)
                            .font(.system(size: 12))

                        Text("Threat intelligence enriches IP connections with abuse scores, scanner detection, and security classifications.")
                            .font(.system(size: 11))
                            .foregroundColor(.gray)
                    }
                }
                .padding(12)
                .background(Color.blue.opacity(0.1))
                .cornerRadius(8)
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
        .onAppear {
            // Initialize the service with stored API key
            Task {
                await AbuseIPDBService.shared.setAPIKey(abuseIPDBKey.isEmpty ? nil : abuseIPDBKey)
            }
        }
    }
}
