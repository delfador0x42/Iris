import SwiftUI

/// Settings view for managing app preferences and security extension
public struct SettingsView: View {
    @StateObject var extensionManager = ExtensionManager.shared
    // API key state stored in UserDefaults
    @AppStorage("abuseIPDBAPIKey") var abuseIPDBKey: String = ""

    public init() {}

    public var body: some View {
        ZStack {
            // Dark gradient background
            LinearGradient(
                colors: [
                    Color(red: 0.02, green: 0.03, blue: 0.05),
                    Color(red: 0.05, green: 0.07, blue: 0.1)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 32) {
                    // Header
                    Text("Settings")
                        .font(.system(size: 36, weight: .bold, design: .serif))
                        .foregroundColor(.white)
                        .padding(.bottom, 8)

                    // System Extensions Section
                    networkExtensionSection

                    endpointExtensionSection

                    proxyExtensionSection

                    dnsExtensionSection

                    // Network Capture Section
                    networkCaptureSection

                    // Permissions Section
                    permissionsSection

                    // Threat Intelligence Section
                    threatIntelligenceSection

                    Spacer()
                }
                .padding(32)
            }
        }
        .onAppear {
            Task {
                await extensionManager.checkAllExtensionStatuses()
            }
        }
    }
}

#Preview {
    SettingsView()
        .frame(width: 600, height: 700)
}
