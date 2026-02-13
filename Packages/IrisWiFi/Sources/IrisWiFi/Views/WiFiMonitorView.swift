import SwiftUI

/// Main view for WiFi monitoring
public struct WiFiMonitorView: View {
    @StateObject var store = WiFiStore()
    @State var selectedNetwork: WiFiNetwork?
    @State var showConnectSheet = false
    @State var networkToConnect: WiFiNetwork?
    @State var passwordInput = ""
    @State var isConnecting = false

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

            ThemedScrollView {
                VStack(spacing: 20) {
                    // Header with power toggle
                    headerSection

                    if store.isPoweredOn {
                        // Current connection card
                        if let info = store.interfaceInfo, info.isConnected {
                            connectionCard(info)
                        } else {
                            notConnectedCard
                        }

                        // Signal strength graph
                        if !store.signalHistory.isEmpty {
                            signalGraph
                        }

                        // Network scan section
                        networkScanSection
                    } else {
                        wifiOffCard
                    }

                    // Error message
                    if let error = store.errorMessage {
                        errorCard(error)
                    }
                }
                .padding()
            }
        }
        .onAppear {
            store.startMonitoring()
        }
        .onDisappear {
            store.stopMonitoring()
        }
        .sheet(isPresented: $showConnectSheet) {
            connectSheet
        }
    }
}

#Preview {
    WiFiMonitorView()
        .frame(width: 500, height: 800)
}
