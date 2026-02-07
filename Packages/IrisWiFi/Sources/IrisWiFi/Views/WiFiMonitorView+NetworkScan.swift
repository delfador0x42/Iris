import SwiftUI

extension WiFiMonitorView {

    // MARK: - Network Scan Section

    var networkScanSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Nearby Networks")
                    .font(.headline)
                    .foregroundColor(.white)

                Spacer()

                Button {
                    Task {
                        await store.scan()
                    }
                } label: {
                    HStack(spacing: 4) {
                        if store.isScanning {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "arrow.clockwise")
                        }
                        Text("Scan")
                    }
                    .font(.caption)
                    .foregroundColor(.blue)
                }
                .disabled(store.isScanning)
            }

            if store.scannedNetworks.isEmpty {
                Text("No networks found. Tap Scan to search.")
                    .font(.caption)
                    .foregroundColor(.gray)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else {
                ForEach(store.scannedNetworks) { network in
                    networkRow(network)
                }
            }
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(16)
    }

    func networkRow(_ network: WiFiNetwork) -> some View {
        HStack(spacing: 12) {
            // Signal indicator
            signalBars(quality: network.signalQuality, size: 16)

            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(network.displayName)
                        .font(.system(.body, design: network.isHidden ? .monospaced : .default))
                        .foregroundColor(network.isHidden ? .gray : .white)

                    if network.security.isWeak {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.caption2)
                            .foregroundColor(.orange)
                    }
                }

                HStack(spacing: 8) {
                    Text("Ch \(network.channel)")
                    Text(network.channelBand.shortName)
                    Text(network.security.rawValue)
                }
                .font(.caption2)
                .foregroundColor(.gray)
            }

            Spacer()

            Text("\(network.rssi) dBm")
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(colorForSignal(network.signalQuality))

            // Connect button
            Button {
                networkToConnect = network
                passwordInput = ""
                if network.security == .none {
                    // Open network - connect directly
                    Task {
                        isConnecting = true
                        _ = await store.associate(to: network, password: nil)
                        isConnecting = false
                    }
                } else {
                    // Secured network - show password sheet
                    showConnectSheet = true
                }
            } label: {
                Image(systemName: "wifi.circle")
                    .font(.title3)
                    .foregroundColor(.blue)
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 8)
    }
}
