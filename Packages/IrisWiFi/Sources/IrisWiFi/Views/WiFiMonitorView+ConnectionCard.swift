import SwiftUI

extension WiFiMonitorView {

    // MARK: - Connection Card

    func connectionCard(_ info: WiFiInterfaceInfo) -> some View {
        VStack(spacing: 16) {
            // Network name and signal
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(info.ssid ?? "Unknown Network")
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundColor(.white)

                    if let bssid = info.bssid {
                        Text(bssid)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }

                Spacer()

                // Signal bars
                signalBars(quality: info.signalQuality)
            }

            Divider()
                .background(Color.white.opacity(0.2))

            // Stats grid
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 16) {
                statCell(title: "RSSI", value: "\(info.rssi) dBm", quality: info.signalQuality)
                statCell(title: "Noise", value: "\(info.noise) dBm")
                statCell(title: "SNR", value: "\(info.snr) dB", quality: snrQuality(info.snr))

                statCell(title: "Channel", value: "\(info.channel)")
                statCell(title: "Band", value: info.channelBand.shortName)
                statCell(title: "Width", value: info.channelWidth.displayName)

                statCell(title: "PHY Mode", value: info.phyMode.shortName)
                statCell(title: "TX Rate", value: info.formattedTransmitRate)
                statCell(title: "Security", value: info.security.rawValue, isSecure: !info.security.isWeak)

                statCell(title: "MCS", value: info.mcsDescription ?? "-")
                statCell(title: "Streams", value: info.nssDescription ?? "-")
                statCell(title: "Mode", value: info.interfaceMode.rawValue)
            }

            Divider()
                .background(Color.white.opacity(0.2))

            // Additional info
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("MAC: \(info.hardwareAddress)")
                        .font(.system(.caption, design: .monospaced))
                    if let country = info.countryCode {
                        Text("Country: \(country)")
                            .font(.caption)
                    }
                }
                .foregroundColor(.gray)

                Spacer()

                Text("TX Power: \(info.formattedTransmitPower)")
                    .font(.caption)
                    .foregroundColor(.gray)
            }

            // Disconnect button
            Button {
                store.disassociate()
            } label: {
                HStack {
                    Image(systemName: "wifi.slash")
                    Text("Disconnect")
                }
                .font(.subheadline)
                .foregroundColor(.red)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
                .background(Color.red.opacity(0.15))
                .cornerRadius(8)
            }
            .buttonStyle(.plain)
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(16)
    }

    var notConnectedCard: some View {
        VStack(spacing: 12) {
            Image(systemName: "wifi.slash")
                .font(.system(size: 48))
                .foregroundColor(.gray)

            Text("Not Connected")
                .font(.headline)
                .foregroundColor(.white)

            Text("No WiFi network connected")
                .font(.caption)
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity)
        .padding(40)
        .background(Color.white.opacity(0.05))
        .cornerRadius(16)
    }

    var wifiOffCard: some View {
        VStack(spacing: 12) {
            Image(systemName: "wifi.exclamationmark")
                .font(.system(size: 48))
                .foregroundColor(.orange)

            Text("WiFi is Off")
                .font(.headline)
                .foregroundColor(.white)

            Text("Turn on WiFi to see network information")
                .font(.caption)
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity)
        .padding(40)
        .background(Color.white.opacity(0.05))
        .cornerRadius(16)
    }

    // MARK: - Error Card

    func errorCard(_ message: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.orange)

            Text(message)
                .font(.caption)
                .foregroundColor(.orange)
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(Color.orange.opacity(0.1))
        .cornerRadius(8)
    }
}
