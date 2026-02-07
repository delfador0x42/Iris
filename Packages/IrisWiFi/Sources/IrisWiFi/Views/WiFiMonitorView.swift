import SwiftUI
import Charts

/// Main view for WiFi monitoring
public struct WiFiMonitorView: View {
    @StateObject private var store = WiFiStore()
    @State private var selectedNetwork: WiFiNetwork?
    @State private var showConnectSheet = false
    @State private var networkToConnect: WiFiNetwork?
    @State private var passwordInput = ""
    @State private var isConnecting = false

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

    // MARK: - Connect Sheet

    private var connectSheet: some View {
        VStack(spacing: 20) {
            Text("Connect to Network")
                .font(.headline)

            if let network = networkToConnect {
                VStack(spacing: 8) {
                    Text(network.displayName)
                        .font(.title2)
                        .fontWeight(.semibold)

                    HStack(spacing: 12) {
                        Label(network.security.rawValue, systemImage: "lock.fill")
                        Label(network.channelBand.shortName, systemImage: "antenna.radiowaves.left.and.right")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }

                SecureField("Password", text: $passwordInput)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 300)

                HStack(spacing: 16) {
                    Button("Cancel") {
                        showConnectSheet = false
                        networkToConnect = nil
                    }
                    .buttonStyle(.bordered)

                    Button {
                        Task {
                            isConnecting = true
                            _ = await store.associate(to: network, password: passwordInput)
                            isConnecting = false
                            showConnectSheet = false
                            networkToConnect = nil
                        }
                    } label: {
                        if isConnecting {
                            ProgressView()
                                .scaleEffect(0.8)
                        } else {
                            Text("Connect")
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(passwordInput.isEmpty || isConnecting)
                }
            }
        }
        .padding(30)
        .frame(minWidth: 350)
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("WiFi Monitor")
                    .font(.system(size: 28, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                if let info = store.interfaceInfo {
                    Text("Interface: \(info.id)")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
            }

            Spacer()

            // Power toggle
            Toggle("", isOn: Binding(
                get: { store.isPoweredOn },
                set: { newValue in
                    Task {
                        await store.setPower(newValue)
                    }
                }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
        }
    }

    // MARK: - Connection Card

    private func connectionCard(_ info: WiFiInterfaceInfo) -> some View {
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

    private var notConnectedCard: some View {
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

    private var wifiOffCard: some View {
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

    // MARK: - Signal Graph

    private var signalGraph: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Signal Strength")
                    .font(.headline)
                    .foregroundColor(.white)

                Spacer()

                Button("Clear") {
                    store.clearSignalHistory()
                }
                .font(.caption)
                .foregroundColor(.blue)
            }

            Chart(store.signalHistory) { sample in
                LineMark(
                    x: .value("Time", sample.timestamp),
                    y: .value("RSSI", sample.rssi)
                )
                .foregroundStyle(Color.cyan)
                .interpolationMethod(.catmullRom)

                AreaMark(
                    x: .value("Time", sample.timestamp),
                    y: .value("RSSI", sample.rssi)
                )
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color.cyan.opacity(0.3), Color.cyan.opacity(0.0)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .interpolationMethod(.catmullRom)
            }
            .chartYScale(domain: -100...(-20))
            .chartYAxis {
                AxisMarks(position: .leading, values: [-90, -70, -50, -30]) { value in
                    AxisGridLine()
                        .foregroundStyle(Color.white.opacity(0.1))
                    AxisValueLabel {
                        Text("\(value.as(Int.self) ?? 0)")
                            .font(.caption2)
                            .foregroundColor(.gray)
                    }
                }
            }
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 5)) { _ in
                    AxisGridLine()
                        .foregroundStyle(Color.white.opacity(0.1))
                }
            }
            .frame(height: 150)
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(16)
    }

    // MARK: - Network Scan Section

    private var networkScanSection: some View {
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

    private func networkRow(_ network: WiFiNetwork) -> some View {
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

    // MARK: - Error Card

    private func errorCard(_ message: String) -> some View {
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

    // MARK: - Helper Views

    private func signalBars(quality: WiFiSignalQuality, size: CGFloat = 24) -> some View {
        HStack(spacing: 2) {
            ForEach(0..<4) { bar in
                RoundedRectangle(cornerRadius: 2)
                    .fill(bar < quality.bars ? colorForSignal(quality) : Color.gray.opacity(0.3))
                    .frame(width: size / 4, height: size * CGFloat(bar + 1) / 4)
            }
        }
        .frame(width: size, height: size, alignment: .bottom)
    }

    private func statCell(
        title: String,
        value: String,
        quality: WiFiSignalQuality? = nil,
        isSecure: Bool? = nil
    ) -> some View {
        VStack(spacing: 4) {
            Text(title)
                .font(.caption2)
                .foregroundColor(.gray)

            Text(value)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(
                    quality != nil ? colorForSignal(quality!) :
                    isSecure == false ? .orange :
                    .white
                )
        }
    }

    private func colorForSignal(_ quality: WiFiSignalQuality) -> Color {
        switch quality {
        case .excellent: return .green
        case .good: return .cyan
        case .fair: return .yellow
        case .weak: return .orange
        case .poor: return .red
        }
    }

    private func snrQuality(_ snr: Int) -> WiFiSignalQuality {
        switch snr {
        case 40...: return .excellent
        case 25..<40: return .good
        case 15..<25: return .fair
        case 10..<15: return .weak
        default: return .poor
        }
    }
}

#Preview {
    WiFiMonitorView()
        .frame(width: 500, height: 800)
}
