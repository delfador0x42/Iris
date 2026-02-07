import SwiftUI

extension WiFiMonitorView {

    // MARK: - Connect Sheet

    var connectSheet: some View {
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
}
