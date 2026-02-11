import SwiftUI

// MARK: - Extension Setup & State Views

extension NetworkMonitorView {

    // MARK: - Extension Setup View

    var extensionSetupView: some View {
        VStack(spacing: 20) {
            Image(systemName: "network.badge.shield.half.filled")
                .font(.system(size: 64))
                .foregroundColor(.blue)

            Text("Network Monitor")
                .font(.system(size: 24, weight: .bold))
                .foregroundColor(.white)

            Text("Install the security extension to monitor network connections")
                .font(.system(size: 14))
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)

            extensionStatusView

            if extensionManager.networkExtensionState == .needsUserApproval {
                Button("Open System Settings") {
                    extensionManager.openSystemSettings()
                }
                .buttonStyle(.bordered)
            } else if extensionManager.networkExtensionState != .installing {
                Button("Install Extension") {
                    extensionManager.installExtension(.network)
                }
                .buttonStyle(.borderedProminent)
            }

            if let error = extensionManager.lastError {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Error Details:")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.red)

                    ScrollView {
                        Text(error)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.red.opacity(0.9))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 120)
                }
                .padding(12)
                .background(Color.red.opacity(0.1))
                .cornerRadius(8)
                .padding(.horizontal, 40)
                .padding(.top, 8)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Extension Status

    var extensionStatusView: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(extensionStatusColor)
                .frame(width: 8, height: 8)

            Text(extensionManager.networkExtensionState.description)
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.gray)
        }
        .padding(.vertical, 8)
    }

    var extensionStatusColor: Color {
        switch extensionManager.networkExtensionState {
        case .installed: return .green
        case .installing: return .yellow
        case .needsUserApproval: return .orange
        case .failed: return .red
        default: return .gray
        }
    }

    // MARK: - Connecting View

    var connectingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.2)
                .tint(.white)

            Text("Connecting to extension...")
                .font(.system(size: 14))
                .foregroundColor(.gray)

            Button("Connect") {
                store.connect()
            }
            .buttonStyle(.bordered)
            .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Empty View

    var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "network.slash")
                .font(.system(size: 48))
                .foregroundColor(.gray)

            Text("No active connections")
                .font(.headline)
                .foregroundColor(.white)

            Text("Network activity will appear here")
                .font(.system(size: 14))
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
