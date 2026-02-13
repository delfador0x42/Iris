import SwiftUI

// MARK: - Helper Views

extension SettingsView {

    func sectionHeader(title: String, icon: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(Color(red: 0.4, green: 0.6, blue: 1.0))

            Text(title)
                .font(.system(size: 18, weight: .semibold))
                .foregroundColor(.white)
        }
    }

    func errorView(error: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                Text("Error")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.red)
            }

            ThemedScrollView {
                Text(error)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.red.opacity(0.9))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 80)
        }
        .padding(12)
        .background(Color.red.opacity(0.1))
        .cornerRadius(8)
    }

    func statusColor(for state: ExtensionState) -> Color {
        switch state {
        case .installed: return .green
        case .installing: return .yellow
        case .needsUserApproval: return .orange
        case .failed: return .red
        default: return .gray
        }
    }

    @ViewBuilder
    func extensionActionButton(for type: ExtensionType, state: ExtensionState) -> some View {
        switch state {
        case .notInstalled, .unknown:
            Button(action: { extensionManager.installExtension(type) }) {
                HStack {
                    Image(systemName: "arrow.down.circle.fill")
                    Text("Install Extension")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)

        case .installing:
            HStack {
                ProgressView()
                    .scaleEffect(0.8)
                    .tint(.white)
                Text("Installing...")
                    .foregroundColor(.gray)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)

        case .needsUserApproval:
            VStack(spacing: 12) {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    Text("User approval required")
                        .foregroundColor(.orange)
                        .font(.system(size: 13))
                }

                Button(action: { extensionManager.openSystemSettings() }) {
                    HStack {
                        Image(systemName: "gear")
                        Text("Open System Settings")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)

                Text("Go to Privacy & Security > Security and allow the extension")
                    .font(.system(size: 11))
                    .foregroundColor(.gray)
                    .multilineTextAlignment(.center)
            }

        case .installed:
            VStack(spacing: 12) {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text("Extension installed and active")
                        .foregroundColor(.green)
                        .font(.system(size: 13))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)

                HStack(spacing: 12) {
                    Button(action: {
                        Task {
                            await extensionManager.checkAllExtensionStatuses()
                        }
                    }) {
                        HStack {
                            Image(systemName: "arrow.clockwise")
                            Text("Refresh")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(.gray)

                    Button(action: { extensionManager.installExtension(type) }) {
                        HStack {
                            Image(systemName: "arrow.triangle.2.circlepath")
                            Text("Reinstall")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(.blue)

                    Button(action: { extensionManager.uninstallExtension(type) }) {
                        HStack {
                            Image(systemName: "trash")
                            Text("Uninstall")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                }
            }

        case .failed:
            Button(action: { extensionManager.installExtension(type) }) {
                HStack {
                    Image(systemName: "arrow.clockwise")
                    Text("Retry Installation")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(.orange)
        }
    }
}
