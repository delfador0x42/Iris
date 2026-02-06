import SwiftUI

/// Settings view for managing app preferences and security extension
public struct SettingsView: View {
    @StateObject private var extensionManager = ExtensionManager.shared
    @Environment(\.dismiss) private var dismiss

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

                    // Network Extension Section
                    networkExtensionSection

                    // Endpoint Extension Section
                    endpointExtensionSection

                    // Permissions Section
                    permissionsSection

                    Spacer()
                }
                .padding(32)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button(action: { dismiss() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left")
                        Text("Back")
                    }
                    .foregroundColor(Color(red: 0.4, green: 0.7, blue: 1.0))
                }
            }
        }
        .onAppear {
            Task {
                await extensionManager.checkAllExtensionStatuses()
            }
        }
    }

    // MARK: - Network Extension Section

    private var networkExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Network Extension", icon: "network")

            VStack(alignment: .leading, spacing: 12) {
                // Extension Status Row
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Network Filter")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Monitors and filters network connections")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    networkExtensionStatusBadge
                }

                // Extension Action Button
                networkExtensionActionButton

                // Filter Status Row (only when extension is installed)
                if extensionManager.networkExtensionState == .installed {
                    Divider()
                        .background(Color.gray.opacity(0.3))

                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Filter Active")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundColor(.white)

                            Text("Enable or disable network filtering")
                                .font(.system(size: 12))
                                .foregroundColor(.gray)
                        }

                        Spacer()

                        filterStatusBadge

                        Toggle("", isOn: Binding(
                            get: { extensionManager.filterState == .enabled },
                            set: { enabled in
                                Task {
                                    if enabled {
                                        await extensionManager.enableFilter()
                                    } else {
                                        await extensionManager.disableFilter()
                                    }
                                }
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .disabled(extensionManager.filterState == .configuring)
                    }
                }

                // Error display
                if let error = extensionManager.lastError {
                    errorView(error: error)
                }
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }

    // MARK: - Endpoint Extension Section

    private var endpointExtensionSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Endpoint Extension", icon: "cpu")

            VStack(alignment: .leading, spacing: 12) {
                // Extension Status Row
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Process Monitor")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Monitors process execution via Endpoint Security")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    endpointExtensionStatusBadge
                }

                // Extension Action Button
                endpointExtensionActionButton
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }

    private var networkExtensionStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor(for: extensionManager.networkExtensionState))
                .frame(width: 8, height: 8)

            Text(extensionManager.networkExtensionState.description)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    private var endpointExtensionStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(statusColor(for: extensionManager.endpointExtensionState))
                .frame(width: 8, height: 8)

            Text(extensionManager.endpointExtensionState.description)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    private func statusColor(for state: ExtensionState) -> Color {
        switch state {
        case .installed: return .green
        case .installing: return .yellow
        case .needsUserApproval: return .orange
        case .failed: return .red
        default: return .gray
        }
    }

    @ViewBuilder
    private var networkExtensionActionButton: some View {
        extensionActionButton(for: .network, state: extensionManager.networkExtensionState)
    }

    @ViewBuilder
    private var endpointExtensionActionButton: some View {
        extensionActionButton(for: .endpoint, state: extensionManager.endpointExtensionState)
    }

    @ViewBuilder
    private func extensionActionButton(for type: ExtensionType, state: ExtensionState) -> some View {
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

    private var filterStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(filterStatusColor)
                .frame(width: 8, height: 8)

            Text(extensionManager.filterState.description)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    private var filterStatusColor: Color {
        switch extensionManager.filterState {
        case .enabled: return .green
        case .disabled: return .gray
        case .configuring: return .yellow
        default: return .gray
        }
    }

    // MARK: - Permissions Section

    private var permissionsSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Permissions", icon: "lock.shield")

            VStack(alignment: .leading, spacing: 12) {
                // Full Disk Access
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Full Disk Access")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundColor(.white)

                        Text("Required for Endpoint Security process monitoring")
                            .font(.system(size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    fullDiskAccessStatusBadge

                    if !extensionManager.hasFullDiskAccess {
                        Button(action: { extensionManager.openFullDiskAccessSettings() }) {
                            Text("Grant Access")
                                .font(.system(size: 12))
                        }
                        .buttonStyle(.bordered)
                    }
                }

                if !extensionManager.hasFullDiskAccess {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundColor(.blue)
                            .font(.system(size: 12))

                        Text("Add the Iris Security Extension to Full Disk Access in System Settings > Privacy & Security")
                            .font(.system(size: 11))
                            .foregroundColor(.gray)
                    }
                    .padding(12)
                    .background(Color.blue.opacity(0.1))
                    .cornerRadius(8)
                }
            }
            .padding(16)
            .background(Color.white.opacity(0.05))
            .cornerRadius(12)
        }
    }

    private var fullDiskAccessStatusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(extensionManager.hasFullDiskAccess ? Color.green : Color.orange)
                .frame(width: 8, height: 8)

            Text(extensionManager.hasFullDiskAccess ? "Granted" : "Not Granted")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.gray)
        }
    }

    // MARK: - Helper Views

    private func sectionHeader(title: String, icon: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(Color(red: 0.4, green: 0.6, blue: 1.0))

            Text(title)
                .font(.system(size: 18, weight: .semibold))
                .foregroundColor(.white)
        }
    }

    private func errorView(error: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                Text("Error")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.red)
            }

            ScrollView {
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
}

#Preview {
    SettingsView()
        .frame(width: 600, height: 700)
}
