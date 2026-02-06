import SwiftUI

/// View mode for network monitor
public enum NetworkViewMode: String, CaseIterable {
    case list = "List"
    case map = "Map"

    var icon: String {
        switch self {
        case .list: return "list.bullet"
        case .map: return "globe"
        }
    }
}

/// Main view for network monitoring - displays per-process connections
public struct NetworkMonitorView: View {
    @StateObject private var store = SecurityStore()
    @StateObject private var extensionManager = ExtensionManager.shared
    @State private var expandedProcesses: Set<Int32> = []
    @State private var viewMode: NetworkViewMode = .list

    public init() {}

    public var body: some View {
        ZStack {
            // Background gradient matching app style
            LinearGradient(
                colors: [
                    Color(red: 0.02, green: 0.03, blue: 0.05),
                    Color(red: 0.05, green: 0.07, blue: 0.1)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                // Header
                NetworkMonitorHeaderView(
                    store: store,
                    extensionManager: extensionManager,
                    viewMode: $viewMode
                )

                // Content based on state
                if extensionManager.networkExtensionState != .installed {
                    extensionSetupView
                } else if !store.isConnected {
                    connectingView
                } else if store.connections.isEmpty {
                    emptyView
                } else {
                    // Show list or map based on view mode
                    switch viewMode {
                    case .list:
                        connectionListView
                    case .map:
                        WorldMapView(store: store)
                    }
                }
            }
        }
        .onAppear {
            // Set callback for when extension becomes ready (after user approval)
            extensionManager.onNetworkExtensionReady = { [weak store] in
                store?.connect()
            }

            Task {
                // Check if extension is already installed
                await extensionManager.checkNetworkExtensionStatus()
                // If installed, connect automatically
                if extensionManager.networkExtensionState == .installed {
                    store.connect()
                }
            }
        }
        .onDisappear {
            store.disconnect()
            extensionManager.onNetworkExtensionReady = nil
        }
    }

    // MARK: - Extension Setup View

    private var extensionSetupView: some View {
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

    private var extensionStatusView: some View {
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

    private var extensionStatusColor: Color {
        switch extensionManager.networkExtensionState {
        case .installed: return .green
        case .installing: return .yellow
        case .needsUserApproval: return .orange
        case .failed: return .red
        default: return .gray
        }
    }

    // MARK: - Connecting View

    private var connectingView: some View {
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

    private var emptyView: some View {
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

    // MARK: - Connection List View

    private var connectionListView: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                // Column headers
                connectionHeaderRow

                Divider()
                    .background(Color.gray.opacity(0.3))

                // Process rows
                ForEach(store.processes) { process in
                    ProcessConnectionRow(
                        process: process,
                        connections: store.connectionsByProcess[process.pid] ?? [],
                        isExpanded: expandedProcesses.contains(process.pid),
                        onToggle: {
                            toggleProcess(process.pid)
                        }
                    )
                }
            }
            .padding()
        }
    }

    private var connectionHeaderRow: some View {
        HStack(spacing: 0) {
            Text("Process / Connection")
                .frame(maxWidth: .infinity, alignment: .leading)

            Text("Protocol")
                .frame(width: 60)

            Text("Interface")
                .frame(width: 70)

            Text("State")
                .frame(width: 90)

            Text("Bytes Up")
                .frame(width: 80, alignment: .trailing)

            Text("Bytes Down")
                .frame(width: 80, alignment: .trailing)
        }
        .font(.system(size: 11, weight: .medium))
        .foregroundColor(.gray)
        .padding(.vertical, 8)
    }

    private func toggleProcess(_ pid: Int32) {
        withAnimation(.easeInOut(duration: 0.2)) {
            if expandedProcesses.contains(pid) {
                expandedProcesses.remove(pid)
            } else {
                expandedProcesses.insert(pid)
            }
        }
    }
}

// MARK: - Process Connection Row

struct ProcessConnectionRow: View {
    let process: SecurityStore.ProcessSummary
    let connections: [NetworkConnection]
    let isExpanded: Bool
    let onToggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Process row
            HStack(spacing: 8) {
                // Expand indicator
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .font(.system(size: 10))
                    .foregroundColor(.gray)
                    .frame(width: 12)

                // Process icon (placeholder)
                Image(systemName: "app.fill")
                    .foregroundColor(.blue)
                    .frame(width: 20)

                // Process name and path
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(process.name) (pid: \(process.pid))")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.white)

                    Text(process.path)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.7))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                Spacer()

                // Total bytes
                Text(process.formattedBytesUp)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.gray)
                    .frame(width: 80, alignment: .trailing)

                Text(process.formattedBytesDown)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.gray)
                    .frame(width: 80, alignment: .trailing)
            }
            .padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture {
                onToggle()
            }

            // Connection rows (when expanded)
            if isExpanded {
                ForEach(connections) { connection in
                    ConnectionDetailRow(connection: connection)
                }
            }
        }
        .background(
            isExpanded ? Color.white.opacity(0.03) : Color.clear
        )
    }
}

// MARK: - Connection Detail Row

struct ConnectionDetailRow: View {
    let connection: NetworkConnection

    var body: some View {
        HStack(spacing: 0) {
            // Indent + connection info
            HStack(spacing: 8) {
                Spacer()
                    .frame(width: 40) // Indent

                Text(connection.connectionDescription)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.8))
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // Protocol
            Text(connection.protocol.rawValue)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 60)

            // Interface
            Text(connection.interface ?? "-")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 70)

            // State
            Text(connection.state.rawValue)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(stateColor)
                .frame(width: 90)

            // Bytes up
            Text(connection.formattedBytesUp)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 80, alignment: .trailing)

            // Bytes down
            Text(connection.formattedBytesDown)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray)
                .frame(width: 80, alignment: .trailing)
        }
        .padding(.vertical, 4)
    }

    private var stateColor: Color {
        switch connection.state {
        case .established: return .green
        case .listen: return .blue
        case .closed: return .gray
        default: return .orange
        }
    }
}

// MARK: - Header View

struct NetworkMonitorHeaderView: View {
    @ObservedObject var store: SecurityStore
    @ObservedObject var extensionManager: ExtensionManager
    @Binding var viewMode: NetworkViewMode

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Title row
            HStack {
                Text("Network Monitor")
                    .font(.system(size: 24, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                Spacer()

                // View mode picker
                Picker("View", selection: $viewMode) {
                    ForEach(NetworkViewMode.allCases, id: \.self) { mode in
                        Text(mode.rawValue)
                            .tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 140)

                Spacer()
                    .frame(width: 16)

                // Status indicator
                HStack(spacing: 6) {
                    Circle()
                        .fill(store.isConnected ? Color.green : Color.red)
                        .frame(width: 8, height: 8)

                    Text(store.isConnected ? "Connected" : "Disconnected")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
            }

            // Stats row
            HStack(spacing: 24) {
                // Connection count
                StatBox(
                    label: "Connections",
                    value: "\(store.connections.count)",
                    color: .white
                )

                // Processes
                StatBox(
                    label: "Processes",
                    value: "\(store.processes.count)",
                    color: .white
                )

                // Total up
                StatBox(
                    label: "Total Up",
                    value: NetworkConnection.formatBytes(store.totalBytesUp),
                    color: .orange
                )

                // Total down
                StatBox(
                    label: "Total Down",
                    value: NetworkConnection.formatBytes(store.totalBytesDown),
                    color: .green
                )

                Spacer()

                // Last update
                if let lastUpdate = store.lastUpdate {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Last update")
                            .font(.system(size: 10))
                            .foregroundColor(.gray.opacity(0.7))
                        Text(lastUpdate, style: .time)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }
            }
        }
        .padding(.vertical, 16)
        .padding(.horizontal, 20)
        .background(Color.black.opacity(0.3))
    }
}

struct StatBox: View {
    let label: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 10))
                .foregroundColor(.gray.opacity(0.7))
            Text(value)
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .foregroundColor(color)
        }
    }
}

// MARK: - Preview

#Preview {
    NetworkMonitorView()
        .frame(width: 900, height: 600)
}
