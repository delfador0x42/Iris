import SwiftUI
import AppKit

// MARK: - Pointer Cursor Modifier

extension View {
    func pointerCursor() -> some View {
        self.onHover { inside in
            if inside {
                NSCursor.pointingHand.set()
            } else {
                NSCursor.arrow.set()
            }
        }
    }
}

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
    @State private var conversationConnection: NetworkConnection?

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
        .overlay {
            if let conn = conversationConnection {
                ZStack {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture { conversationConnection = nil }

                    ConnectionConversationView(
                        connection: conn,
                        onDismiss: { conversationConnection = nil }
                    )
                    .frame(width: 800, height: 600)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .shadow(color: .black.opacity(0.5), radius: 20)
                }
                .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: conversationConnection != nil)
        .environmentObject(store)
        .onAppear {
            // Set callback for when extension becomes ready (after user approval)
            extensionManager.onNetworkExtensionReady = { [weak store] in
                store?.connect()
                store?.startMonitoring()
            }

            Task {
                // Check if extension is already installed
                await extensionManager.checkNetworkExtensionStatus()
                // If installed, connect and start polling
                if extensionManager.networkExtensionState == .installed {
                    store.connect()
                    store.startMonitoring()
                }
            }
        }
        .onDisappear {
            store.stopMonitoring()
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
                        },
                        onViewTraffic: { connection in
                            conversationConnection = connection
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

// MARK: - Preview

#Preview {
    NetworkMonitorView()
        .frame(width: 900, height: 600)
}
