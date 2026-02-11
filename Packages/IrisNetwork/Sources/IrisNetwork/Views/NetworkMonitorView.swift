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
    case rules = "Rules"

    var icon: String {
        switch self {
        case .list: return "list.bullet"
        case .map: return "globe"
        case .rules: return "shield.lefthalf.filled"
        }
    }
}

/// Main view for network monitoring - displays per-process connections
public struct NetworkMonitorView: View {
    @StateObject var store = SecurityStore()
    @StateObject var extensionManager = ExtensionManager.shared
    @State var expandedProcesses: Set<String> = []
    @State var viewMode: NetworkViewMode = .list
    @State var conversationConnection: NetworkConnection?

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
                    // Show list, map, or rules based on view mode
                    switch viewMode {
                    case .list:
                        connectionListView
                    case .map:
                        WorldMapView(store: store)
                    case .rules:
                        RulesListView()
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
                        connections: store.connectionsByProcess[process.identityKey] ?? [],
                        isExpanded: expandedProcesses.contains(process.identityKey),
                        onToggle: {
                            toggleProcess(process.identityKey)
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

    private func toggleProcess(_ identityKey: String) {
        withAnimation(.easeInOut(duration: 0.2)) {
            if expandedProcesses.contains(identityKey) {
                expandedProcesses.remove(identityKey)
            } else {
                expandedProcesses.insert(identityKey)
            }
        }
    }
}

// MARK: - Preview

#Preview {
    NetworkMonitorView()
        .frame(width: 900, height: 600)
}
