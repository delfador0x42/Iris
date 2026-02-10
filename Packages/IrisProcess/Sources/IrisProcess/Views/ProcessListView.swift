import SwiftUI

/// Main view for process list - displays all running processes with suspicious highlighting
public struct ProcessListView: View {
    @ObservedObject private var store = ProcessStore.shared
    @State private var selectedProcess: ProcessInfo?
    @State private var showingDetail = false

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
                ProcessListHeaderView(store: store)

                // Toolbar
                ProcessListToolbar(store: store)

                // Content
                if store.isLoading && store.processes.isEmpty {
                    loadingView
                } else if store.displayedProcesses.isEmpty {
                    emptyView
                } else if store.viewMode == .tree {
                    ProcessTreeView(
                        processes: store.displayedProcesses,
                        onSelect: { process in
                            selectedProcess = process
                            showingDetail = true
                        }
                    )
                } else {
                    processListView
                }
            }
        }
        .overlay {
            if showingDetail, let process = selectedProcess {
                ZStack {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                        .onTapGesture { showingDetail = false }

                    ProcessDetailView(process: process, onDismiss: { showingDetail = false })
                        .frame(width: 600, height: 700)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .shadow(color: .black.opacity(0.5), radius: 20)
                }
                .transition(.opacity)
            }
        }
        .animation(.easeInOut(duration: 0.2), value: showingDetail)
        .onAppear {
            store.startAutoRefresh()
        }
        .onDisappear {
            store.stopAutoRefresh()
        }
    }

    // MARK: - Loading View

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.2)
                .tint(.white)

            Text("Loading processes...")
                .font(.system(size: 14))
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Empty View

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "list.bullet.rectangle")
                .font(.system(size: 48))
                .foregroundColor(.gray)

            Text("No processes found")
                .font(.headline)
                .foregroundColor(.white)

            if !store.filterText.isEmpty || store.showOnlySuspicious {
                Text("Try adjusting your filters")
                    .font(.system(size: 14))
                    .foregroundColor(.gray)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Process List View

    private var processListView: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                // Column headers
                processHeaderRow

                Divider()
                    .background(Color.gray.opacity(0.3))

                // Process rows
                ForEach(store.displayedProcesses) { process in
                    ProcessRow(
                        process: process,
                        onSelect: {
                            selectedProcess = process
                            showingDetail = true
                        }
                    )

                    Divider()
                        .background(Color.gray.opacity(0.15))
                }
            }
            .padding()
        }
    }

    private var processHeaderRow: some View {
        HStack(spacing: 0) {
            Text("PID")
                .frame(width: 70, alignment: .leading)

            Text("COMMAND")
                .frame(maxWidth: .infinity, alignment: .leading)

            Text("CPU")
                .frame(width: 70, alignment: .trailing)

            Text("MEM")
                .frame(width: 80, alignment: .trailing)

            Text("USER")
                .frame(width: 100, alignment: .leading)

            Text("SIGNING")
                .frame(width: 140, alignment: .leading)
        }
        .font(.system(size: 11, weight: .medium, design: .monospaced))
        .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))
        .padding(.vertical, 8)
    }
}

#Preview {
    ProcessListView()
        .frame(width: 1200, height: 800)
}
