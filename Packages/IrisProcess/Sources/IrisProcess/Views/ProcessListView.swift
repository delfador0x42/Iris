import SwiftUI

/// Main container for process monitoring — switches between Monitor and History views
public struct ProcessListView: View {
    @ObservedObject private var store = ProcessStore.shared
    @State private var selectedProcess: ProcessInfo?
    @State private var showingDetail = false

    public init() {}

    public var body: some View {
        ZStack {
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
                ProcessListHeaderView(store: store)
                ProcessListToolbar(store: store)

                // Content — switches on view mode
                if store.isLoading && store.processes.isEmpty {
                    loadingView
                } else {
                    switch store.viewMode {
                    case .monitor:
                        ProcessMonitorView(onSelect: selectProcess)
                    case .history:
                        ProcessHistoryView(store: store, onSelect: selectProcess)
                    }
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
        .onAppear { store.startAutoRefresh() }
        .onDisappear { store.stopAutoRefresh() }
    }

    private func selectProcess(_ process: ProcessInfo) {
        selectedProcess = process
        showingDetail = true
    }

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
}

#Preview {
    ProcessListView()
        .frame(width: 1200, height: 800)
}
