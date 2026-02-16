import SwiftUI

/// Main view for disk usage visualization
public struct DiskUsageView: View {
    @StateObject private var store = DiskUsageStore()
    @Environment(\.dismiss) private var dismiss

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
                DiskUsageHeaderView(store: store)

                // Content based on state
                contentView
            }
        }
        .onAppear {
            // Try to load cached results first
            store.loadCachedResults()
        }
        .onDisappear {
            store.cancelScan()
        }
    }

    @ViewBuilder
    private var contentView: some View {
        switch store.scanState {
        case .idle:
            idleView

        case .loading:
            loadingView

        case .scanning(let progress):
            scanningView(progress: progress)

        case .completed, .cached:
            if let root = store.rootNode {
                DiskTreeView(root: root, store: store)
            }

        case .error(let error):
            errorView(error: error)

        case .cancelled:
            cancelledView
        }
    }

    private var idleView: some View {
        VStack(spacing: 16) {
            Image(systemName: "internaldrive")
                .font(.system(size: 48))
                .foregroundColor(.gray)

            Text("No scan data available")
                .font(.headline)
                .foregroundColor(.white)

            Text("Scan your disk to see usage breakdown")
                .font(.system(size: 14))
                .foregroundColor(.gray)

            Button("Start Scan") {
                store.startScan()
            }
            .buttonStyle(.borderedProminent)
            .padding(.top, 8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.2)
                .tint(.white)

            Text("Loading cached results...")
                .font(.system(size: 14))
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func scanningView(progress: ScanProgress) -> some View {
        VStack(spacing: 24) {
            ProgressView()
                .scaleEffect(1.5)
                .tint(.white)

            Text("Scanning filesystem...")
                .font(.headline)
                .foregroundColor(.white)

            VStack(spacing: 8) {
                Text(progress.currentPath)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.gray)
                    .lineLimit(1)
                    .truncationMode(.middle)

                Text("\(progress.filesScanned) files, \(ByteFormatter.format(progress.totalSizeScanned, style: .abbreviated))")
                    .font(.system(size: 14))
                    .foregroundColor(.white)
            }

            Button("Cancel") {
                store.cancelScan()
            }
            .buttonStyle(.bordered)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorView(error: DiskScanError) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48))
                .foregroundColor(.yellow)

            Text("Scan Error")
                .font(.headline)
                .foregroundColor(.white)

            Text(error.localizedDescription)
                .font(.system(size: 14))
                .foregroundColor(.gray)

            if let suggestion = error.recoverySuggestion {
                Text(suggestion)
                    .font(.system(size: 12))
                    .foregroundColor(.gray)
                    .multilineTextAlignment(.center)
            }

            Button("Retry") {
                store.startScan()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var cancelledView: some View {
        VStack(spacing: 16) {
            Text("Scan cancelled")
                .foregroundColor(.gray)

            Button("Start New Scan") {
                store.startScan()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

#Preview {
    DiskUsageView()
        .frame(width: 800, height: 600)
}
