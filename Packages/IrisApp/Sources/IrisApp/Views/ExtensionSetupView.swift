import SwiftUI

/// Blocking setup screen shown until all system extensions are installed
struct ExtensionSetupView: View {
    @ObservedObject var extensionManager = ExtensionManager.shared
    @State private var isChecking = false
    @State private var pollTimer: Timer?

    private var readyCount: Int {
        ExtensionType.allCases.filter { extensionManager.state(for: $0).isReady }.count
    }

    var body: some View {
        ZStack {
            background

            VStack(spacing: 32) {
                header
                progressBar
                extensionList
                footerActions
            }
            .padding(40)
            .frame(maxWidth: 600)
        }
        .onAppear { startPolling() }
        .onDisappear { stopPolling() }
    }

    // MARK: - Polling

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            Task { @MainActor in
                await extensionManager.checkAllExtensionStatuses()
            }
        }
        // Initial check
        Task {
            isChecking = true
            await extensionManager.checkAllExtensionStatuses()
            isChecking = false
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    // MARK: - Views

    private var background: some View {
        LinearGradient(
            colors: [
                Color(red: 0.02, green: 0.03, blue: 0.05),
                Color(red: 0.05, green: 0.07, blue: 0.1)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
    }

    private var header: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundColor(Color(red: 0.4, green: 0.6, blue: 1.0))

            Text("System Extensions Required")
                .font(.system(size: 28, weight: .bold, design: .serif))
                .foregroundColor(.white)

            Text("Iris requires all system extensions to be installed and approved before monitoring can begin.")
                .font(.system(size: 14))
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
        }
    }

    private var progressBar: some View {
        VStack(spacing: 6) {
            HStack {
                Text("\(readyCount) of \(ExtensionType.allCases.count) extensions ready")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.gray)
                Spacer()
            }
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.white.opacity(0.1))
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.green)
                        .frame(width: geo.size.width * CGFloat(readyCount) / CGFloat(ExtensionType.allCases.count))
                        .animation(.easeInOut(duration: 0.3), value: readyCount)
                }
            }
            .frame(height: 6)
        }
    }

    private var extensionList: some View {
        VStack(spacing: 12) {
            ForEach(ExtensionType.allCases, id: \.bundleIdentifier) { type in
                extensionRow(type)
            }
        }
    }

    private func extensionRow(_ type: ExtensionType) -> some View {
        let state = extensionManager.state(for: type)

        return HStack(spacing: 16) {
            statusIcon(for: state)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(type.displayName)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(.white)
                Text(type.description)
                    .font(.system(size: 11))
                    .foregroundColor(.gray)
                if case .failed(let reason) = state {
                    Text(reason)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.red.opacity(0.8))
                        .lineLimit(2)
                }
            }

            Spacer()

            extensionAction(type: type, state: state)
        }
        .padding(16)
        .background(Color.white.opacity(0.05))
        .cornerRadius(10)
    }

    @ViewBuilder
    private func statusIcon(for state: ExtensionState) -> some View {
        switch state {
        case .installed:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 20))
                .foregroundColor(.green)
        case .installing:
            ProgressView()
                .scaleEffect(0.7)
                .tint(.yellow)
        case .needsUserApproval:
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 20))
                .foregroundColor(.orange)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: 20))
                .foregroundColor(.red)
        default:
            Image(systemName: "circle.dashed")
                .font(.system(size: 20))
                .foregroundColor(.gray)
        }
    }

    @ViewBuilder
    private func extensionAction(type: ExtensionType, state: ExtensionState) -> some View {
        switch state {
        case .notInstalled, .unknown:
            Button("Install") {
                extensionManager.installExtension(type)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)

        case .installing:
            Text("Installing...")
                .font(.system(size: 12))
                .foregroundColor(.yellow)

        case .needsUserApproval:
            Button("Open Settings") {
                extensionManager.openSystemSettings()
            }
            .buttonStyle(.bordered)
            .tint(.orange)
            .controlSize(.small)

        case .installed:
            Text("Ready")
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(.green)

        case .failed:
            Button("Retry") {
                extensionManager.installExtension(type)
            }
            .buttonStyle(.bordered)
            .tint(.orange)
            .controlSize(.small)
        }
    }

    private var footerActions: some View {
        VStack(spacing: 16) {
            if !extensionManager.areAllExtensionsReady {
                Button(action: {
                    extensionManager.installAllExtensions()
                }) {
                    HStack {
                        Image(systemName: "arrow.down.circle.fill")
                        Text("Install All Extensions")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(isInstalling)
            }

            Button(action: {
                Task {
                    isChecking = true
                    await extensionManager.checkAllExtensionStatuses()
                    isChecking = false
                }
            }) {
                HStack {
                    if isChecking {
                        ProgressView()
                            .scaleEffect(0.7)
                            .tint(.white)
                    }
                    Image(systemName: "arrow.clockwise")
                    Text("Refresh Status")
                }
            }
            .buttonStyle(.bordered)
            .tint(.gray)
            .disabled(isChecking)

            Text("Extensions require approval in System Settings > Privacy & Security")
                .font(.system(size: 11))
                .foregroundColor(.gray.opacity(0.6))
        }
    }

    private var isInstalling: Bool {
        ExtensionType.allCases.contains { type in
            extensionManager.state(for: type) == .installing
        }
    }
}
