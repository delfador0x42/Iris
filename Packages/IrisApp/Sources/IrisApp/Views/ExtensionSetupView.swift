import SwiftUI

/// Two-step sequential wizard for installing system extensions.
/// Step 1: Process Monitor (Endpoint Security)
/// Step 2: Network Monitor (Transparent Proxy + DNS + Firewall)
/// Auto-advances when each extension is approved.
struct ExtensionSetupView: View {
    @ObservedObject var extensionManager = ExtensionManager.shared
    @State private var isChecking = false
    @State private var pollTimer: Timer?
    @State private var currentStep: ExtensionType = .endpoint

    private var allReady: Bool { extensionManager.areAllExtensionsReady }

    var body: some View {
        ZStack {
            background

            VStack(spacing: 32) {
                header
                stepIndicator
                stepContent
                footerHint
            }
            .padding(40)
            .frame(maxWidth: 600)
        }
        .onAppear { startPolling() }
        .onDisappear { stopPolling() }
        .onChange(of: extensionManager.endpointExtensionState) { newState in
            if newState.isReady && currentStep == .endpoint {
                withAnimation(.easeInOut(duration: 0.4)) {
                    currentStep = .network
                }
            }
        }
    }

    // MARK: - Polling

    private func startPolling() {
        pollTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            Task { @MainActor in
                await extensionManager.checkAllExtensionStatuses()
            }
        }
        Task {
            isChecking = true
            await extensionManager.checkAllExtensionStatuses()
            isChecking = false
            // If endpoint already installed, jump to step 2
            if extensionManager.endpointExtensionState.isReady {
                currentStep = .network
            }
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

            Text("Set Up Iris")
                .font(.system(size: 28, weight: .bold, design: .serif))
                .foregroundColor(.white)

            Text("Two extensions need to be installed for full protection.")
                .font(.system(size: 14))
                .foregroundColor(.gray)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 400)
        }
    }

    private var stepIndicator: some View {
        HStack(spacing: 0) {
            stepDot(step: .endpoint, label: "1")
            stepLine(completed: extensionManager.endpointExtensionState.isReady)
            stepDot(step: .network, label: "2")
        }
        .frame(maxWidth: 200)
    }

    private func stepDot(step: ExtensionType, label: String) -> some View {
        let state = extensionManager.state(for: step)
        let isActive = currentStep == step
        let isComplete = state.isReady

        return ZStack {
            Circle()
                .fill(isComplete ? Color.green : isActive ? Color(red: 0.4, green: 0.6, blue: 1.0) : Color.white.opacity(0.2))
                .frame(width: 32, height: 32)

            if isComplete {
                Image(systemName: "checkmark")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(.white)
            } else {
                Text(label)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(isActive ? .white : .gray)
            }
        }
    }

    private func stepLine(completed: Bool) -> some View {
        Rectangle()
            .fill(completed ? Color.green : Color.white.opacity(0.15))
            .frame(height: 2)
            .animation(.easeInOut(duration: 0.3), value: completed)
    }

    @ViewBuilder
    private var stepContent: some View {
        let type = currentStep
        let state = extensionManager.state(for: type)

        VStack(spacing: 20) {
            // Icon
            Image(systemName: type == .endpoint ? "cpu" : "network")
                .font(.system(size: 36))
                .foregroundColor(Color(red: 0.4, green: 0.6, blue: 1.0))

            // Title and description
            VStack(spacing: 6) {
                Text(stepTitle)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundColor(.white)

                Text(type.description)
                    .font(.system(size: 13))
                    .foregroundColor(.gray)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 350)
            }

            // Error display
            if case .failed(let reason) = state {
                Text(reason)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.red.opacity(0.8))
                    .lineLimit(3)
                    .padding(8)
                    .background(Color.red.opacity(0.1))
                    .cornerRadius(6)
            }

            // Action
            stepAction(type: type, state: state)
        }
        .padding(24)
        .background(Color.white.opacity(0.05))
        .cornerRadius(14)
        .transition(.asymmetric(
            insertion: .move(edge: .trailing).combined(with: .opacity),
            removal: .move(edge: .leading).combined(with: .opacity)
        ))
        .id(currentStep)  // force transition on step change
    }

    private var stepTitle: String {
        let stepNum = currentStep == .endpoint ? 1 : 2
        return "Step \(stepNum): \(currentStep.displayName)"
    }

    @ViewBuilder
    private func stepAction(type: ExtensionType, state: ExtensionState) -> some View {
        switch state {
        case .notInstalled, .unknown:
            Button(action: { extensionManager.installExtension(type) }) {
                HStack {
                    Image(systemName: "arrow.down.circle.fill")
                    Text("Enable \(type.displayName)")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

        case .installing:
            HStack(spacing: 8) {
                ProgressView()
                    .scaleEffect(0.8)
                    .tint(.yellow)
                Text("Installing...")
                    .font(.system(size: 14))
                    .foregroundColor(.yellow)
            }

        case .needsUserApproval:
            VStack(spacing: 10) {
                Text("Approval required in System Settings")
                    .font(.system(size: 13))
                    .foregroundColor(.orange)

                Button(action: { extensionManager.openSystemSettings() }) {
                    HStack {
                        Image(systemName: "gear")
                        Text("Open System Settings")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
                .controlSize(.large)
            }

        case .installed:
            HStack(spacing: 6) {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
                Text("Ready")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.green)
            }

        case .failed:
            Button(action: { extensionManager.installExtension(type) }) {
                HStack {
                    Image(systemName: "arrow.counterclockwise")
                    Text("Retry")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.orange)
            .controlSize(.large)
        }
    }

    private var footerHint: some View {
        VStack(spacing: 8) {
            if isChecking {
                HStack(spacing: 6) {
                    ProgressView()
                        .scaleEffect(0.6)
                        .tint(.gray)
                    Text("Checking status...")
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                }
            }

            Text("Extensions require approval in System Settings > Privacy & Security")
                .font(.system(size: 11))
                .foregroundColor(.gray.opacity(0.6))
        }
    }
}
