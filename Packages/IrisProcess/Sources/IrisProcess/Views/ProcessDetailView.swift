import SwiftUI

/// Detail view for a single process showing all information
struct ProcessDetailView: View {
    let process: ProcessInfo
    var onDismiss: () -> Void = {}
    @State private var manPageContent: String?
    @State private var isLoadingManPage = false
    @State private var showManPage = false
    @State private var binaryAnalysis: BinaryAnalysis?
    @State private var isAnalyzing = false
    @State private var analysisRequested = false

    var body: some View {
        ZStack {
            Color(red: 0.05, green: 0.07, blue: 0.1)
                .ignoresSafeArea()

            ThemedScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header
                    commandLineSection
                    processIdentity
                    processLineage
                    resourcesSection
                    alertsSection
                    binaryAnalysisSection
                    manPageSection
                }
                .padding(24)
            }
        }
        .task {
            await loadManPage()
            await runBinaryAnalysis()
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            if process.isSuspicious {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.red)
                    .font(.title2)
            }

            Text(process.displayName)
                .font(.system(size: 24, weight: .bold))
                .foregroundColor(process.isSuspicious ? .red : .white)

            Spacer()

            Button("Close") { onDismiss() }
                .foregroundColor(.blue)
        }
        .padding(.bottom, 4)
    }

    // MARK: - Command Line

    @ViewBuilder
    private var commandLineSection: some View {
        if !process.arguments.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text("COMMAND LINE")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyan.opacity(0.6))

                Text(formatCommandLine())
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Color.black.opacity(0.4))
                    .cornerRadius(6)
            }
        }
    }

    // MARK: - Process Identity

    private var processIdentity: some View {
        DetailSection(title: "Process") {
            DetailRow(label: "PID", value: "\(process.pid) (parent: \(process.ppid))")
            DetailRow(label: "Path", value: process.path)
            DetailRow(label: "User", value: userDescription)
            if let csInfo = process.codeSigningInfo {
                DetailRow(label: "Signing", value: signingOneLiner(csInfo))
            } else {
                DetailRow(label: "Signing", value: "Unsigned")
            }
        }
    }

    // MARK: - Resources

    @ViewBuilder
    private var resourcesSection: some View {
        if let res = process.resources {
            DetailSection(title: "Resources") {
                DetailRow(label: "CPU", value: res.formattedCPU)
                DetailRow(label: "Memory", value: res.formattedMemory)
                DetailRow(label: "Threads", value: String(res.threadCount))
                DetailRow(label: "Open Files", value: String(res.openFileCount))
            }
        }
    }

    // MARK: - Alerts

    @ViewBuilder
    private var alertsSection: some View {
        if !process.suspicionReasons.isEmpty {
            DetailSection(title: "Alerts") {
                ForEach(process.suspicionReasons, id: \.self) { reason in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(severityColor(reason.severity))
                            .frame(width: 6, height: 6)
                        Text(reason.description)
                            .font(.system(size: 12))
                            .foregroundColor(.white)
                    }
                    .padding(.vertical, 1)
                }
            }
        }
    }

    // MARK: - Binary Analysis

    @ViewBuilder
    private var binaryAnalysisSection: some View {
        if isAnalyzing {
            DetailSection(title: "Binary Analysis") {
                HStack {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("Analyzing binary...")
                        .foregroundColor(.gray)
                        .font(.system(size: 12))
                }
            }
        } else if let analysis = binaryAnalysis {
            BinaryAnalysisSection(analysis: analysis)
        }
    }

    // MARK: - Man Page

    @ViewBuilder
    private var manPageSection: some View {
        if isLoadingManPage {
            DetailSection(title: "Man Page") {
                HStack {
                    ProgressView().scaleEffect(0.8)
                    Text("Loading...").foregroundColor(.gray)
                }
            }
        } else if let content = manPageContent {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Man Page")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))
                    Spacer()
                    Button(action: { showManPage.toggle() }) {
                        HStack(spacing: 4) {
                            Text(showManPage ? "Hide" : "Show")
                            Image(systemName: showManPage ? "chevron.up" : "chevron.down")
                        }
                        .font(.system(size: 12))
                        .foregroundColor(.blue)
                    }
                    .buttonStyle(.plain)
                }

                if showManPage {
                    ThemedScrollView {
                        Text(content)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.gray)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 300)
                    .padding(12)
                    .background(Color.black.opacity(0.3))
                    .cornerRadius(8)
                }
            }
        }
    }

    // MARK: - Helpers

    private func formatCommandLine() -> String {
        process.arguments.map { arg in
            arg.contains(" ") || arg.contains("\"") ? "'\(arg)'" : arg
        }.joined(separator: " ")
    }

    private var userDescription: String {
        let uid = process.userId
        switch uid {
        case 0: return "root (0)"
        case 501: return "user (501)"
        default: return String(uid)
        }
    }

    private func signingOneLiner(_ cs: ProcessInfo.CodeSigningInfo) -> String {
        var parts = [cs.signerDescription]
        var flags: [String] = []
        if cs.isHardenedRuntime { flags.append("hardened") }
        if cs.isDebuggable { flags.append("debuggable") }
        if cs.isLinkerSigned { flags.append("linker-signed") }
        if !flags.isEmpty { parts.append("[\(flags.joined(separator: ", "))]") }
        return parts.joined(separator: " ")
    }

    private func loadManPage() async {
        isLoadingManPage = true
        manPageContent = await ManPageStore.shared.getManPage(for: process.name)
        isLoadingManPage = false
    }

    private func runBinaryAnalysis() async {
        guard !process.path.isEmpty else { return }
        isAnalyzing = true
        binaryAnalysis = await Task.detached {
            BinaryAnalysisEngine.analyzeOne(process.path)
        }.value
        isAnalyzing = false
    }
}
