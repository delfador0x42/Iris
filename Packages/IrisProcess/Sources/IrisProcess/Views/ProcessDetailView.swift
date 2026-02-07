import SwiftUI

/// Detail view for a single process showing all information
struct ProcessDetailView: View {
    let process: ProcessInfo
    @Environment(\.dismiss) private var dismiss
    @State private var manPageContent: String?
    @State private var isLoadingManPage = false
    @State private var showManPage = false

    var body: some View {
        ZStack {
            // Background
            Color(red: 0.05, green: 0.07, blue: 0.1)
                .ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
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

                        Button("Close") { dismiss() }
                            .foregroundColor(.blue)
                    }
                    .padding(.bottom, 10)

                    // Basic info
                    DetailSection(title: "Process Information") {
                        DetailRow(label: "Name", value: process.name)
                        DetailRow(label: "PID", value: "\(process.pid)")
                        DetailRow(label: "Parent PID", value: "\(process.ppid)")
                        DetailRow(label: "Path", value: process.path)
                        DetailRow(label: "User ID", value: "\(process.userId)")
                        DetailRow(label: "Group ID", value: "\(process.groupId)")
                        DetailRow(label: "Has Man Page", value: manPageStatusText)
                    }

                    // Resource metrics
                    if let res = process.resources {
                        DetailSection(title: "Resources") {
                            DetailRow(label: "CPU Usage", value: res.formattedCPU)
                            DetailRow(label: "Memory (RSS)", value: res.formattedMemory)
                            DetailRow(label: "Threads", value: "\(res.threadCount)")
                            DetailRow(label: "Open Files", value: "\(res.openFileCount)")
                        }
                    }

                    // Code signing
                    if let csInfo = process.codeSigningInfo {
                        DetailSection(title: "Code Signing") {
                            DetailRow(label: "Status", value: csInfo.signerDescription)
                            DetailRow(label: "Team ID", value: csInfo.teamId ?? "None")
                            DetailRow(label: "Signing ID", value: csInfo.signingId ?? "None")
                            DetailRow(label: "Platform Binary", value: csInfo.isPlatformBinary ? "Yes" : "No")
                            DetailRow(label: "Apple Signed", value: csInfo.isAppleSigned ? "Yes" : "No")
                            DetailRow(label: "Flags", value: "0x\(String(csInfo.flags, radix: 16))")
                        }
                    }

                    // Suspicion reasons
                    if !process.suspicionReasons.isEmpty {
                        DetailSection(title: "Suspicion Indicators") {
                            ForEach(process.suspicionReasons, id: \.self) { reason in
                                HStack {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(severityColor(reason.severity))
                                    Text(reason.description)
                                        .foregroundColor(.white)
                                    Spacer()
                                    Text(reason.severity.label)
                                        .foregroundColor(severityColor(reason.severity))
                                        .font(.caption)
                                        .padding(.horizontal, 8)
                                        .padding(.vertical, 2)
                                        .background(severityColor(reason.severity).opacity(0.2))
                                        .cornerRadius(4)
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }

                    // Arguments
                    if !process.arguments.isEmpty {
                        DetailSection(title: "Arguments") {
                            ForEach(process.arguments.indices, id: \.self) { index in
                                Text(process.arguments[index])
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(.gray)
                            }
                        }
                    }

                    // Man Page Section
                    manPageSection
                }
                .padding(24)
            }
        }
        .frame(width: 600, height: 700)
        .task {
            await loadManPage()
        }
    }

    private var manPageStatusText: String {
        if isLoadingManPage {
            return "Checking..."
        } else if manPageContent != nil {
            return "Yes"
        } else if process.hasManPage == false {
            return "No"
        } else {
            return "Unknown"
        }
    }

    @ViewBuilder
    private var manPageSection: some View {
        if isLoadingManPage {
            DetailSection(title: "Man Page") {
                HStack {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("Loading man page...")
                        .foregroundColor(.gray)
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
                    ScrollView {
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
        } else if process.hasManPage == false {
            DetailSection(title: "Man Page") {
                HStack {
                    Image(systemName: "doc.questionmark")
                        .foregroundColor(.orange)
                    Text("No man page available for this command")
                        .foregroundColor(.gray)
                        .font(.system(size: 12))
                }
            }
        }
    }

    private func loadManPage() async {
        isLoadingManPage = true
        manPageContent = await ManPageStore.shared.getManPage(for: process.name)
        isLoadingManPage = false
    }

    private func severityColor(_ severity: SuspicionSeverity) -> Color {
        switch severity {
        case .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        }
    }
}
