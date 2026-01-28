import SwiftUI

/// Main view for process list - displays all running processes with suspicious highlighting
public struct ProcessListView: View {
    @StateObject private var store = ProcessStore()
    @State private var selectedProcess: ProcessInfo?
    @State private var showingDetail = false
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
                ProcessListHeaderView(store: store)

                // Toolbar
                ProcessListToolbar(store: store)

                // Content
                if store.isLoading && store.processes.isEmpty {
                    loadingView
                } else if store.displayedProcesses.isEmpty {
                    emptyView
                } else {
                    processListView
                }
            }
        }
        .onAppear {
            store.startAutoRefresh()
        }
        .onDisappear {
            store.stopAutoRefresh()
        }
        .sheet(isPresented: $showingDetail) {
            if let process = selectedProcess {
                ProcessDetailView(process: process)
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button(action: { dismiss() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left")
                        Text("Back")
                    }
                    .foregroundColor(Color(red: 0.4, green: 0.7, blue: 1.0))
                }
            }
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

            Text("USER")
                .frame(width: 100, alignment: .leading)

            Text("SIGNING")
                .frame(width: 140, alignment: .leading)

            Text("PATH")
                .frame(width: 250, alignment: .leading)
        }
        .font(.system(size: 11, weight: .medium, design: .monospaced))
        .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))
        .padding(.vertical, 8)
    }
}

// MARK: - Process Row

struct ProcessRow: View {
    let process: ProcessInfo
    let onSelect: () -> Void
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 0) {
            // PID
            Text("\(process.pid)")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(rowColor)
                .frame(width: 70, alignment: .leading)

            // Process name with icon
            HStack(spacing: 8) {
                // Suspicious indicator
                if process.isSuspicious {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 12))
                }

                Text(process.displayName)
                    .font(.system(size: 13, weight: process.isSuspicious ? .semibold : .regular, design: .monospaced))
                    .foregroundColor(rowColor)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // User
            Text(ProcessStore.username(forUID: process.userId))
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(rowColor)
                .frame(width: 100, alignment: .leading)

            // Signing status
            Text(signingStatus)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(signingColor)
                .frame(width: 140, alignment: .leading)

            // Path (truncated)
            Text(process.path)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray.opacity(0.7))
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(width: 250, alignment: .leading)
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 4)
        .contentShape(Rectangle())
        .background(backgroundColor)
        .onTapGesture {
            onSelect()
        }
        .onHover { hovering in
            isHovered = hovering
        }
    }

    private var backgroundColor: Color {
        if process.isSuspicious {
            return Color.red.opacity(isHovered ? 0.15 : 0.08)
        } else if isHovered {
            return Color.white.opacity(0.05)
        }
        return Color.clear
    }

    private var rowColor: Color {
        process.isSuspicious ? .red : .white
    }

    private var signingStatus: String {
        process.codeSigningInfo?.signerDescription ?? "Unknown"
    }

    private var signingColor: Color {
        guard let csInfo = process.codeSigningInfo else {
            return .orange
        }

        if csInfo.isPlatformBinary {
            return .green
        } else if csInfo.isAppleSigned {
            return .green.opacity(0.8)
        } else if csInfo.teamId != nil {
            return .blue
        } else if csInfo.signingId != nil {
            return .orange  // Ad-hoc
        } else {
            return .red  // Unsigned
        }
    }
}

// MARK: - Header View

struct ProcessListHeaderView: View {
    @ObservedObject var store: ProcessStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Title row
            HStack {
                Text("Process List")
                    .font(.system(size: 24, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                Spacer()

                // Refresh button
                Button(action: {
                    Task {
                        await store.refreshProcesses()
                    }
                }) {
                    Image(systemName: "arrow.clockwise")
                        .foregroundColor(.white)
                        .opacity(store.isLoading ? 0.5 : 1.0)
                }
                .buttonStyle(.plain)
                .disabled(store.isLoading)
            }

            // Stats row
            HStack(spacing: 24) {
                ProcessStatBox(
                    label: "Total Processes",
                    value: "\(store.totalCount)",
                    color: .white
                )

                ProcessStatBox(
                    label: "Suspicious",
                    value: "\(store.suspiciousCount)",
                    color: store.suspiciousCount > 0 ? .red : .green
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

// MARK: - Process Stat Box

struct ProcessStatBox: View {
    let label: String
    let value: String
    let color: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 10))
                .foregroundColor(.gray.opacity(0.7))
            Text(value)
                .font(.system(size: 18, weight: .bold, design: .monospaced))
                .foregroundColor(color)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.white.opacity(0.05))
        .cornerRadius(8)
    }
}

// MARK: - Toolbar

struct ProcessListToolbar: View {
    @ObservedObject var store: ProcessStore

    var body: some View {
        HStack(spacing: 16) {
            // Search field
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)

                TextField("Search processes...", text: $store.filterText)
                    .textFieldStyle(.plain)
                    .foregroundColor(.white)

                if !store.filterText.isEmpty {
                    Button(action: { store.filterText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.gray)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(8)
            .background(Color.white.opacity(0.1))
            .cornerRadius(8)
            .frame(maxWidth: 300)

            // Suspicious filter toggle
            Button(action: {
                store.showOnlySuspicious.toggle()
            }) {
                HStack(spacing: 4) {
                    Image(systemName: "exclamationmark.triangle")
                    Text("Suspicious Only")
                }
                .font(.system(size: 12))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(store.showOnlySuspicious ? Color.red.opacity(0.3) : Color.white.opacity(0.1))
                .foregroundColor(store.showOnlySuspicious ? .red : .white)
                .cornerRadius(6)
            }
            .buttonStyle(.plain)

            Spacer()

            // Sort picker
            HStack(spacing: 8) {
                Text("Sort:")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)

                Picker("", selection: $store.sortOrder) {
                    ForEach(ProcessStore.SortOrder.allCases, id: \.self) { order in
                        Text(order.rawValue).tag(order)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 120)
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(Color.black.opacity(0.2))
    }
}

// MARK: - Process Detail View

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

// MARK: - Detail Section

struct DetailSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))

            VStack(alignment: .leading, spacing: 8) {
                content()
            }
            .padding(12)
            .background(Color.white.opacity(0.05))
            .cornerRadius(8)
        }
    }
}

// MARK: - Detail Row

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .foregroundColor(.gray)
                .frame(width: 120, alignment: .leading)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white)
                .textSelection(.enabled)
            Spacer()
        }
    }
}

#Preview {
    ProcessListView()
        .frame(width: 1200, height: 800)
}
