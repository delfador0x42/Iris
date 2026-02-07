import SwiftUI

/// Filesystem integrity monitoring view.
/// Take a SHA-256 baseline of critical system paths, then diff to detect
/// unauthorized modifications — the IPSW diffing approach.
public struct FileIntegrityView: View {
    @State private var changes: [FileSystemChange] = []
    @State private var isScanning = false
    @State private var isTakingBaseline = false
    @State private var baselineExists = false
    @State private var baselineFileCount = 0
    @State private var scanPhase = ""
    @Environment(\.dismiss) private var dismiss

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                if isTakingBaseline {
                    baselineProgress
                } else if isScanning {
                    scanningProgress
                } else if !baselineExists {
                    noBaselineView
                } else if changes.isEmpty {
                    cleanView
                } else {
                    changesList
                }
            }
        }
        .task { await checkBaseline() }
        .toolbar {
            ToolbarItem(placement: .navigation) { backButton }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Filesystem Integrity")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                if baselineExists && !changes.isEmpty {
                    let critical = changes.filter { $0.severity == .critical }.count
                    Text("\(changes.count) changes (\(critical) critical)")
                        .font(.caption).foregroundColor(critical > 0 ? .red : .gray)
                } else if baselineExists {
                    Text("\(baselineFileCount) files baselined")
                        .font(.caption).foregroundColor(.gray)
                }
            }
            Spacer()
            if !isScanning && !isTakingBaseline {
                HStack(spacing: 12) {
                    Button("Baseline") { Task { await takeBaseline() } }
                        .buttonStyle(.plain).foregroundColor(.cyan)
                        .font(.system(size: 12, weight: .medium))
                    if baselineExists {
                        Button("Diff") { Task { await runDiff() } }
                            .buttonStyle(.plain).foregroundColor(.orange)
                            .font(.system(size: 12, weight: .medium))
                    }
                }
            }
        }.padding(20)
    }

    private var changesList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(changes) { change in
                    FSIntegrityRow(change: change)
                }
            }.padding(.vertical, 8)
        }
    }

    private var baselineProgress: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.cyan)
            Text("Taking filesystem baseline...")
                .font(.system(size: 14)).foregroundColor(.gray)
            Text("Hashing critical system directories")
                .font(.system(size: 11)).foregroundColor(.gray.opacity(0.7))
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var scanningProgress: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.orange)
            Text("Diffing filesystem against baseline...")
                .font(.system(size: 14)).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var noBaselineView: some View {
        VStack(spacing: 16) {
            Image(systemName: "externaldrive.badge.questionmark")
                .font(.system(size: 48)).foregroundColor(.gray)
            Text("No Baseline").font(.headline).foregroundColor(.white)
            Text("Take a baseline snapshot first, then diff later to detect changes.")
                .font(.caption).foregroundColor(.gray)
                .multilineTextAlignment(.center).frame(maxWidth: 300)
            Button("Take Baseline Now") { Task { await takeBaseline() } }
                .buttonStyle(.borderedProminent).tint(.cyan)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var cleanView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48)).foregroundColor(.green)
            Text("No changes detected").font(.headline).foregroundColor(.white)
            Text("Filesystem matches baseline")
                .font(.caption).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var darkBackground: some View {
        LinearGradient(
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }

    private var backButton: some View {
        Button(action: { dismiss() }) {
            HStack(spacing: 4) {
                Image(systemName: "chevron.left")
                Text("Back")
            }.foregroundColor(Color(red: 0.4, green: 0.7, blue: 1.0))
        }
    }

    private func checkBaseline() async {
        // Check if a baseline file exists
        let support = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/com.wudan.iris")
        let baselinePath = support.appendingPathComponent("fs_baseline.json")
        baselineExists = FileManager.default.fileExists(atPath: baselinePath.path)
    }

    private func takeBaseline() async {
        isTakingBaseline = true
        let count = await FileSystemBaseline.shared.takeBaseline()
        baselineFileCount = count
        baselineExists = true
        isTakingBaseline = false
    }

    private func runDiff() async {
        isScanning = true
        changes = await FileSystemBaseline.shared.diff()
        isScanning = false
    }
}

struct FSIntegrityRow: View {
    let change: FileSystemChange
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                changeTypeIcon
                VStack(alignment: .leading, spacing: 2) {
                    Text(URL(fileURLWithPath: change.path).lastPathComponent)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(change.changeType.rawValue)
                        .font(.system(size: 10)).foregroundColor(changeColor)
                }
                Spacer()
                SeverityBadge(severity: change.severity)
                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .foregroundColor(.gray).font(.system(size: 10))
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(change.path)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                    Text(change.details)
                        .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    if let oldHash = change.oldHash, let newHash = change.newHash {
                        Text("Old: \(oldHash.prefix(32))...")
                            .font(.system(size: 9, design: .monospaced)).foregroundColor(.red.opacity(0.7))
                        Text("New: \(newHash.prefix(32))...")
                            .font(.system(size: 9, design: .monospaced)).foregroundColor(.green.opacity(0.7))
                    }
                }
                .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(rowBackground)
    }

    private var changeTypeIcon: some View {
        Image(systemName: iconName)
            .font(.system(size: 14))
            .foregroundColor(changeColor)
            .frame(width: 24)
    }

    private var iconName: String {
        switch change.changeType {
        case .created: return "plus.circle.fill"
        case .modified: return "pencil.circle.fill"
        case .deleted: return "trash.circle.fill"
        case .permissionsChanged: return "lock.circle.fill"
        }
    }

    private var changeColor: Color {
        switch change.changeType {
        case .created: return .green
        case .modified: return .orange
        case .deleted: return .red
        case .permissionsChanged: return .yellow
        }
    }

    private var rowBackground: Color {
        switch change.severity {
        case .critical: return Color.red.opacity(0.05)
        case .high: return Color.orange.opacity(0.03)
        default: return Color.white.opacity(0.02)
        }
    }
}
