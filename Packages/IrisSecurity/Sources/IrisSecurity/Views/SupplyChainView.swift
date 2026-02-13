import SwiftUI

/// Supply chain integrity auditing view.
/// Checks Homebrew, npm, pip, and Xcode for tampering, typosquatting,
/// and malicious packages.
public struct SupplyChainView: View {
    @State private var findings: [SupplyChainFinding] = []
    @State private var isScanning = false
    @State private var selectedSource: PackageManagerSource?

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                sourceFilter
                if isScanning {
                    scanningView
                } else if filteredFindings.isEmpty {
                    cleanView
                } else {
                    findingsList
                }
            }
        }
        .task { await runAudit() }
    }

    private var filteredFindings: [SupplyChainFinding] {
        guard let source = selectedSource else { return findings }
        return findings.filter { $0.source == source }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Supply Chain Audit")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                if !isScanning && !findings.isEmpty {
                    Text("\(findings.count) findings across \(sourceCounts) sources")
                        .font(.caption).foregroundColor(.gray)
                }
            }
            Spacer()
            if !isScanning {
                Button(action: { Task { await runAudit() } }) {
                    Image(systemName: "arrow.clockwise").foregroundColor(.blue)
                }.buttonStyle(.plain)
            }
        }.padding(20)
    }

    private var sourceCounts: String {
        let sources = Set(findings.map(\.source))
        return "\(sources.count)"
    }

    private var sourceFilter: some View {
        ThemedScrollView(.horizontal) {
            HStack(spacing: 8) {
                FilterChip(label: "All", isSelected: selectedSource == nil) {
                    selectedSource = nil
                }
                ForEach([PackageManagerSource.homebrew, .npm, .pip, .xcode], id: \.self) { source in
                    let count = findings.filter { $0.source == source }.count
                    FilterChip(
                        label: "\(source.rawValue) (\(count))",
                        isSelected: selectedSource == source
                    ) {
                        selectedSource = source
                    }
                }
            }.padding(.horizontal, 20).padding(.bottom, 8)
        }
    }

    private var findingsList: some View {
        ThemedScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(filteredFindings) { finding in
                    SupplyChainDetailRow(finding: finding)
                }
            }.padding(.vertical, 8)
        }
    }

    private var scanningView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.cyan)
            Text("Auditing package managers...")
                .font(.system(size: 14)).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var cleanView: some View {
        VStack(spacing: 16) {
            Image(systemName: "shippingbox.fill")
                .font(.system(size: 48)).foregroundColor(.green)
            Text("Supply chain clean").font(.headline).foregroundColor(.white)
            Text("No suspicious packages detected")
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

    private func runAudit() async {
        isScanning = true
        findings = await SupplyChainAuditor.shared.auditAll()
        isScanning = false
    }
}

struct FilterChip: View {
    let label: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 11, weight: isSelected ? .semibold : .regular))
                .foregroundColor(isSelected ? .white : .gray)
                .padding(.horizontal, 12).padding(.vertical, 6)
                .background(isSelected ? Color.cyan.opacity(0.3) : Color.white.opacity(0.05))
                .cornerRadius(14)
        }.buttonStyle(.plain)
    }
}

struct SupplyChainDetailRow: View {
    let finding: SupplyChainFinding
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                sourceIcon
                VStack(alignment: .leading, spacing: 2) {
                    Text(finding.packageName)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(finding.finding)
                        .font(.system(size: 10)).foregroundColor(.gray)
                }
                Spacer()
                SeverityBadge(severity: finding.severity)
                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .foregroundColor(.gray).font(.system(size: 10))
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                Text(finding.details)
                    .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(rowBackground)
    }

    private var sourceIcon: some View {
        Image(systemName: iconForSource)
            .font(.system(size: 14))
            .foregroundColor(colorForSource)
            .frame(width: 24)
    }

    private var iconForSource: String {
        switch finding.source {
        case .homebrew: return "mug"
        case .npm: return "shippingbox"
        case .pip: return "puzzlepiece"
        case .xcode: return "hammer"
        }
    }

    private var colorForSource: Color {
        switch finding.source {
        case .homebrew: return .yellow
        case .npm: return .red
        case .pip: return .blue
        case .xcode: return .cyan
        }
    }

    private var rowBackground: Color {
        switch finding.severity {
        case .critical: return Color.red.opacity(0.05)
        case .high: return Color.orange.opacity(0.03)
        default: return Color.white.opacity(0.02)
        }
    }
}
