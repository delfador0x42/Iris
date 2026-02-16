import SwiftUI

/// Main findings view — streams results as scanners complete.
/// Groups duplicates by (technique, processName). Uses ThemedScrollView for styled scrollbar.
struct ScanResultsView: View {
  @ObservedObject var session: ScanSession

  var body: some View {
    ZStack {
      Color(red: 0.01, green: 0.02, blue: 0.04).ignoresSafeArea()
      if session.scannerResults.isEmpty && session.isScanning {
        scanningPlaceholder
      } else if session.scannerResults.isEmpty {
        emptyState
      } else {
        ThemedScrollView {
          LazyVStack(spacing: 0) {
            scanHeader
            correlationsSection
            anomalySection(severity: .critical)
            anomalySection(severity: .high)
            supplyChainSection
            fsChangesSection
            anomalySection(severity: .medium)
            anomalySection(severity: .low)
          }
          .padding(.bottom, 20)
          .onAppear { FindingAnalyzer.registerAll() }
        }
      }
    }
  }

  // MARK: - Placeholders

  private var scanningPlaceholder: some View {
    VStack(spacing: 12) {
      ProgressView().controlSize(.regular).tint(.cyan)
      Text("Running \(ScannerEntry.all.count) scanners...")
        .font(.system(size: 13, weight: .medium, design: .monospaced))
        .foregroundColor(.cyan.opacity(0.7))
    }
  }

  private var emptyState: some View {
    VStack(spacing: 8) {
      Image(systemName: "shield.checkered")
        .font(.system(size: 32)).foregroundColor(.gray.opacity(0.3))
      Text("No scan results")
        .font(.system(size: 13, design: .monospaced))
        .foregroundColor(.gray.opacity(0.5))
    }
  }

  // MARK: - Scan Header

  @ViewBuilder
  private var scanHeader: some View {
    if let r = session.scanResult {
      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 6) {
          label("LAST SCAN", color: .cyan)
          Text(r.timestamp, style: .time)
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.white.opacity(0.5))
          Text("\u{00B7}")
            .foregroundColor(.white.opacity(0.2))
          Text("\(r.scannerCount) engines")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.white.opacity(0.4))
          Text("\u{00B7}")
            .foregroundColor(.white.opacity(0.2))
          Text(String(format: "%.1fs", r.scanDuration))
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.white.opacity(0.4))
          Text("\u{00B7}")
            .foregroundColor(.white.opacity(0.2))
          Text("\(r.totalFindings) findings")
            .font(.system(size: 9, weight: .medium, design: .monospaced))
            .foregroundColor(r.criticalCount > 0 ? .red.opacity(0.8) : .white.opacity(0.5))
          if r.criticalCount > 0 {
            Text("(\(r.criticalCount) critical)")
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.red.opacity(0.6))
          }
        }
        if let d = session.diff, d.hasChanges {
          HStack(spacing: 6) {
            label("\u{0394}", color: .cyan.opacity(0.6))
            if !d.newFindings.isEmpty {
              Text("+\(d.newFindings.count) new")
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.orange.opacity(0.7))
            }
            if !d.resolvedFindings.isEmpty {
              Text("-\(d.resolvedFindings.count) resolved")
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.green.opacity(0.7))
            }
          }
        }
      }
      .padding(.horizontal, 20).padding(.vertical, 6)
      .background(Color.white.opacity(0.02))
    }
  }

  private func label(_ text: String, color: Color) -> some View {
    Text(text)
      .font(.system(size: 8, weight: .bold, design: .monospaced))
      .foregroundColor(color.opacity(0.7))
  }

  // MARK: - Sections

  @ViewBuilder
  private var correlationsSection: some View {
    let items = session.correlations
    if !items.isEmpty {
      sectionHeader("Correlated Threats", count: items.count, color: .red)
      ForEach(items) { c in CorrelationRow(correlation: c) }
    }
  }

  @ViewBuilder
  private func anomalySection(severity: AnomalySeverity) -> some View {
    let all = allAnomalies.filter { $0.severity == severity }
    let groups = AnomalyGroup.group(all)
    if !groups.isEmpty {
      sectionHeader(severity.label.capitalized, count: all.count, color: severityColor(severity))
      ForEach(groups) { g in
        let path = g.anomalies.first?.processPath ?? ""
        AnomalyGroupRow(group: g, binaryAnalysis: session.binaryAnalysis(for: path))
      }
    }
  }

  @ViewBuilder
  private var supplyChainSection: some View {
    let items = session.scanResult?.supplyChainFindings ?? []
    if !items.isEmpty {
      sectionHeader("Supply Chain", count: items.count, color: .green)
      ForEach(items) { f in SupplyChainRow(finding: f) }
    }
  }

  @ViewBuilder
  private var fsChangesSection: some View {
    let items = session.scanResult?.fsChanges ?? []
    if !items.isEmpty {
      sectionHeader("Filesystem Changes", count: items.count, color: .cyan)
      ForEach(items) { c in FSChangeRow(change: c) }
    }
  }

  // MARK: - Helpers

  private var allAnomalies: [ProcessAnomaly] {
    session.scanResult?.anomalies ?? session.scannerResults.flatMap(\.anomalies)
  }

  private func sectionHeader(_ title: String, count: Int, color: Color) -> some View {
    HStack(spacing: 8) {
      Rectangle().fill(color.opacity(0.4)).frame(width: 3, height: 14)
      Text(title.uppercased())
        .font(.system(size: 10, weight: .bold, design: .monospaced))
        .foregroundColor(color.opacity(0.8))
      Text("(\(count))")
        .font(.system(size: 10, weight: .medium, design: .monospaced))
        .foregroundColor(color.opacity(0.5))
      Spacer()
    }
    .padding(.horizontal, 20).padding(.top, 10).padding(.bottom, 4)
  }

  private func severityColor(_ s: AnomalySeverity) -> Color {
    switch s {
    case .critical: return .red
    case .high: return .orange
    case .medium: return .yellow
    case .low: return .gray
    }
  }
}
