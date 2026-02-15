import SwiftUI

/// Scanner status grid — 50 dots that light up as scanners complete.
struct ScannerStatusGrid: View {
  @ObservedObject var session: ScanSession

  var body: some View {
    VStack(alignment: .leading, spacing: 8) {
      // Tier labels + dot grid
      ForEach([ScannerTier.fast, .medium, .slow], id: \.rawValue) { tier in
        let entries = ScannerEntry.all.filter { $0.tier == tier }
        HStack(spacing: 6) {
          Text(tierLabel(tier))
            .font(.system(size: 8, weight: .medium, design: .monospaced))
            .foregroundColor(tierColor(tier).opacity(0.6))
            .frame(width: 32, alignment: .trailing)
          HStack(spacing: 3) {
            ForEach(entries) { entry in
              Circle()
                .fill(dotColor(for: entry))
                .frame(width: 5, height: 5)
                .help(entry.name)
            }
          }
        }
      }

      // Live status line
      if session.isScanning {
        HStack(spacing: 6) {
          Text("\(session.completed)/\(session.total)")
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundColor(.cyan)
          if !session.latestScanner.isEmpty {
            Text(session.latestScanner)
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.gray)
          }
          Spacer()
          Text(liveFindingsText)
            .font(.system(size: 9, weight: .medium, design: .monospaced))
            .foregroundColor(liveFindingsColor)
        }
      }

      // Diff summary
      if let diff = session.diff, diff.hasChanges {
        HStack(spacing: 8) {
          if !diff.newFindings.isEmpty {
            Label("+\(diff.newFindings.count) new", systemImage: "arrow.up.circle.fill")
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.red)
          }
          if !diff.resolvedFindings.isEmpty {
            Label("-\(diff.resolvedFindings.count) resolved", systemImage: "arrow.down.circle.fill")
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.green)
          }
          if diff.unchangedCount > 0 {
            Text("\(diff.unchangedCount) unchanged")
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.gray.opacity(0.5))
          }
        }
      }
    }
  }

  private func dotColor(for entry: ScannerEntry) -> Color {
    guard let result = session.result(for: entry.id) else {
      return session.isScanning ? Color.gray.opacity(0.15) : Color.gray.opacity(0.3)
    }
    if result.anomalies.isEmpty { return .green.opacity(0.7) }
    let maxSeverity = result.anomalies.map(\.severity).max() ?? .low
    switch maxSeverity {
    case .critical: return .red
    case .high: return .orange
    case .medium: return .yellow
    case .low: return .green
    }
  }

  private func tierLabel(_ tier: ScannerTier) -> String {
    switch tier {
    case .fast: return "FAST"
    case .medium: return "MED"
    case .slow: return "SLOW"
    }
  }

  private func tierColor(_ tier: ScannerTier) -> Color {
    switch tier {
    case .fast: return .green
    case .medium: return .yellow
    case .slow: return .orange
    }
  }

  private var liveFindingsText: String {
    let count = session.scannerResults.flatMap(\.anomalies).count
    return count == 0 ? "clean" : "\(count) findings"
  }

  private var liveFindingsColor: Color {
    session.scannerResults.flatMap(\.anomalies).isEmpty ? .green : .orange
  }
}

/// Per-scanner timing breakdown (expandable detail).
struct ScannerTimingView: View {
  let results: [ScannerResult]

  var body: some View {
    let sorted = results.sorted { $0.duration > $1.duration }
    VStack(alignment: .leading, spacing: 2) {
      ForEach(sorted.prefix(10)) { r in
        HStack(spacing: 6) {
          Circle()
            .fill(r.anomalies.isEmpty ? Color.green.opacity(0.6) : .orange)
            .frame(width: 4, height: 4)
          Text(r.name)
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.gray)
          Spacer()
          Text(r.anomalies.isEmpty ? "" : "\(r.anomalies.count)")
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundColor(.orange)
          Text(String(format: "%.0fms", r.duration * 1000))
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.gray.opacity(0.6))
            .frame(width: 48, alignment: .trailing)
        }
      }
    }
  }
}
