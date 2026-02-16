import SwiftUI

/// Comprehensive threat scanning view that runs all 50 security scanners
/// via SecurityAssessor and presents findings organized by severity.
public struct ThreatScanView: View {
  @State private var result: ThreatScanResult?
  @State private var isLoading = true
  @State private var showCriticalOnly = false

  public init() {}

  public var body: some View {
    ZStack {
      darkBackground
      VStack(spacing: 0) {
        header
        if isLoading {
          scanningView
        } else if let result, result.totalFindings > 0 {
          findingsList(result)
        } else {
          cleanView
        }
      }
    }
    .task { await runFullScan() }
  }

  private var header: some View {
    HStack {
      VStack(alignment: .leading, spacing: 4) {
        Text("Threat Scanner")
          .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
        if let r = result, !isLoading {
          HStack(spacing: 12) {
            Text("\(r.totalFindings) findings")
              .font(.caption).foregroundColor(.gray)
            if r.criticalCount > 0 {
              Text("\(r.criticalCount) critical").font(.caption).foregroundColor(.red)
            }
            if r.highCount > 0 {
              Text("\(r.highCount) high").font(.caption).foregroundColor(.orange)
            }
            Text("\(String(format: "%.1f", r.scanDuration))s")
              .font(.caption).foregroundColor(.gray.opacity(0.6))
          }
        }
      }
      Spacer()
      if !isLoading {
        Toggle("Critical+", isOn: $showCriticalOnly)
          .toggleStyle(.switch)
          .foregroundColor(.white).font(.system(size: 11))
        Button(action: { Task { await runFullScan() } }) {
          Image(systemName: "arrow.clockwise").foregroundColor(.blue)
        }.buttonStyle(.plain)
      }
    }.padding(20)
  }

  private func findingsList(_ r: ThreatScanResult) -> some View {
    let anomalies = showCriticalOnly
      ? r.anomalies.filter { $0.severity >= .high } : r.anomalies
    let scFindings = showCriticalOnly
      ? r.supplyChainFindings.filter { $0.severity >= .high } : r.supplyChainFindings
    let fsChanges = showCriticalOnly
      ? r.fsChanges.filter { $0.severity >= .high } : r.fsChanges

    return ThemedScrollView {
      LazyVStack(alignment: .leading, spacing: 2) {
        // Correlated threats (highest-confidence findings)
        if !r.correlations.isEmpty {
          sectionHeader("Correlated Threats", count: r.correlations.count)
          ForEach(r.correlations) { c in
            CorrelationRow(correlation: c)
          }
        }
        if !anomalies.isEmpty {
          sectionHeader("Process & System Anomalies", count: anomalies.count)
          ForEach(anomalies) { anomaly in AnomalyRow(anomaly: anomaly) }
        }
        if !fsChanges.isEmpty {
          sectionHeader("Filesystem Changes", count: fsChanges.count)
          ForEach(fsChanges) { change in FSChangeRow(change: change) }
        }
        if !scFindings.isEmpty {
          sectionHeader("Supply Chain", count: scFindings.count)
          ForEach(scFindings) { finding in SupplyChainRow(finding: finding) }
        }
      }.padding(.vertical, 8)
    }
  }

  private func sectionHeader(_ title: String, count: Int) -> some View {
    HStack {
      Text(title).font(.system(size: 11, weight: .semibold)).foregroundColor(.cyan)
      Text("(\(count))").font(.system(size: 10)).foregroundColor(.gray)
      Spacer()
    }
    .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 4)
  }

  private var scanningView: some View {
    VStack(spacing: 16) {
      ProgressView().tint(.cyan)
      Text("Running 50 scanners...")
        .font(.system(size: 14, design: .monospaced)).foregroundColor(.gray)
    }.frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var cleanView: some View {
    VStack(spacing: 16) {
      Image(systemName: "checkmark.shield.fill")
        .font(.system(size: 48)).foregroundColor(.green)
      Text("No threats detected").font(.headline).foregroundColor(.white)
      Text("All 50 scanners passed")
        .font(.caption).foregroundColor(.gray)
    }.frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var darkBackground: some View {
    LinearGradient(
      colors: [
        Color(red: 0.02, green: 0.03, blue: 0.05),
        Color(red: 0.05, green: 0.07, blue: 0.1),
      ],
      startPoint: .top, endPoint: .bottom
    ).ignoresSafeArea()
  }

  private func runFullScan() async {
    isLoading = true
    result = await SecurityAssessor.shared.scanThreats()
    isLoading = false
  }
}
