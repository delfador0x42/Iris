import SwiftUI

/// Right-side analysis context panel for expanded findings.
/// Evidence-first layout: MITRE + evidence + process detail on top.
/// TLDR insight collapsed into a single expandable line.
struct AnalysisPanel: View {
  let technique: String
  let processName: String
  let severity: AnomalySeverity
  let count: Int
  var anomalies: [ProcessAnomaly] = []
  var vtVerdict: VTVerdict?
  var binaryAnalysis: BinaryAnalysis?
  @State private var showTLDR = false
  @State private var ancestors: [ProcessProfiler.Ancestor] = []

  var body: some View {
    let a = FindingAnalyzer.analyze(
      technique: technique, processName: processName,
      severity: severity, count: count
    )
    ScrollView {
      VStack(alignment: .leading, spacing: 4) {
        insightRow(a)
        Divider().background(Color.white.opacity(0.08))
        forensicSection
      }
      .padding(10)
    }
    .background(Color.white.opacity(0.03))
    .cornerRadius(6)
    .task { loadGenealogy() }
  }

  // MARK: - Compact insight (replaces verbose TLDR)

  private func insightRow(_ a: FindingAnalyzer.Analysis) -> some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack(spacing: 4) {
        label("INSIGHT", color: .orange)
        Spacer()
        Button(action: { withAnimation(.easeInOut(duration: 0.15)) { showTLDR.toggle() } }) {
          Image(systemName: showTLDR ? "chevron.up" : "chevron.down")
            .font(.system(size: 7))
            .foregroundColor(.white.opacity(0.3))
        }.buttonStyle(.plain)
      }
      Text(a.whatsHappening)
        .font(.system(size: 10)).foregroundColor(.white.opacity(0.7))
        .lineLimit(showTLDR ? nil : 2)
        .textSelection(.enabled)
      if showTLDR {
        HStack(alignment: .top, spacing: 12) {
          VStack(alignment: .leading, spacing: 1) {
            label("WHY", color: .orange.opacity(0.6))
            Text(a.whyItMatters)
              .font(.system(size: 9)).foregroundColor(.white.opacity(0.5))
              .textSelection(.enabled)
          }
          VStack(alignment: .leading, spacing: 1) {
            label("ACTION", color: .green.opacity(0.6))
            Text(a.recommendedAction)
              .font(.system(size: 9)).foregroundColor(.white.opacity(0.5))
              .textSelection(.enabled)
          }
        }
      }
    }
  }

  // MARK: - Evidence-first forensic detail

  @ViewBuilder
  private var forensicSection: some View {
    let first = anomalies.first
    let evidence = first?.evidence ?? []

    VStack(alignment: .leading, spacing: 4) {
      // DETECTION: MITRE + scanner + method on compact lines
      detectionSection(first)
      // Evidence (primary content)
      if !evidence.isEmpty {
        evidenceBlock(evidence)
      }
      // Process context from knowledge base
      processContext
      // Genealogy chain (live-traced from PID)
      if !ancestors.isEmpty {
        lineageSection
      }
      // Process info
      if let f = first, f.pid > 0 {
        processDetail(f)
      }
      // Affected paths for groups
      if anomalies.count > 1 {
        groupedPaths
      }
      // Binary analysis
      if let ba = binaryAnalysis {
        BinaryAnalysisSection(analysis: ba)
      }
      // VirusTotal
      if let vt = vtVerdict {
        vtSection(vt)
      }
    }
  }

  private func vtSection(_ vt: VTVerdict) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      label("VIRUSTOTAL", color: vt.isMalicious ? .red : .gray)
      Text(vt.summary)
        .font(.system(size: 10, design: .monospaced))
        .foregroundColor(vt.isMalicious ? .red.opacity(0.8) : .white.opacity(0.6))
      if vt.found {
        monoLine("sha256: \(vt.sha256)")
        Link("View full report on VirusTotal",
             destination: URL(string: "https://www.virustotal.com/gui/file/\(vt.sha256)")!)
          .font(.system(size: 9, design: .monospaced))
          .foregroundColor(.blue.opacity(0.7))
      }
    }
  }

  @ViewBuilder
  private var processContext: some View {
    let info = ProcessKnowledgeBase.lookup(processName)
    if let info {
      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 6) {
          label("IDENTITY", color: .cyan)
          Text(info.category.rawValue)
            .font(.system(size: 8, design: .monospaced))
            .foregroundColor(.cyan.opacity(0.5))
        }
        Text("\(processName) — \(info.description)")
          .font(.system(size: 10)).foregroundColor(.white.opacity(0.7))
        Text("subsystem: \(info.subsystem)")
          .font(.system(size: 9, design: .monospaced))
          .foregroundColor(.white.opacity(0.4))
      }
    }
  }

  private func processDetail(_ a: ProcessAnomaly) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      label("PROCESS", color: .white.opacity(0.4))
      monoLine("pid: \(a.pid)")
      if !a.processPath.isEmpty { monoLine("path: \(a.processPath)") }
      if a.parentPID > 0 {
        monoLine("parent: \(a.parentName) (\(a.parentPID))")
      }
    }
  }

  private func evidenceBlock(_ lines: [String]) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      label("EVIDENCE", color: .orange.opacity(0.8))
      ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
        monoLine(line)
      }
    }
  }

  @ViewBuilder
  private var groupedPaths: some View {
    let paths = Array(Set(anomalies.compactMap {
      $0.processPath.isEmpty ? nil : $0.processPath
    }).sorted().prefix(15))
    if !paths.isEmpty {
      VStack(alignment: .leading, spacing: 2) {
        label("AFFECTED (\(anomalies.count))", color: .white.opacity(0.4))
        ForEach(paths, id: \.self) { p in monoLine(p) }
        if anomalies.count > 15 {
          monoLine("... +\(anomalies.count - 15) more")
        }
      }
    }
  }

  // MARK: - Detection context

  private func detectionSection(_ first: ProcessAnomaly?) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      HStack(spacing: 6) {
        label("DETECTION", color: .purple)
        if let mitre = anomalies.compactMap(\.mitreID).first {
          Text(mitre)
            .font(.system(size: 9, weight: .medium, design: .monospaced))
            .foregroundColor(.red.opacity(0.7))
        }
      }
      if let f = first {
        let scanner = scannerDisplayName(f.scannerId)
        let method = f.enumMethod.isEmpty ? "" : " · \(f.enumMethod)"
        monoLine("\(scanner)\(method)")
      }
    }
  }

  // MARK: - Lineage

  private var lineageSection: some View {
    VStack(alignment: .leading, spacing: 2) {
      label("LINEAGE", color: .cyan.opacity(0.7))
      let chain = ProcessProfiler.chainString(ancestors: ancestors, processName: processName)
      monoLine(chain)
    }
  }

  private func loadGenealogy() {
    guard ancestors.isEmpty, let first = anomalies.first, first.pid > 0 else { return }
    ancestors = ProcessProfiler.traceGenealogyLive(pid: first.pid)
  }

  // MARK: - Helpers

  private func label(_ text: String, color: Color) -> some View {
    Text(text)
      .font(.system(size: 8, weight: .bold, design: .monospaced))
      .foregroundColor(color.opacity(0.7))
  }

  private func monoLine(_ text: String) -> some View {
    Text(text)
      .font(.system(size: 9, design: .monospaced))
      .foregroundColor(.white.opacity(0.55))
      .textSelection(.enabled)
  }

  private func scannerDisplayName(_ id: String) -> String {
    let names: [String: String] = [
      "process_integrity": "ProcessIntegrity",
      "hidden_process": "HiddenProcess",
      "credential_access": "CredentialAccess",
      "stealth": "Stealth",
      "masquerade": "Masquerade",
      "lolbin": "LOLBin",
      "dyld_env": "DyldEnv",
      "memory": "Memory",
      "exploit_tool": "ExploitTool",
      "binary_integrity": "BinaryIntegrity",
      "dylib_hijack": "DylibHijack",
      "entitlement": "Entitlement",
      "persistence": "Persistence",
      "persistence_monitor": "PersistenceMonitor",
      "kext": "KextAnomaly",
      "system_integrity": "SystemIntegrity",
      "tcc": "TCC",
      "event_taps": "EventTaps",
      "network_anomaly": "NetworkAnomaly",
      "cloud_c2": "CloudC2",
      "covert_channel": "CovertChannel",
      "thread_anomaly": "ThreadAnomaly",
      "dns_tunnel": "DNSTunnel",
    ]
    return names[id] ?? id
  }
}
