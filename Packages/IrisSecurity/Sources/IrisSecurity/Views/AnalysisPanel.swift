import SwiftUI

/// Right-side analysis context panel for expanded findings.
/// Top: compact TLDR. Bottom: rich forensic detail (module, enumeration, evidence).
struct AnalysisPanel: View {
  let technique: String
  let processName: String
  let severity: AnomalySeverity
  let count: Int
  var anomalies: [ProcessAnomaly] = []
  var vtVerdict: VTVerdict?

  var body: some View {
    let a = FindingAnalyzer.analyze(
      technique: technique, processName: processName,
      severity: severity, count: count
    )
    ScrollView {
      VStack(alignment: .leading, spacing: 6) {
        tldrSection(a)
        Divider().background(Color.white.opacity(0.08))
        forensicSection
      }
      .padding(10)
    }
    .background(Color.white.opacity(0.03))
    .cornerRadius(6)
  }

  // MARK: - Compact TLDR (top half)

  private func tldrSection(_ a: FindingAnalyzer.Analysis) -> some View {
    VStack(alignment: .leading, spacing: 4) {
      label("WHY", color: .orange)
      Text(a.whyItMatters)
        .font(.system(size: 10)).foregroundColor(.white.opacity(0.7))
      label("WHAT", color: .cyan)
      Text(a.whatsHappening)
        .font(.system(size: 10)).foregroundColor(.white.opacity(0.7))
      HStack(alignment: .top, spacing: 12) {
        VStack(alignment: .leading, spacing: 1) {
          label("SEVERITY", color: .yellow)
          Text(a.severityContext)
            .font(.system(size: 9)).foregroundColor(.white.opacity(0.6))
        }
        VStack(alignment: .leading, spacing: 1) {
          label("ACTION", color: .green)
          Text(a.recommendedAction)
            .font(.system(size: 9)).foregroundColor(.white.opacity(0.6))
        }
      }
    }
  }

  // MARK: - Rich forensic detail (bottom half)

  @ViewBuilder
  private var forensicSection: some View {
    let first = anomalies.first
    let sid = first?.scannerId ?? ""
    let method = first?.enumMethod ?? ""
    let evidence = first?.evidence ?? []

    VStack(alignment: .leading, spacing: 6) {
      if !sid.isEmpty {
        detailRow("MODULE", value: scannerDisplayName(sid), color: .purple)
      }
      if !method.isEmpty {
        detailRow("ENUMERATION", value: method, color: .blue)
      }
      if let mitre = anomalies.compactMap(\.mitreID).first {
        detailRow("MITRE ATT&CK", value: mitre, color: .red)
      }
      if let f = first, f.pid > 0 {
        processDetail(f)
      }
      if !evidence.isEmpty {
        evidenceBlock(evidence)
      }
      if anomalies.count > 1 {
        groupedPaths
      }
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

  private func detailRow(_ title: String, value: String, color: Color) -> some View {
    VStack(alignment: .leading, spacing: 1) {
      label(title, color: color)
      Text(value)
        .font(.system(size: 10, design: .monospaced))
        .foregroundColor(.white.opacity(0.7))
        .textSelection(.enabled)
    }
  }

  private func scannerDisplayName(_ id: String) -> String {
    let names: [String: String] = [
      "process_integrity": "ProcessIntegrityChecker",
      "hidden_process": "HiddenProcessDetector",
      "credential_access": "CredentialAccessDetector",
      "stealth": "StealthScanner",
      "masquerade": "MasqueradeDetector",
      "lolbin": "LOLBinDetector",
      "dyld_env": "DyldEnvDetector",
      "memory": "MemoryScanner",
      "exploit_tool": "ExploitToolDetector",
      "binary_integrity": "BinaryIntegrityScanner",
      "dylib_hijack": "DylibHijackScanner",
      "entitlement": "EntitlementScanner",
      "persistence": "PersistenceScanner",
      "kext": "KextAnomalyDetector",
      "system_integrity": "SystemIntegrityScanner",
      "tcc": "TCCMonitor",
      "event_taps": "EventTapScanner",
      "network_anomaly": "NetworkAnomalyDetector",
      "cloud_c2": "CloudC2Detector",
    ]
    return names[id] ?? id
  }
}
