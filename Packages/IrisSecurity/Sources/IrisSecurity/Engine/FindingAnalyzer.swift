import Foundation

/// Contextual analysis for findings — explains WHY, not just WHAT.
/// Pure static lookup: technique string → human-readable context.
enum FindingAnalyzer {

  struct Analysis {
    let whyItMatters: String
    let whatsHappening: String
    let severityContext: String
    let recommendedAction: String
  }

  /// Analyze a finding. Checks exact match, then prefix match, then default.
  static func analyze(
    technique: String, processName: String = "",
    severity: AnomalySeverity = .medium, count: Int = 1
  ) -> Analysis {
    // Exact match
    if let factory = techniques[technique] {
      return factory(processName, severity, count)
    }
    // Prefix match for dynamic names like "Kext Hooks vnode_check_exec"
    for (prefix, factory) in prefixTechniques {
      if technique.hasPrefix(prefix) {
        return factory(processName, severity, count)
      }
    }
    return defaultAnalysis(technique, processName, severity, count)
  }

  // Populated in FindingAnalyzer+Techniques.swift
  static var techniques: [String: (String, AnomalySeverity, Int) -> Analysis] = [:]
  static var prefixTechniques: [(String, (String, AnomalySeverity, Int) -> Analysis)] = []

  static func defaultAnalysis(
    _ technique: String, _ process: String,
    _ severity: AnomalySeverity, _ count: Int
  ) -> Analysis {
    let countNote = count > 1 ? " (\(count) instances)" : ""
    switch severity {
    case .critical:
      return Analysis(
        whyItMatters: "Critical findings indicate active compromise or severe misconfiguration.",
        whatsHappening: "\(process.isEmpty ? "A process" : process) triggered \(technique)\(countNote).",
        severityContext: "Investigate immediately. This may indicate malware or a rootkit.",
        recommendedAction: "Examine the process, check code signature, review parent chain.")
    case .high:
      return Analysis(
        whyItMatters: "High-severity findings weaken system defenses or indicate suspicious behavior.",
        whatsHappening: "\(process.isEmpty ? "A process" : process) triggered \(technique)\(countNote).",
        severityContext: "Worth investigating. Could be benign developer tooling or a real threat.",
        recommendedAction: "Verify the process is legitimate. Add to allowlist if expected.")
    case .medium:
      return Analysis(
        whyItMatters: "Medium findings are configuration issues or unusual but not necessarily malicious behavior.",
        whatsHappening: "\(process.isEmpty ? "A process" : process) triggered \(technique)\(countNote).",
        severityContext: "Monitor but not urgent. Common on developer machines.",
        recommendedAction: "Review when convenient. Consider tightening configuration.")
    case .low:
      return Analysis(
        whyItMatters: "Low findings are informational — they note deviations from hardened defaults.",
        whatsHappening: "\(process.isEmpty ? "A process" : process) triggered \(technique)\(countNote).",
        severityContext: "Informational only. Normal on most systems.",
        recommendedAction: "No action required unless hardening for production.")
    }
  }
}
