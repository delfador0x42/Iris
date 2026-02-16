import Foundation
import os.log

/// Exports ThreatScanResult as JSON or standalone HTML for IR.
public enum ScanReportExporter {

  // MARK: - JSON Export

  /// Export scan result as JSON. Self-contained, machine-readable.
  public static func exportJSON(_ result: ThreatScanResult) -> Data? {
    let report = JSONReport(
      version: "1.0",
      timestamp: result.timestamp,
      hostname: Foundation.ProcessInfo.processInfo.hostName,
      osVersion: Foundation.ProcessInfo.processInfo.operatingSystemVersionString,
      scanDuration: result.scanDuration,
      scannerCount: result.scannerCount,
      totalFindings: result.totalFindings,
      criticalCount: result.criticalCount,
      highCount: result.highCount,
      allowlistSuppressed: result.allowlistSuppressed,
      anomalies: result.anomalies.map { .init(from: $0) },
      correlations: result.correlations.map { .init(from: $0) },
      scannerResults: result.scannerResults.map { .init(from: $0) })
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    return try? encoder.encode(report)
  }

  // MARK: - HTML Export

  /// Export scan result as standalone HTML with inline CSS.
  public static func exportHTML(_ result: ThreatScanResult) -> String {
    let host = Foundation.ProcessInfo.processInfo.hostName
    let os = Foundation.ProcessInfo.processInfo.operatingSystemVersionString
    let date = ISO8601DateFormatter().string(from: result.timestamp)
    let dur = String(format: "%.1f", result.scanDuration)

    var html = """
      <!DOCTYPE html><html><head><meta charset="utf-8">
      <title>Iris Security Report — \(date)</title>
      <style>
      body{font-family:monospace;background:#0a0b0d;color:#e0e0e0;margin:2em}
      h1{color:#00e5ff;border-bottom:1px solid #00e5ff33}
      h2{color:#8ab4f8;margin-top:1.5em}
      .meta{color:#888;font-size:0.9em}
      table{border-collapse:collapse;width:100%;margin:0.5em 0}
      th,td{text-align:left;padding:4px 8px;border:1px solid #333}
      th{background:#1a1b1d;color:#00e5ff}
      .crit{color:#ff4444;font-weight:bold}
      .high{color:#ff8800}.med{color:#ffcc00}.low{color:#44ff44}
      .clean{color:#44ff44;font-size:1.2em}
      .bar{height:4px;background:#00e5ff22;margin:2px 0}
      .bar-fill{height:4px;background:#00e5ff}
      </style></head><body>
      <h1>IRIS SECURITY REPORT</h1>
      <p class="meta">\(host) &middot; \(os) &middot; \(date) &middot; \(dur)s &middot; \(result.scannerCount) engines</p>
      """

    // Summary
    if result.totalFindings == 0 {
      html += "<p class=\"clean\">SYSTEM CLEAN — 0 findings</p>"
    } else {
      html += "<h2>Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>"
      html += "<tr><td class=\"crit\">Critical</td><td>\(result.criticalCount)</td></tr>"
      html += "<tr><td class=\"high\">High</td><td>\(result.highCount)</td></tr>"
      html += "<tr><td class=\"med\">Medium + Low</td><td>\(result.totalFindings - result.criticalCount - result.highCount)</td></tr>"
      html += "<tr><td>Total</td><td><b>\(result.totalFindings)</b></td></tr></table>"
    }

    if result.allowlistSuppressed > 0 {
      html += "<p class=\"meta\">\(result.allowlistSuppressed) finding(s) suppressed by allowlist</p>"
    }

    // Correlations
    if !result.correlations.isEmpty {
      html += "<h2>Correlated Threats</h2><table>"
      html += "<tr><th>Name</th><th>Severity</th><th>MITRE</th><th>Description</th></tr>"
      for c in result.correlations {
        html += "<tr><td>\(c.name)</td><td class=\"\(c.severity.cssClass)\">\(c.severity.label)</td>"
        html += "<td>\(c.mitreChain)</td><td>\(c.description)</td></tr>"
      }
      html += "</table>"
    }

    // Anomalies
    if !result.anomalies.isEmpty {
      html += "<h2>Findings (\(result.anomalies.count))</h2><table>"
      html += "<tr><th>Process</th><th>Severity</th><th>Technique</th><th>MITRE</th><th>Description</th></tr>"
      for a in result.anomalies.prefix(200) {
        html += "<tr><td>\(a.processName)</td>"
        html += "<td class=\"\(a.severity.cssClass)\">\(a.severity.label)</td>"
        html += "<td>\(a.technique)</td><td>\(a.mitreID ?? "")</td>"
        html += "<td>\(esc(a.description))</td></tr>"
      }
      html += "</table>"
    }

    // Scanner timing
    html += "<h2>Scanner Timing</h2><table>"
    html += "<tr><th>Scanner</th><th>Tier</th><th>Findings</th><th>Duration</th></tr>"
    let sorted = result.scannerResults.sorted { $0.duration > $1.duration }
    for s in sorted {
      let ms = String(format: "%.0fms", s.duration * 1000)
      html += "<tr><td>\(s.name)</td><td>\(s.tier.label)</td>"
      html += "<td>\(s.anomalies.count)</td><td>\(ms)</td></tr>"
    }
    html += "</table></body></html>"
    return html
  }

  // MARK: - File Writing

  /// Write report to disk. Returns file URL on success.
  @discardableResult
  public static func save(
    _ result: ThreatScanResult,
    format: ExportFormat,
    directory: URL? = nil
  ) -> URL? {
    let dir = directory ?? defaultDirectory()
    try? FileManager.default.createDirectory(
      at: dir, withIntermediateDirectories: true)
    let ts = ISO8601DateFormatter().string(from: result.timestamp)
      .replacingOccurrences(of: ":", with: "-")
    let ext = format == .json ? "json" : "html"
    let url = dir.appendingPathComponent("iris-report-\(ts).\(ext)")
    let data: Data?
    switch format {
    case .json: data = exportJSON(result)
    case .html: data = exportHTML(result).data(using: .utf8)
    }
    guard let d = data else { return nil }
    try? d.write(to: url, options: .atomic)
    return url
  }

  public enum ExportFormat { case json, html }

  private static func defaultDirectory() -> URL {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
      .first!.appendingPathComponent("Iris/Reports")
  }

  private static func esc(_ s: String) -> String {
    s.replacingOccurrences(of: "&", with: "&amp;")
      .replacingOccurrences(of: "<", with: "&lt;")
      .replacingOccurrences(of: ">", with: "&gt;")
  }
}

// MARK: - JSON Models

private struct JSONReport: Encodable {
  let version: String
  let timestamp: Date
  let hostname: String
  let osVersion: String
  let scanDuration: TimeInterval
  let scannerCount: Int
  let totalFindings: Int
  let criticalCount: Int
  let highCount: Int
  let allowlistSuppressed: Int
  let anomalies: [JSONAnomaly]
  let correlations: [JSONCorrelation]
  let scannerResults: [JSONScanner]
}

private struct JSONAnomaly: Encodable {
  let processName: String
  let technique: String
  let description: String
  let severity: String
  let mitreId: String?
  init(from a: ProcessAnomaly) {
    processName = a.processName; technique = a.technique
    description = a.description; severity = a.severity.label
    mitreId = a.mitreID
  }
}

private struct JSONCorrelation: Encodable {
  let name: String
  let description: String
  let severity: String
  let mitreChain: String
  let scannerIds: [String]
  init(from c: CorrelationEngine.Correlation) {
    name = c.name; description = c.description
    severity = c.severity.label; mitreChain = c.mitreChain
    scannerIds = c.scannerIds
  }
}

private struct JSONScanner: Encodable {
  let id: String
  let name: String
  let tier: String
  let findingsCount: Int
  let durationMs: Double
  init(from s: ScannerResult) {
    id = s.id; name = s.name; tier = s.tier.label
    findingsCount = s.anomalies.count
    durationMs = s.duration * 1000
  }
}

// MARK: - Severity CSS helpers

extension AnomalySeverity {
  var cssClass: String {
    switch self {
    case .critical: return "crit"
    case .high: return "high"
    case .medium: return "med"
    case .low: return "low"
    }
  }
}
