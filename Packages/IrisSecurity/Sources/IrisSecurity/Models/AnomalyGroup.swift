import Foundation

/// Groups anomalies by (technique, processName) for presentation dedup.
/// Scanners produce individual findings; this collapses duplicates in the view layer.
struct AnomalyGroup: Identifiable, Sendable {
  let id: String
  let technique: String
  let processName: String
  let severity: AnomalySeverity
  let mitreID: String?
  let anomalies: [ProcessAnomaly]

  var count: Int { anomalies.count }
  var isGrouped: Bool { count > 1 }

  /// O(n) grouping preserving input order.
  static func group(_ anomalies: [ProcessAnomaly]) -> [AnomalyGroup] {
    var dict: [String: [ProcessAnomaly]] = [:]
    var order: [String] = []
    for a in anomalies {
      let key = "\(a.technique)|\(a.processName)"
      if dict[key] == nil { order.append(key) }
      dict[key, default: []].append(a)
    }
    return order.compactMap { key in
      guard let items = dict[key], let first = items.first else { return nil }
      let maxSev = items.map(\.severity).max() ?? first.severity
      let mitre = items.compactMap(\.mitreID).first
      return AnomalyGroup(
        id: key, technique: first.technique,
        processName: first.processName,
        severity: maxSev, mitreID: mitre, anomalies: items
      )
    }
  }
}
