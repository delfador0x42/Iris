import SwiftUI

/// Row for a group of anomalies sharing (technique, processName).
/// Single findings look like the old AnomalyRow. Groups show count badge.
/// Expanded: two-column layout — details left, analysis right.
struct AnomalyGroupRow: View {
  let group: AnomalyGroup
  var vtVerdict: VTVerdict?
  @State private var isExpanded = false

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      collapsedHeader
      if isExpanded { expandedContent }
    }
    .background(backgroundFor(group.severity))
  }

  // MARK: - Collapsed

  private var collapsedHeader: some View {
    HStack(spacing: 10) {
      SeverityBadge(severity: group.severity)
      VStack(alignment: .leading, spacing: 2) {
        Text(group.technique)
          .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
        HStack(spacing: 6) {
          Text(group.processName)
            .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
          if let sid = group.anomalies.first?.scannerId, !sid.isEmpty {
            Text(sid)
              .font(.system(size: 8, design: .monospaced))
              .foregroundColor(.purple.opacity(0.6))
          }
        }
      }
      Spacer()
      if group.isGrouped {
        Text("\u{00D7}\(group.count)")
          .font(.system(size: 10, weight: .bold, design: .monospaced))
          .foregroundColor(.white.opacity(0.9))
          .padding(.horizontal, 6).padding(.vertical, 2)
          .background(Color.white.opacity(0.08))
          .cornerRadius(4)
      }
      if let mitre = group.mitreID {
        MITREBadge(id: mitre)
      }
      ExpandChevron(isExpanded: isExpanded)
    }
    .padding(.horizontal, 20).padding(.vertical, 6)
    .contentShape(Rectangle())
    .onTapGesture { withAnimation { isExpanded.toggle() } }
  }

  // MARK: - Expanded: Two Column

  private var expandedContent: some View {
    HStack(alignment: .top, spacing: 16) {
      detailsColumn
      AnalysisPanel(
        technique: group.technique, processName: group.processName,
        severity: group.severity, count: group.count,
        anomalies: group.anomalies, vtVerdict: vtVerdict
      )
      .frame(maxWidth: .infinity, alignment: .leading)
    }
    .padding(.horizontal, 20).padding(.bottom, 10)
  }

  private var detailsColumn: some View {
    VStack(alignment: .leading, spacing: 4) {
      ForEach(group.anomalies.prefix(20)) { a in
        VStack(alignment: .leading, spacing: 1) {
          Text(a.description)
            .font(.system(size: 10)).foregroundColor(.white.opacity(0.8))
          if !a.processPath.isEmpty {
            Text(a.processPath)
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.gray.opacity(0.6))
              .textSelection(.enabled)
          }
          if a.pid > 0 {
            Text("PID: \(a.pid) | Parent: \(a.parentName) (\(a.parentPID))")
              .font(.system(size: 9, design: .monospaced)).foregroundColor(.gray.opacity(0.5))
          }
        }
      }
      if group.count > 20 {
        Text("+\(group.count - 20) more")
          .font(.system(size: 9, design: .monospaced)).foregroundColor(.gray.opacity(0.5))
      }
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}
