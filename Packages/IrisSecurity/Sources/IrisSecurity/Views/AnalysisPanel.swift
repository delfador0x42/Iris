import SwiftUI

/// Right-side analysis context panel for expanded findings.
/// Four labeled sections explaining WHY a finding matters.
struct AnalysisPanel: View {
  let technique: String
  let processName: String
  let severity: AnomalySeverity
  let count: Int

  var body: some View {
    let a = FindingAnalyzer.analyze(
      technique: technique, processName: processName,
      severity: severity, count: count
    )
    VStack(alignment: .leading, spacing: 8) {
      section("Why This Matters", text: a.whyItMatters, color: .orange)
      section("What's Happening", text: a.whatsHappening, color: .cyan)
      section("Severity Context", text: a.severityContext, color: .yellow)
      section("Recommended Action", text: a.recommendedAction, color: .green)
    }
    .padding(10)
    .background(Color.white.opacity(0.03))
    .cornerRadius(6)
  }

  private func section(_ title: String, text: String, color: Color) -> some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(title.uppercased())
        .font(.system(size: 8, weight: .bold, design: .monospaced))
        .foregroundColor(color.opacity(0.7))
      Text(text)
        .font(.system(size: 10))
        .foregroundColor(.white.opacity(0.75))
        .fixedSize(horizontal: false, vertical: true)
    }
  }
}
