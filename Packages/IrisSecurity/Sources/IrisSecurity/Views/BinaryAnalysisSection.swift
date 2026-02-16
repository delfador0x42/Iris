import SwiftUI

/// Compact binary analysis summary for AnalysisPanel forensic section.
struct BinaryAnalysisSection: View {
  let analysis: BinaryAnalysis

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      HStack(spacing: 6) {
        label("BINARY ANALYSIS", color: .teal)
        riskBadge
      }
      signingLine
      if let e = analysis.entropy, e.entropy >= 7.0 {
        entropyLine(e)
      }
      if !analysis.suspiciousStrings.isEmpty {
        stringsLine
      }
      if !analysis.suspiciousSymbols.isEmpty {
        symbolsLine
      }
      if !analysis.riskFactors.isEmpty {
        factorsBlock
      }
      monoLine("sha256: \(analysis.sha256)")
    }
  }

  private var riskBadge: some View {
    Text("\(analysis.riskScore)")
      .font(.system(size: 9, weight: .bold, design: .monospaced))
      .foregroundColor(.white)
      .padding(.horizontal, 5).padding(.vertical, 1)
      .background(riskColor.opacity(0.8))
      .cornerRadius(3)
  }

  private var signingLine: some View {
    let s = analysis.signing
    let desc: String
    if s.isApple { desc = "Apple-signed (\(s.signingId ?? "?"))" }
    else if !s.isSigned { desc = "UNSIGNED" }
    else if !s.isValid { desc = "INVALID signature (\(s.teamId ?? "no team"))" }
    else if s.isAdHoc { desc = "Ad-hoc signed" }
    else { desc = "Signed by \(s.teamId ?? s.signingId ?? "?")" }
    return monoLine("signing: \(desc)")
  }

  private func entropyLine(_ e: BinaryAnalysis.EntropySummary) -> some View {
    let enc = e.isEncrypted ? " (likely encrypted)" : ""
    return monoLine("entropy: \(String(format: "%.3f", e.entropy))\(enc)")
  }

  private var stringsLine: some View {
    let cats = Set(analysis.suspiciousStrings.map(\.category))
    let preview = analysis.suspiciousStrings.prefix(3).map(\.value).joined(separator: ", ")
    return monoLine("strings: \(analysis.suspiciousStrings.count) suspicious [\(cats.map(\.rawValue).sorted().joined(separator: ", "))] — \(preview)")
  }

  private var symbolsLine: some View {
    monoLine("symbols: \(analysis.suspiciousSymbols.joined(separator: ", "))")
  }

  private var factorsBlock: some View {
    VStack(alignment: .leading, spacing: 1) {
      label("RISK FACTORS", color: riskColor)
      ForEach(Array(analysis.riskFactors.enumerated()), id: \.offset) { _, factor in
        monoLine("  \(factor)")
      }
    }
  }

  private var riskColor: Color {
    switch analysis.riskScore {
    case 0..<20: return .green
    case 20..<50: return .yellow
    case 50..<75: return .orange
    default: return .red
    }
  }

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
}
