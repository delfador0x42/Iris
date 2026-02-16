import Foundation

/// Computes aggregate risk score from binary analysis signals.
extension BinaryAnalysisEngine {

  static func computeRisk(
    signing: CodeSignValidator.SigningInfo,
    dangerousEnts: [String],
    entropy: EntropyAnalyzer.Result?,
    strings: [BinaryAnalysis.SuspiciousString],
    symbols: SymbolExtractor.Result?
  ) -> (score: Int, factors: [String]) {
    var score = 0
    var factors: [String] = []

    // Signing signals
    if !signing.isSigned {
      score += 30; factors.append("unsigned binary (+30)")
    } else if !signing.isValidSignature {
      score += 25; factors.append("invalid code signature (+25)")
    } else if signing.isAdHoc {
      score += 15; factors.append("ad-hoc signed (+15)")
    }

    // Dangerous entitlements
    let entScore = min(dangerousEnts.count * 10, 30)
    if entScore > 0 {
      score += entScore
      factors.append("\(dangerousEnts.count) dangerous entitlement(s) (+\(entScore))")
    }

    // Entropy
    if let e = entropy, e.entropy >= 7.9 {
      score += 15
      factors.append("high entropy \(String(format: "%.2f", e.entropy)) (+15)")
    }

    // Suspicious strings by category
    let categories = Set(strings.map(\.category))
    let strScore = min(categories.count * 5, 20)
    if strScore > 0 {
      score += strScore
      factors.append("\(categories.count) suspicious string categories (+\(strScore))")
    }

    // Suspicious symbols
    if let sym = symbols, !sym.suspiciousImports.isEmpty {
      let symScore = min(sym.suspiciousImports.count * 5, 20)
      score += symScore
      factors.append("\(sym.suspiciousImports.count) suspicious imports (+\(symScore))")
    }

    return (min(score, 100), factors)
  }
}
