import Foundation

/// Orchestrates deep static analysis on binaries referenced in scan findings.
/// Runs all sub-analyzers concurrently, computes risk score.
public enum BinaryAnalysisEngine {

  /// Analyze all unique binaries referenced in anomalies.
  public static func analyze(anomalies: [ProcessAnomaly]) async -> [String: BinaryAnalysis] {
    let paths = collectPaths(anomalies)
    guard !paths.isEmpty else { return [:] }

    return await withTaskGroup(of: (String, BinaryAnalysis?).self) { group in
      for path in paths {
        group.addTask { (path, analyzeOne(path)) }
      }
      var results: [String: BinaryAnalysis] = [:]
      for await (path, analysis) in group {
        if let a = analysis { results[path] = a }
      }
      return results
    }
  }

  /// Collect unique existing binary paths from anomalies.
  private static func collectPaths(_ anomalies: [ProcessAnomaly]) -> Set<String> {
    var paths = Set<String>()
    let fm = FileManager.default
    for a in anomalies {
      if !a.processPath.isEmpty && fm.fileExists(atPath: a.processPath) {
        paths.insert(a.processPath)
      }
      // Also check evidence for file paths
      for ev in a.evidence {
        if let p = extractPath(ev), fm.fileExists(atPath: p) {
          paths.insert(p)
        }
      }
    }
    return paths
  }

  /// Extract a file path from an evidence line like "injected_dylib: /path/to/foo"
  private static func extractPath(_ evidence: String) -> String? {
    guard let colonIdx = evidence.firstIndex(of: ":") else { return nil }
    let after = evidence[evidence.index(after: colonIdx)...].trimmingCharacters(in: .whitespaces)
    guard after.hasPrefix("/") else { return nil }
    let path = after.components(separatedBy: " ").first ?? after
    return path.isEmpty ? nil : path
  }

  /// Run all sub-analyzers on a single binary path.
  public static func analyzeOne(_ path: String) -> BinaryAnalysis? {
    let fm = FileManager.default
    guard let attrs = try? fm.attributesOfItem(atPath: path) else { return nil }
    let fileSize = (attrs[.size] as? Int64) ?? 0
    let modDate = attrs[.modificationDate] as? Date

    let hash = sha256(path: path)
    let sign = CodeSignValidator.validate(path: path)
    let dangerousEnts = CodeSignValidator.dangerousEntitlements(path: path)
    let machO = MachOParser.parse(path)
    let entropy = EntropyAnalyzer.analyze(path: path)
    let strings = StringsExtractor.extract(path: path)
    let symbols = SymbolExtractor.extract(path: path)

    let signingSummary = BinaryAnalysis.SigningSummary(
      isSigned: sign.isSigned, isValid: sign.isValidSignature,
      isApple: sign.isAppleSigned, isAdHoc: sign.isAdHoc,
      signingId: sign.signingIdentifier, teamId: sign.teamIdentifier)

    let machOSummary = machO.map {
      BinaryAnalysis.MachOSummary(
        fileType: $0.fileType, dylibCount: $0.loadDylibs.count,
        weakDylibCount: $0.weakDylibs.count, rpathCount: $0.rpaths.count,
        reexportCount: $0.reexportDylibs.count)
    }

    let entropySummary = entropy.map {
      BinaryAnalysis.EntropySummary(
        entropy: $0.entropy, chiSquare: $0.chiSquare, isEncrypted: $0.isEncrypted)
    }

    let (score, factors) = computeRisk(
      signing: sign, dangerousEnts: dangerousEnts,
      entropy: entropy, strings: strings,
      symbols: symbols)

    return BinaryAnalysis(
      path: path, sha256: hash, fileSize: fileSize, modDate: modDate,
      signing: signingSummary, dangerousEntitlements: dangerousEnts,
      machO: machOSummary, entropy: entropySummary,
      suspiciousStrings: strings,
      importCount: symbols?.importCount ?? 0,
      exportCount: symbols?.exportCount ?? 0,
      suspiciousSymbols: symbols?.suspiciousImports ?? [],
      riskScore: score, riskFactors: factors)
  }

  /// SHA256 via Rust FFI (pure-Rust FIPS 180-4, no framework overhead).
  private static func sha256(path: String) -> String {
    RustBatchOps.sha256(path: path) ?? ""
  }
}
