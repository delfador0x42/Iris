import Foundation

/// Category of suspicious string found in a binary
public enum StringCategory: String, Sendable, Codable {
  case url, ipAddress, shellCmd, cryptoAPI, c2Pattern
}

/// Result of deep static analysis on a single binary
public struct BinaryAnalysis: Sendable, Codable, Equatable {
  public let path: String
  public let sha256: String
  public let fileSize: Int64
  public let modDate: Date?

  // Code signing (reuses CodeSignValidator)
  public let signing: SigningSummary
  public let dangerousEntitlements: [String]

  // Mach-O structure (reuses MachOParser)
  public let machO: MachOSummary?

  // Entropy (reuses EntropyAnalyzer)
  public let entropy: EntropySummary?

  // Strings analysis
  public let suspiciousStrings: [SuspiciousString]

  // Symbol table analysis
  public let importCount: Int
  public let exportCount: Int
  public let suspiciousSymbols: [String]

  // Aggregate risk
  public let riskScore: Int       // 0-100
  public let riskFactors: [String]

  public struct SigningSummary: Sendable, Codable, Equatable {
    public let isSigned: Bool
    public let isValid: Bool
    public let isApple: Bool
    public let isAdHoc: Bool
    public let signingId: String?
    public let teamId: String?
  }

  public struct MachOSummary: Sendable, Codable, Equatable {
    public let fileType: UInt32
    public let dylibCount: Int
    public let weakDylibCount: Int
    public let rpathCount: Int
    public let reexportCount: Int
  }

  public struct EntropySummary: Sendable, Codable, Equatable {
    public let entropy: Double
    public let chiSquare: Double
    public let isEncrypted: Bool
  }

  public struct SuspiciousString: Sendable, Codable, Equatable {
    public let value: String
    public let category: StringCategory
  }
}
