import Foundation
import os.log

/// Runs all security checks and computes an overall security grade.
/// Entry point for the security assessment engine.
public actor SecurityAssessor {
    public static let shared = SecurityAssessor()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityAssessor")

    /// Run all security checks and return results with grade
    public func assess() async -> (checks: [SecurityCheck], grade: SecurityGrade) {
        logger.info("Starting security assessment")

        var allChecks: [SecurityCheck] = []

        // System-level checks (SIP, FileVault, Gatekeeper, Firewall, etc.)
        let systemChecks = await SystemSecurityChecks.runAll()
        allChecks.append(contentsOf: systemChecks)

        // Sort by severity (critical first) then by category
        allChecks.sort { lhs, rhs in
            if lhs.severity != rhs.severity { return lhs.severity > rhs.severity }
            return lhs.category.rawValue < rhs.category.rawValue
        }

        let grade = SecurityGrade.compute(from: allChecks)
        logger.info("Assessment complete: \(grade.letter) (\(grade.score)/100), \(allChecks.count) checks")

        return (allChecks, grade)
    }
}
