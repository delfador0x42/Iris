import Foundation

/// Overall security posture grade computed from individual checks
public struct SecurityGrade: Sendable, Codable, Equatable {
    /// Letter grade: A, B, C, D, or F
    public let letter: String
    /// Numeric score 0-100
    public let score: Int
    /// Per-category scores (0-100)
    public let categoryScores: [SecurityCategory: Int]

    /// Compute grade from a set of security checks.
    /// Score = (sum of weights for passing checks) / (sum of all weights) * 100
    /// Weights: critical=20, high=15, medium=10, low=5, info=2
    public static func compute(from checks: [SecurityCheck]) -> SecurityGrade {
        guard !checks.isEmpty else {
            return SecurityGrade(letter: "?", score: 0, categoryScores: [:])
        }

        // Single pass: accumulate overall + per-category weights simultaneously
        var totalWeight = 0
        var earnedWeight = 0
        var catTotal: [SecurityCategory: Int] = [:]
        var catEarned: [SecurityCategory: Int] = [:]

        for check in checks {
            let w = check.severity.weight
            let earned = check.status == .pass ? w : (check.status == .warning ? w / 2 : 0)
            totalWeight += w
            earnedWeight += earned
            catTotal[check.category, default: 0] += w
            catEarned[check.category, default: 0] += earned
        }

        let score = totalWeight > 0 ? earnedWeight * 100 / totalWeight : 0

        var catScores: [SecurityCategory: Int] = [:]
        for (cat, total) in catTotal {
            catScores[cat] = total > 0 ? (catEarned[cat, default: 0]) * 100 / total : 0
        }

        return SecurityGrade(
            letter: letterGrade(for: score),
            score: score,
            categoryScores: catScores
        )
    }

    private static func letterGrade(for score: Int) -> String {
        switch score {
        case 90...100: return "A"
        case 80..<90: return "B"
        case 70..<80: return "C"
        case 60..<70: return "D"
        default: return "F"
        }
    }
}
