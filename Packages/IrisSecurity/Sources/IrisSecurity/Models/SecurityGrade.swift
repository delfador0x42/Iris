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

        var totalWeight = 0
        var earnedWeight = 0

        for check in checks {
            let w = check.severity.weight
            totalWeight += w
            if check.status == .pass { earnedWeight += w }
            if check.status == .warning { earnedWeight += w / 2 }
        }

        let score = totalWeight > 0 ? earnedWeight * 100 / totalWeight : 0

        // Per-category breakdown
        var catScores: [SecurityCategory: Int] = [:]
        for category in SecurityCategory.allCases {
            let catChecks = checks.filter { $0.category == category }
            guard !catChecks.isEmpty else { continue }
            var catTotal = 0
            var catEarned = 0
            for check in catChecks {
                let w = check.severity.weight
                catTotal += w
                if check.status == .pass { catEarned += w }
                if check.status == .warning { catEarned += w / 2 }
            }
            catScores[category] = catTotal > 0 ? catEarned * 100 / catTotal : 0
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
