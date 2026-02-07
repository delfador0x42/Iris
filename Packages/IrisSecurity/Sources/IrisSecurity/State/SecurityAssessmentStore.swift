import Foundation
import os.log

/// State store for security assessment results
@MainActor
public final class SecurityAssessmentStore: ObservableObject {

    // MARK: - Published State

    @Published public private(set) var checks: [SecurityCheck] = []
    @Published public private(set) var grade: SecurityGrade?
    @Published public private(set) var isLoading = false
    @Published public private(set) var lastAssessment: Date?
    @Published public private(set) var errorMessage: String?

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "SecurityAssessmentStore")

    // MARK: - Initialization

    public init() {}

    // MARK: - Public Methods

    /// Run a full security assessment
    public func runAssessment() async {
        isLoading = true
        errorMessage = nil

        let assessor = SecurityAssessor.shared
        let result = await assessor.assess()

        checks = result.checks
        grade = result.grade
        lastAssessment = Date()
        isLoading = false
    }

    /// Checks grouped by category
    public var checksByCategory: [(category: SecurityCategory, checks: [SecurityCheck])] {
        SecurityCategory.allCases.compactMap { category in
            let catChecks = checks.filter { $0.category == category }
            return catChecks.isEmpty ? nil : (category, catChecks)
        }
    }

    /// Count of failing checks
    public var failCount: Int {
        checks.filter { $0.status == .fail }.count
    }

    /// Count of warning checks
    public var warningCount: Int {
        checks.filter { $0.status == .warning }.count
    }

    /// Count of passing checks
    public var passCount: Int {
        checks.filter { $0.status == .pass }.count
    }
}
