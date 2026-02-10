import Foundation

/// Result of code signing verification with full details
public struct VerificationResult: Sendable {
    public let status: SigningStatus
    public let identifier: String?
    public let teamID: String?
    public let isApple: Bool
    public let isHardenedRuntime: Bool

    public init(
        status: SigningStatus,
        identifier: String? = nil,
        teamID: String? = nil,
        isApple: Bool = false,
        isHardenedRuntime: Bool = false
    ) {
        self.status = status
        self.identifier = identifier
        self.teamID = teamID
        self.isApple = isApple
        self.isHardenedRuntime = isHardenedRuntime
    }
}
