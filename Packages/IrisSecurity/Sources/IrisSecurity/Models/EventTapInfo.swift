import Foundation
import CoreGraphics

/// Information about a keyboard event tap (keylogger detection)
public struct EventTapInfo: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let tapID: UInt32
    public let tappingPID: pid_t
    public let tappingProcessName: String
    public let tappingProcessPath: String
    public let targetPID: pid_t
    public let targetDescription: String
    public let isActiveFilter: Bool
    public let isKeyboardTap: Bool
    public let isSystemWide: Bool
    public let isSuspicious: Bool
    public let suspicionReasons: [String]
    public let signingStatus: SigningStatus
    public let eventMask: UInt64

    public init(
        id: UUID = UUID(),
        tapID: UInt32,
        tappingPID: pid_t,
        tappingProcessName: String,
        tappingProcessPath: String,
        targetPID: pid_t,
        targetDescription: String,
        isActiveFilter: Bool,
        isKeyboardTap: Bool,
        isSystemWide: Bool,
        isSuspicious: Bool = false,
        suspicionReasons: [String] = [],
        signingStatus: SigningStatus = .unknown,
        eventMask: UInt64 = 0
    ) {
        self.id = id
        self.tapID = tapID
        self.tappingPID = tappingPID
        self.tappingProcessName = tappingProcessName
        self.tappingProcessPath = tappingProcessPath
        self.targetPID = targetPID
        self.targetDescription = targetDescription
        self.isActiveFilter = isActiveFilter
        self.isKeyboardTap = isKeyboardTap
        self.isSystemWide = isSystemWide
        self.isSuspicious = isSuspicious
        self.suspicionReasons = suspicionReasons
        self.signingStatus = signingStatus
        self.eventMask = eventMask
    }
}
