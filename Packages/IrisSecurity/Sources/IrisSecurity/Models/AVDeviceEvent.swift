import Foundation

/// Type of AV device being monitored
public enum AVDeviceType: String, Sendable, Codable {
    case microphone = "Microphone"
    case camera = "Camera"

    public var icon: String {
        switch self {
        case .microphone: return "mic.fill"
        case .camera: return "video.fill"
        }
    }
}

/// An audio/video device activation or deactivation event
public struct AVDeviceEvent: Identifiable, Sendable, Codable, Equatable {
    public let id: UUID
    public let deviceType: AVDeviceType
    public let deviceName: String
    public let deviceUID: String
    public let isActive: Bool
    public let processID: pid_t?
    public let processName: String?
    public let processPath: String?
    public let timestamp: Date

    public init(
        id: UUID = UUID(),
        deviceType: AVDeviceType,
        deviceName: String,
        deviceUID: String,
        isActive: Bool,
        processID: pid_t? = nil,
        processName: String? = nil,
        processPath: String? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.deviceType = deviceType
        self.deviceName = deviceName
        self.deviceUID = deviceUID
        self.isActive = isActive
        self.processID = processID
        self.processName = processName
        self.processPath = processPath
        self.timestamp = timestamp
    }
}
