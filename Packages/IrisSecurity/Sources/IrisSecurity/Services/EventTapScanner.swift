import Foundation
import CoreGraphics
import os.log

/// Detects keyboard event taps (keylogger detection, ReiKey-inspired)
public actor EventTapScanner {
    public static let shared = EventTapScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "EventTapScanner")
    private let verifier = SigningVerifier.shared

    // Known benign tapping process identifiers
    private let knownBenign: Set<String> = [
        "com.vmware.vmware-vmx",
        "com.apple.universalaccess",
        "com.apple.dock",
        "com.apple.SecurityAgent",
        "com.apple.WindowServer"
    ]

    /// Enumerate all active event taps and identify suspicious ones
    public func scan() async -> [EventTapInfo] {
        var tapCount: UInt32 = 0
        guard CGGetEventTapList(0, nil, &tapCount) == .success, tapCount > 0 else {
            return []
        }

        var taps = [CGEventTapInformation](repeating: CGEventTapInformation(), count: Int(tapCount))
        guard CGGetEventTapList(tapCount, &taps, &tapCount) == .success else {
            return []
        }

        var results: [EventTapInfo] = []
        for i in 0..<Int(tapCount) {
            let tap = taps[i]
            guard tap.enabled else { continue }

            let keyUpMask = CGEventMask(1 << CGEventType.keyUp.rawValue)
            let keyDownMask = CGEventMask(1 << CGEventType.keyDown.rawValue)
            let flagsMask = CGEventMask(1 << CGEventType.flagsChanged.rawValue)
            let isKeyboard = (tap.eventsOfInterest & keyUpMask) != 0 ||
                             (tap.eventsOfInterest & keyDownMask) != 0 ||
                             (tap.eventsOfInterest & flagsMask) != 0

            let isActive = tap.options == .defaultTap
            let isSystemWide = tap.processBeingTapped == 0
            let processPath = Self.getProcessPath(tap.tappingProcess)
            let processName = URL(fileURLWithPath: processPath).lastPathComponent

            // Verify signing
            let (signing, identifier, apple) = await verifier.verify(processPath)

            // Determine suspicion
            var reasons: [String] = []
            if isKeyboard && isActive {
                reasons.append("Active keyboard filter (can intercept keystrokes)")
            }
            if isKeyboard && isSystemWide {
                reasons.append("System-wide keyboard monitoring")
            }
            if !apple && isKeyboard {
                reasons.append("Non-Apple process tapping keyboard")
            }
            if signing == .unsigned && isKeyboard {
                reasons.append("Unsigned process with keyboard tap")
            }

            // Remove suspicion for known benign
            if let id = identifier, knownBenign.contains(id) {
                reasons.removeAll()
            }
            if apple { reasons.removeAll() }

            let targetDesc = isSystemWide ? "All Processes" :
                Self.getProcessPath(tap.processBeingTapped)

            results.append(EventTapInfo(
                tapID: tap.eventTapID,
                tappingPID: tap.tappingProcess,
                tappingProcessName: processName,
                tappingProcessPath: processPath,
                targetPID: tap.processBeingTapped,
                targetDescription: targetDesc,
                isActiveFilter: isActive,
                isKeyboardTap: isKeyboard,
                isSystemWide: isSystemWide,
                isSuspicious: !reasons.isEmpty,
                suspicionReasons: reasons,
                signingStatus: signing,
                eventMask: UInt64(tap.eventsOfInterest)
            ))
        }

        return results.sorted { $0.isSuspicious && !$1.isSuspicious }
    }

    /// Get the executable path for a PID
    static func getProcessPath(_ pid: pid_t) -> String {
        let pathBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { pathBuffer.deallocate() }
        let len = proc_pidpath(pid, pathBuffer, UInt32(MAXPATHLEN))
        guard len > 0 else { return "unknown (\(pid))" }
        return String(cString: pathBuffer)
    }
}
