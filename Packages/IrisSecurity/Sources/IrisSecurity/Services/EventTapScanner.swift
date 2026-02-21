import Foundation
import CoreGraphics
import os.log

/// Detects keyboard event taps (keylogger detection, ReiKey-inspired)
public actor EventTapScanner {
    public static let shared = EventTapScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "EventTapScanner")
    private let verifier = SigningVerifier.shared

    // Known benign tapping process signing identifiers
    private let knownBenign: Set<String> = [
        // Apple
        "com.apple.universalaccess", "com.apple.dock",
        "com.apple.SecurityAgent", "com.apple.WindowServer",
        "com.apple.Accessibility-Inspector",
        // Virtualization
        "com.vmware.vmware-vmx", "com.parallels.vm.main",
        // Keyboard remapping / window management
        "org.pqrs.Karabiner-EventViewer", "org.pqrs.karabiner.agent.grabber",
        "org.pqrs.Karabiner-VirtualHIDDevice-Manager",
        "com.knollsoft.Rectangle", "com.crowdcafe.windowmagnet",
        "com.hegenberg.BetterTouchTool", "com.hegenberg.BetterSnapTool",
        "com.koekeishiya.skhd", "com.koekeishiya.yabai",
        // Launchers / productivity
        "com.runningwithcrayons.Alfred", "com.raycast.macos",
        "org.hammerspoon.Hammerspoon",
        // Password managers
        "com.1password.1password", "com.agilebits.onepassword7",
        // Text expansion / automation
        "com.smileonmymac.TextExpander",
        "com.stairways.keyboardmaestro.engine",
        // Terminal / dev tools
        "com.googlecode.iterm2", "net.kovidgoyal.kitty",
        // Peripheral software
        "com.logi.cp-dev-mgr", "com.steelseries.gg",
        "com.elgato.StreamDeck",
        // Menu bar managers
        "com.surteesstudios.Bartender",
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
            let rawPath = ProcessEnumeration.getProcessPath(tap.tappingProcess)
            let processPath = rawPath.isEmpty ? "unknown (\(tap.tappingProcess))" : rawPath
            let processName = (processPath as NSString).lastPathComponent

            // Verify signing
            let (signing, identifier, apple) = verifier.verify(processPath)

            // Determine suspicion
            var reasons: [String] = []
            if isKeyboard && isActive {
                reasons.append("Active keyboard filter (can intercept/modify keystrokes)")
            } else if isKeyboard {
                reasons.append("Keyboard listener (can log keystrokes)")
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

            // Reduce (but never eliminate) suspicion for known benign.
            // Nothing gets a free pass — compromised Apple processes or
            // trojaned known-good apps are still flagged with context.
            if let id = identifier, knownBenign.contains(id) {
                reasons = reasons.map { "[\(id)] \($0)" }
            }

            let targetPath = ProcessEnumeration.getProcessPath(tap.processBeingTapped)
            let targetDesc = isSystemWide ? "All Processes" :
                (targetPath.isEmpty ? "PID \(tap.processBeingTapped)" : targetPath)

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

}
