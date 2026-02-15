import Foundation
import os.log

/// Detects process name masquerading — malware using names of legitimate
/// Apple processes but running from wrong paths or with wrong signatures.
/// From: BlueNoroff (keyboardd, airmond), CoinMiner (com.adobe.acc.*),
/// Covid (softwareupdated), CreativeUpdate (mdworker), BlackHole (.JavaUpdater).
public actor MasqueradeDetector {
    public static let shared = MasqueradeDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Masquerade")

    /// Known Apple process names and their expected path prefixes
    static let appleProcesses: [(name: String, expectedPaths: [String])] = [
        ("WindowServer", ["/System/Library/"]),
        ("mdworker", ["/System/Library/"]),
        ("softwareupdated", ["/System/Library/", "/usr/sbin/"]),
        ("mds", ["/System/Library/"]),
        ("launchd", ["/sbin/"]),
        ("loginwindow", ["/System/Library/"]),
        ("Finder", ["/System/Library/"]),
        ("Dock", ["/System/Library/"]),
        ("SystemUIServer", ["/System/Library/"]),
        ("airportd", ["/usr/sbin/"]),
        ("CrashReporter", ["/System/Library/"]),
        ("diskutil", ["/usr/sbin/"]),
        // Additional high-value masquerade targets
        ("securityd", ["/usr/sbin/", "/System/Library/"]),
        ("trustd", ["/usr/sbin/", "/System/Library/"]),
        ("amfid", ["/usr/sbin/", "/System/Library/"]),
        ("tccd", ["/System/Library/"]),
        ("syspolicyd", ["/usr/sbin/", "/System/Library/"]),
        ("coreauthd", ["/System/Library/"]),
        ("secd", ["/usr/sbin/", "/usr/libexec/"]),  // FlexibleFerret masquerades as com.apple.secd
        ("Safari", ["/Applications/Safari.app/", "/System/Library/"]),
        ("Google Chrome", ["/Applications/Google Chrome.app/"]),
        ("Terminal", ["/System/Applications/"]),
        ("Activity Monitor", ["/System/Applications/"]),
        ("Console", ["/System/Applications/"]),
        // DPRK masquerade names
        ("ChromeUpdate", ["/Applications/Google Chrome.app/"]),
        ("CameraAccess", ["/System/Library/"]),
        ("VisualStudioUpdater", []),  // VS for Mac discontinued — should never exist
        ("zoom", ["/Applications/zoom.us.app/"]),
    ]

    /// Scan running processes for masquerade indicators
    public func scan(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)

            for (apName, expectedPaths) in Self.appleProcesses {
                guard name.lowercased() == apName.lowercased() else { continue }

                let matchesExpected = expectedPaths.contains { path.hasPrefix($0) }
                if !matchesExpected && !path.isEmpty {
                    anomalies.append(.forProcess(
                        pid: pid, name: name, path: path,
                        technique: "Process Masquerade",
                        description: "\(name) running from \(path) (expected: \(expectedPaths.joined(separator: ", ")))",
                        severity: .high,
                        mitreID: "T1036.004"
                    ))
                }
            }
        }

        return anomalies
    }
}
