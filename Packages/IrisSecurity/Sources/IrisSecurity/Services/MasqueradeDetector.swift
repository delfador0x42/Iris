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

    /// Scan running processes for masquerade indicators.
    /// Contradiction-based: process claims Apple name but code signature disagrees.
    /// Source 1: Process name (from sysctl/KERN_PROCARGS2).
    /// Source 2: Code signature of the binary at that path.
    /// Contradiction: name matches known Apple process but binary is NOT Apple-signed.
    /// This replaces the path-prefix allowlist which couldn't track all valid locations.
    public func scan(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)

            for (apName, _) in Self.appleProcesses {
                guard name.lowercased() == apName.lowercased() else { continue }
                guard !path.isEmpty else { continue }

                // Cross-validate: does the binary's code signature confirm Apple origin?
                let signing = CodeSignValidator.validate(path: path)

                if signing.isAppleSigned && signing.isValidSignature {
                    // Name claims Apple, signature confirms Apple — consistent, skip.
                    continue
                }

                // Contradiction: claims Apple name but signature says otherwise.
                let sigDetail: String
                if !signing.isSigned {
                    sigDetail = "UNSIGNED"
                } else if !signing.isValidSignature {
                    sigDetail = "INVALID signature"
                } else {
                    sigDetail = "signed by \(signing.teamIdentifier ?? signing.signingIdentifier ?? "unknown")"
                }

                anomalies.append(.forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Process Masquerade",
                    description: "\(name) claims Apple identity but binary is \(sigDetail). Path: \(path)",
                    severity: signing.isSigned ? .high : .critical,
                    mitreID: "T1036.004",
                    scannerId: "masquerade",
                    enumMethod: "sysctl(KERN_PROCARGS2) name + SecStaticCode signature cross-validation",
                    evidence: [
                        "process: \(name)",
                        "actual_path: \(path)",
                        "apple_signed: \(signing.isAppleSigned)",
                        "signature_valid: \(signing.isValidSignature)",
                        "signing_id: \(signing.signingIdentifier ?? "none")",
                        "team_id: \(signing.teamIdentifier ?? "none")",
                    ]
                ))
            }
        }

        return anomalies
    }
}
