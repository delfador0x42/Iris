import Foundation

/// Scan kext directories on disk for unsigned/suspicious kexts
extension KextAnomalyDetector {

    func scanDiskKexts() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let fm = FileManager.default

        let kextDirs = [
            "/Library/Extensions",
            "/Library/StagedExtensions",
        ]

        for dir in kextDirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir) else { continue }

            for item in items where item.hasSuffix(".kext") {
                let kextPath = "\(dir)/\(item)"

                let (status, _, _) = await SigningVerifier.shared.verify(kextPath)

                if status == .unsigned {
                    anomalies.append(.filesystem(
                        name: item, path: kextPath,
                        technique: "Unsigned Kernel Extension",
                        description: "Unsigned kext found at \(kextPath). Unsigned kernel extensions are extremely dangerous — they execute with full kernel privileges.",
                        severity: .critical, mitreID: "T1547.006",
                        scannerId: "kext",
                        enumMethod: "codesign --verify",
                        evidence: [
                            "path: \(kextPath)",
                            "signing_status: unsigned",
                        ]
                    ))
                } else if status == .invalid {
                    anomalies.append(.filesystem(
                        name: item, path: kextPath,
                        technique: "Invalid Kext Signature",
                        description: "Kernel extension at \(kextPath) has an INVALID signature. This kext may have been tampered with.",
                        severity: .critical, mitreID: "T1553.002",
                        scannerId: "kext",
                        enumMethod: "codesign --verify",
                        evidence: [
                            "path: \(kextPath)",
                            "signing_status: invalid",
                        ]
                    ))
                }

                anomalies += checkIOKitPersonalities(item: item, kextPath: kextPath)
            }
        }

        return anomalies
    }

    private func checkIOKitPersonalities(item: String, kextPath: String) -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let plistPath = "\(kextPath)/Contents/Info.plist"
        guard let plist = NSDictionary(contentsOfFile: plistPath),
              let personalities = plist["IOKitPersonalities"] as? [String: Any] else {
            return anomalies
        }

        let suspiciousClasses = [
            "IOHIDEventDriver",      // Input interception (keylogger)
            "IONetworkController",    // Network filtering
            "IOBlockStorageDriver",   // Disk access hooking
            "IOUSBHostDevice",        // USB device interception
        ]

        for (name, personality) in personalities {
            guard let config = personality as? [String: Any],
                  let ioClass = config["IOClass"] as? String else { continue }

            for suspicious in suspiciousClasses where ioClass.contains(suspicious) {
                anomalies.append(.filesystem(
                    name: item, path: kextPath,
                    technique: "Kext Hooks \(suspicious)",
                    description: "Kext \(item) personality '\(name)' hooks IOKit class \(ioClass). This enables deep system interception.",
                    severity: .high, mitreID: "T1014",
                    scannerId: "kext",
                    enumMethod: "Info.plist IOKitPersonalities parsing",
                    evidence: [
                        "kext: \(item)",
                        "personality: \(name)",
                        "io_class: \(ioClass)",
                        "hooked_subsystem: \(suspicious)",
                    ]
                ))
            }
        }

        return anomalies
    }
}
