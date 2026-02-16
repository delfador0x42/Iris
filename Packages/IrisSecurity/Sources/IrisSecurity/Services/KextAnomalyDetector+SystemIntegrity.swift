import Foundation

/// System extension database scanning + kernel integrity checks
extension KextAnomalyDetector {

    /// Scan system extension database for anomalies
    func scanSystemExtensions() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        let dbPath = "/Library/SystemExtensions/db.plist"
        guard let plist = NSDictionary(contentsOfFile: dbPath),
              let extensions = plist["extensions"] as? [[String: Any]] else {
            return anomalies
        }

        for ext in extensions {
            guard let bundleID = ext["identifier"] as? String,
                  let state = ext["state"] as? String else { continue }

            if bundleID.hasPrefix("com.apple.") { continue }

            if state == "activated_enabled" {
                if let containingPath = ext["containingPath"] as? String {
                    if !FileManager.default.fileExists(atPath: containingPath) {
                        anomalies.append(.filesystem(
                            name: bundleID, path: containingPath,
                            technique: "Orphaned System Extension",
                            description: "System extension \(bundleID) is active but its containing app at \(containingPath) no longer exists. Orphaned extensions may be remnants of removed malware.",
                            severity: .high, mitreID: "T1547.006",
                            scannerId: "kext",
                            enumMethod: "NSDictionary(contentsOfFile:) db.plist parsing",
                            evidence: [
                                "bundle_id: \(bundleID)",
                                "state: \(state)",
                                "containing_path: \(containingPath)",
                                "app_exists: false",
                            ]
                        ))
                    }
                }
            }
        }

        return anomalies
    }

    /// Check hints about kernel integrity (SIP, AMFI)
    func checkKernelIntegrity() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        var size: Int = 0
        if sysctlbyname("kern.bootargs", nil, &size, nil, 0) == 0, size > 0 {
            let allocSize = size + 256
            let buf = UnsafeMutablePointer<CChar>.allocate(capacity: allocSize)
            defer { buf.deallocate() }
            var actualSize = allocSize
            if sysctlbyname("kern.bootargs", buf, &actualSize, nil, 0) == 0 {
                let bootArgs = String(cString: buf).lowercased()

                let suspiciousBootArgs: [(flag: String, description: String)] = [
                    ("amfi_get_out_of_my_way", "AMFI disabled — code signing enforcement bypassed"),
                    ("cs_enforcement_disable", "Code signing enforcement disabled"),
                    ("-v", "Verbose boot — may hide boot-time modifications"),
                    ("debug=", "Kernel debugging enabled"),
                    ("kext-dev-mode", "Kext developer mode — unsigned kexts allowed"),
                ]

                for (flag, desc) in suspiciousBootArgs {
                    if bootArgs.contains(flag) {
                        anomalies.append(.filesystem(
                            name: "kernel", path: "/System/Library/Kernels/kernel",
                            technique: "Suspicious Boot Argument",
                            description: "Boot argument '\(flag)' detected: \(desc). This weakens system security and may indicate tampering.",
                            severity: .critical, mitreID: "T1562.001",
                            scannerId: "kext",
                            enumMethod: "sysctlbyname(kern.bootargs)",
                            evidence: [
                                "boot_flag: \(flag)",
                                "boot_args: \(bootArgs)",
                            ]
                        ))
                    }
                }
            }
        }

        return anomalies
    }
}
