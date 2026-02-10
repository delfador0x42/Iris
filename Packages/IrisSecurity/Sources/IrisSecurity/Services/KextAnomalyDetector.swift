import Foundation
import os.log

/// Detects suspicious kernel extensions and driver anomalies.
/// Nation-state actors load kernel extensions to:
/// - Install rootkits (hide processes, files, network connections)
/// - Install keyloggers at the kernel level
/// - Intercept system calls
/// - Disable security features (SIP bypass via kext)
/// MITRE ATT&CK: T1547.006 (Kernel Modules and Extensions),
/// T1014 (Rootkit), T1562.001 (Disable or Modify Tools)
public actor KextAnomalyDetector {
    public static let shared = KextAnomalyDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "KextAnomaly")

    /// Known legitimate kext publishers (signing team IDs)
    private static let trustedTeamIDs: Set<String> = [
        "com.apple", // Apple
    ]

    /// Suspicious kext names/patterns from known macOS rootkits and malware
    private static let knownMaliciousPatterns: [String] = [
        // Real macOS rootkits and malware
        "rubilyn",       // macOS rootkit (kernel-level process hiding)
        "fruitfly",      // Fruitfly spyware kext component
        "thiefquest",    // ThiefQuest/EvilQuest ransomware
        "zuru",          // ZuRu trojan (modified Xcode)
        "shlayer",       // Shlayer adware/dropper
        "cdrthief",      // CDRThief targeting softswitch
        "keydnap",       // Keydnap credential stealer
        "calisto",       // Calisto backdoor (Proton variant)
        "xcsset",        // XCSSET malware
        "osx.dummy",     // OSX.Dummy cryptominer
        // Generic suspicious patterns
        "hideproc",      // process hiding kext
        "hidefile",      // file hiding kext
        "rootkit",       // explicit rootkit in name
        "keylog",        // keylogger kext
        "inject",        // code injection kext
    ]

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // 1. Get loaded kernel extensions
        let loadedKexts = await getLoadedKexts()
        anomalies.append(contentsOf: loadedKexts)

        // 2. Check for unsigned/suspicious kexts on disk
        let diskKexts = await scanDiskKexts()
        anomalies.append(contentsOf: diskKexts)

        // 3. Check for system extension anomalies
        let sysExts = await scanSystemExtensions()
        anomalies.append(contentsOf: sysExts)

        // 4. Check kernel integrity hints
        let kernelHints = checkKernelIntegrity()
        anomalies.append(contentsOf: kernelHints)

        return anomalies
    }

    /// Get currently loaded kernel extensions via kextstat
    private func getLoadedKexts() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        let output = await runCommand("/usr/sbin/kextstat", args: ["-l"])
        let lines = output.split(separator: "\n").dropFirst() // Skip header

        for line in lines {
            let cols = line.split(separator: " ", maxSplits: 6).map(String.init)
            guard cols.count >= 6 else { continue }

            let bundleID = cols[5]

            // Apple kexts are normal
            if bundleID.hasPrefix("com.apple.") { continue }

            // Third-party loaded kext — always flag
            let severity: AnomalySeverity
            let description: String

            // Check against known malicious patterns
            let lower = bundleID.lowercased()
            let isKnownMalicious = Self.knownMaliciousPatterns.contains { lower.contains($0) }

            if isKnownMalicious {
                severity = .critical
                description = "Loaded kernel extension \(bundleID) matches known rootkit pattern."
            } else {
                severity = .medium
                description = "Third-party kernel extension loaded: \(bundleID). Non-Apple kexts can intercept system calls, hide processes, and bypass security."
            }

            anomalies.append(ProcessAnomaly(
                pid: 0, processName: bundleID, processPath: "",
                parentPID: 0, parentName: "",
                technique: "Loaded Kernel Extension",
                description: description,
                severity: severity, mitreID: "T1547.006"
            ))
        }

        return anomalies
    }

    /// Scan kext directories on disk for unsigned/suspicious kexts
    private func scanDiskKexts() async -> [ProcessAnomaly] {
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

                // Check code signing
                let (status, teamID, isApple) = await SigningVerifier.shared.verify(kextPath)

                if status == .unsigned {
                    anomalies.append(ProcessAnomaly(
                        pid: 0, processName: item, processPath: kextPath,
                        parentPID: 0, parentName: "",
                        technique: "Unsigned Kernel Extension",
                        description: "Unsigned kext found at \(kextPath). Unsigned kernel extensions are extremely dangerous — they execute with full kernel privileges.",
                        severity: .critical, mitreID: "T1547.006"
                    ))
                } else if status == .invalid {
                    anomalies.append(ProcessAnomaly(
                        pid: 0, processName: item, processPath: kextPath,
                        parentPID: 0, parentName: "",
                        technique: "Invalid Kext Signature",
                        description: "Kernel extension at \(kextPath) has an INVALID signature. This kext may have been tampered with.",
                        severity: .critical, mitreID: "T1553.002"
                    ))
                }

                // Check Info.plist for suspicious IOKit matching
                let plistPath = "\(kextPath)/Contents/Info.plist"
                if let plist = NSDictionary(contentsOfFile: plistPath) {
                    // Check for IOKit personalities that hook into key subsystems
                    if let personalities = plist["IOKitPersonalities"] as? [String: Any] {
                        for (name, personality) in personalities {
                            guard let config = personality as? [String: Any],
                                  let ioClass = config["IOClass"] as? String else { continue }

                            // These classes indicate deep system hooking
                            let suspiciousClasses = [
                                "IOHIDEventDriver", // Input interception (keylogger)
                                "IONetworkController", // Network filtering
                                "IOBlockStorageDriver", // Disk access hooking
                                "IOUSBHostDevice", // USB device interception
                            ]

                            for suspicious in suspiciousClasses where ioClass.contains(suspicious) {
                                anomalies.append(ProcessAnomaly(
                                    pid: 0, processName: item, processPath: kextPath,
                                    parentPID: 0, parentName: "",
                                    technique: "Kext Hooks \(suspicious)",
                                    description: "Kext \(item) personality '\(name)' hooks IOKit class \(ioClass). This enables deep system interception.",
                                    severity: .high, mitreID: "T1014"
                                ))
                            }
                        }
                    }
                }
            }
        }

        return anomalies
    }

    /// Scan system extension database for anomalies
    private func scanSystemExtensions() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // Check system extensions database
        let dbPath = "/Library/SystemExtensions/db.plist"
        guard let plist = NSDictionary(contentsOfFile: dbPath),
              let extensions = plist["extensions"] as? [[String: Any]] else {
            return anomalies
        }

        for ext in extensions {
            guard let bundleID = ext["identifier"] as? String,
                  let state = ext["state"] as? String else { continue }

            // Skip Apple extensions
            if bundleID.hasPrefix("com.apple.") { continue }

            // Check for extensions in unexpected states
            if state == "activated_enabled" {
                // Verify the containing app still exists
                if let containingPath = ext["containingPath"] as? String {
                    if !FileManager.default.fileExists(atPath: containingPath) {
                        anomalies.append(ProcessAnomaly(
                            pid: 0, processName: bundleID, processPath: containingPath,
                            parentPID: 0, parentName: "",
                            technique: "Orphaned System Extension",
                            description: "System extension \(bundleID) is active but its containing app at \(containingPath) no longer exists. Orphaned extensions may be remnants of removed malware.",
                            severity: .high, mitreID: "T1547.006"
                        ))
                    }
                }
            }
        }

        return anomalies
    }

    /// Check hints about kernel integrity (SIP, AMFI)
    private func checkKernelIntegrity() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // Check boot-args for suspicious flags via sysctl
        var size: Int = 0
        if sysctlbyname("kern.bootargs", nil, &size, nil, 0) == 0, size > 0 {
            // Allocate with margin to handle size changes between calls
            let allocSize = size + 256
            let buf = UnsafeMutablePointer<CChar>.allocate(capacity: allocSize)
            defer { buf.deallocate() }
            var actualSize = allocSize
            if sysctlbyname("kern.bootargs", buf, &actualSize, nil, 0) == 0 {
                let bootArgs = String(cString: buf).lowercased()

                // Suspicious boot arguments that weaken security
                let suspiciousBootArgs: [(flag: String, description: String)] = [
                    ("amfi_get_out_of_my_way", "AMFI disabled — code signing enforcement bypassed"),
                    ("cs_enforcement_disable", "Code signing enforcement disabled"),
                    ("-v", "Verbose boot — may hide boot-time modifications"),
                    ("debug=", "Kernel debugging enabled"),
                    ("kext-dev-mode", "Kext developer mode — unsigned kexts allowed"),
                ]

                for (flag, desc) in suspiciousBootArgs {
                    if bootArgs.contains(flag) {
                        anomalies.append(ProcessAnomaly(
                            pid: 0, processName: "kernel",
                            processPath: "/System/Library/Kernels/kernel",
                            parentPID: 0, parentName: "",
                            technique: "Suspicious Boot Argument",
                            description: "Boot argument '\(flag)' detected: \(desc). This weakens system security and may indicate tampering.",
                            severity: .critical, mitreID: "T1562.001"
                        ))
                    }
                }
            }
        }

        return anomalies
    }

    private func runCommand(_ path: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            } catch {
                continuation.resume(returning: "")
            }
        }
    }
}
