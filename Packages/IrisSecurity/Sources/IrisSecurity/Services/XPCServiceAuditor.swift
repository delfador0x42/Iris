import Foundation
import os.log

/// Audits registered XPC services and Mach services for anomalies.
/// APTs plant malicious XPC services inside legitimate app bundles or
/// register their own Mach services for local C2.
public actor XPCServiceAuditor {
    public static let shared = XPCServiceAuditor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "XPCServiceAuditor")
    private let verifier = SigningVerifier.shared

    /// Scan for suspicious XPC services in application bundles.
    /// Targeted scan: checks known XPC locations instead of recursive enumeration.
    /// ~50ms vs ~3s for full recursive walk of /Applications.
    public nonisolated func scanXPCServices() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let fm = FileManager.default

        // XPC services live in well-known locations within .app bundles:
        let xpcSubdirs = ["Contents/XPCServices", "Contents/Library/LoginItems"]
        let apps = (try? fm.contentsOfDirectory(atPath: "/Applications")) ?? []

        for app in apps where app.hasSuffix(".app") {
            let appPath = "/Applications/\(app)"

            // Check parent identity once per app — skip Apple-signed
            let (parentId, _, parentApple) = verifier.signingIdentity(appPath)
            if parentApple { continue }

            // Check XPC bundles in known locations
            for subdir in xpcSubdirs {
                let xpcDir = "\(appPath)/\(subdir)"
                guard let xpcs = try? fm.contentsOfDirectory(atPath: xpcDir) else { continue }
                for xpc in xpcs where xpc.hasSuffix(".xpc") {
                    let xpcPath = "\(xpcDir)/\(xpc)"
                    let (xpcId, _, _) = verifier.signingIdentity(xpcPath)

                    // Unsigned XPC in signed app = suspicious
                    if xpcId == nil && parentId != nil {
                        anomalies.append(ProcessAnomaly(
                            pid: 0, processName: xpc,
                            processPath: xpcPath,
                            parentPID: 0, parentName: app,
                            technique: "Unsigned XPC Service",
                            description: "Unsigned XPC service in signed app bundle: \(xpcPath)",
                            severity: .critical, mitreID: "T1574",
                            scannerId: "xpc_services",
                            enumMethod: "Targeted XPC scan → signingIdentity()",
                            evidence: [
                                "xpc_path=\(xpcPath)",
                                "parent_app=\(appPath)",
                                "parent_id=\(parentId ?? "none")",
                            ]
                        ))
                    }
                }
            }
        }

        return anomalies
    }

    /// Scan launchd plist entries for suspicious Mach service registrations.
    /// Nonisolated — only reads plists, no actor state needed.
    public nonisolated func scanMachServices() -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let launchDirs = [
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
            "\(home)/Library/LaunchAgents"
        ]

        for dir in launchDirs {
            guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else {
                continue
            }
            for file in files where file.hasSuffix(".plist") {
                let path = "\(dir)/\(file)"
                guard let plist = NSDictionary(contentsOfFile: path) else { continue }

                // Check MachServices key
                if let machServices = plist["MachServices"] as? [String: Any] {
                    for (serviceName, _) in machServices {
                        // Non-Apple Mach service in system directory
                        if !serviceName.hasPrefix("com.apple.") &&
                           !dir.contains("/Users/") {
                            let binary = extractBinary(from: plist)
                            anomalies.append(ProcessAnomaly(
                                pid: 0, processName: serviceName,
                                processPath: path,
                                parentPID: 0, parentName: binary ?? "unknown",
                                technique: "Non-Apple Mach Service",
                                description: "Third-party Mach service '\(serviceName)' registered in system directory. Binary: \(binary ?? "unknown")",
                                severity: .medium, mitreID: "T1569.001",
                                scannerId: "xpc_services",
                                enumMethod: "NSDictionary(contentsOfFile:) → MachServices key",
                                evidence: [
                                    "service_name=\(serviceName)",
                                    "plist_path=\(path)",
                                    "binary=\(binary ?? "unknown")",
                                ]
                            ))
                        }
                    }
                }

                // Check for SockPathName (Unix socket — used for local C2)
                if let sockets = plist["Sockets"] as? [String: Any] {
                    for (_, socketConfig) in sockets {
                        if let config = socketConfig as? [String: Any],
                           let sockPath = config["SockPathName"] as? String {
                            if sockPath.hasPrefix("/tmp/") || sockPath.hasPrefix("/var/tmp/") ||
                               sockPath.contains("/.") {
                                anomalies.append(.filesystem(
                                    name: file, path: path,
                                    technique: "Suspicious Unix Socket",
                                    description: "LaunchAgent/Daemon uses Unix socket in suspicious location: \(sockPath)",
                                    severity: .high, mitreID: "T1071",
                                    scannerId: "xpc_services",
                                    enumMethod: "NSDictionary(contentsOfFile:) → Sockets/SockPathName",
                                    evidence: [
                                        "plist=\(file)",
                                        "sock_path=\(sockPath)",
                                        "directory=\(dir)",
                                    ]
                                ))
                            }
                        }
                    }
                }
            }
        }

        return anomalies
    }

    private nonisolated func findParentApp(_ xpcPath: String) -> String? {
        var components = xpcPath.split(separator: "/").map(String.init)
        while !components.isEmpty {
            let path = "/" + components.joined(separator: "/")
            if path.hasSuffix(".app") {
                return path
            }
            components.removeLast()
        }
        return nil
    }

    private nonisolated func extractBinary(from plist: NSDictionary) -> String? {
        if let program = plist["Program"] as? String { return program }
        if let args = plist["ProgramArguments"] as? [String] { return args.first }
        return nil
    }
}
