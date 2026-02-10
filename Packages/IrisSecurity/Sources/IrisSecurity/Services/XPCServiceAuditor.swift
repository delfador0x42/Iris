import Foundation
import os.log

/// Audits registered XPC services and Mach services for anomalies.
/// APTs plant malicious XPC services inside legitimate app bundles or
/// register their own Mach services for local C2.
public actor XPCServiceAuditor {
    public static let shared = XPCServiceAuditor()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "XPCServiceAuditor")
    private let verifier = SigningVerifier.shared

    /// Scan for suspicious XPC services in application bundles
    public func scanXPCServices() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let fm = FileManager.default
        let appDirs = ["/Applications", "/Library/Application Support"]

        for appDir in appDirs {
            guard let enumerator = fm.enumerator(atPath: appDir) else { continue }
            while let path = enumerator.nextObject() as? String {
                let fullPath = "\(appDir)/\(path)"

                // Look for XPC service bundles
                if path.hasSuffix(".xpc") {
                    // Check if the XPC service is signed differently than its parent app
                    let parentApp = findParentApp(fullPath)
                    if let parent = parentApp {
                        let (parentSigning, parentId, parentApple) = verifier.verify(parent)
                        let (xpcSigning, xpcId, xpcApple) = verifier.verify(fullPath)

                        // Mismatched signing = suspicious
                        if parentApple && !xpcApple {
                            anomalies.append(ProcessAnomaly(
                                pid: 0, processName: URL(fileURLWithPath: fullPath).lastPathComponent,
                                processPath: fullPath,
                                parentPID: 0, parentName: URL(fileURLWithPath: parent).lastPathComponent,
                                technique: "XPC Service Signing Mismatch",
                                description: "XPC service in \(parent) has different signing than parent app. Parent: \(parentSigning.rawValue), XPC: \(xpcSigning.rawValue)",
                                severity: .critical, mitreID: "T1574"
                            ))
                        }

                        // Unsigned XPC service in signed app
                        if xpcSigning == .unsigned && parentSigning != .unsigned {
                            anomalies.append(ProcessAnomaly(
                                pid: 0, processName: URL(fileURLWithPath: fullPath).lastPathComponent,
                                processPath: fullPath,
                                parentPID: 0, parentName: URL(fileURLWithPath: parent).lastPathComponent,
                                technique: "Unsigned XPC Service",
                                description: "Unsigned XPC service in signed app bundle: \(fullPath)",
                                severity: .critical, mitreID: "T1574"
                            ))
                        }
                    }
                }
            }
        }

        return anomalies
    }

    /// Scan launchd plist entries for suspicious Mach service registrations
    public func scanMachServices() async -> [ProcessAnomaly] {
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
                                severity: .medium, mitreID: "T1569.001"
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
                                    severity: .high, mitreID: "T1071"
                                ))
                            }
                        }
                    }
                }
            }
        }

        return anomalies
    }

    private func findParentApp(_ xpcPath: String) -> String? {
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

    private func extractBinary(from plist: NSDictionary) -> String? {
        if let program = plist["Program"] as? String { return program }
        if let args = plist["ProgramArguments"] as? [String] { return args.first }
        return nil
    }
}
