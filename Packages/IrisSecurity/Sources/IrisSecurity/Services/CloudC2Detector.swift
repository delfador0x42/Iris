import Foundation
import os.log

/// Detects cloud storage APIs used as C2/exfiltration channels.
/// CloudMensis: pCloud, NotLockBit: AWS S3, Eleanor: Dropbox,
/// ToDoSwift: Google Drive, Phexia: Telegram/Steam dead drop.
public actor CloudC2Detector {
    public static let shared = CloudC2Detector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "CloudC2")

    /// Cloud storage API hostnames (C2/exfil channels)
    static let cloudAPIs: [(host: String, service: String)] = [
        ("api.pcloud.com", "pCloud"),
        ("content.dropboxapi.com", "Dropbox"),
        ("api.dropboxapi.com", "Dropbox"),
        ("s3.amazonaws.com", "AWS S3"),
        ("storage.googleapis.com", "Google Cloud"),
        ("drive.google.com", "Google Drive"),
        ("graph.microsoft.com", "OneDrive"),
    ]

    /// Dead drop resolver hostnames
    static let deadDrops: [(host: String, service: String)] = [
        ("api.telegram.org", "Telegram"),
        ("steamcommunity.com", "Steam Community"),
        ("pastebin.com", "Pastebin"),
        ("raw.githubusercontent.com", "GitHub Raw"),
        ("gist.githubusercontent.com", "GitHub Gist"),
    ]

    /// Browser signing IDs that legitimately access these
    static let browserIds: Set<String> = [
        "com.apple.Safari", "com.google.Chrome", "org.mozilla.firefox",
        "com.brave.Browser", "com.microsoft.edgemac", "com.operasoftware.Opera",
    ]

    /// Batch scan connections for cloud C2/exfil patterns
    public func scan(connections: [NetworkConnection]) -> [ProcessAnomaly] {
        var results: [ProcessAnomaly] = []
        for conn in connections {
            guard let hostname = conn.remoteHostname, !hostname.isEmpty else { continue }
            if let anomaly = check(
                hostname: hostname, processName: conn.processName,
                signingId: conn.signingId, pid: conn.processId
            ) {
                results.append(ProcessAnomaly(
                    pid: conn.processId, processName: conn.processName,
                    processPath: conn.processPath,
                    parentPID: 0, parentName: "",
                    technique: "Cloud C2/Exfiltration",
                    description: anomaly.description,
                    severity: anomaly.severity, mitreID: "T1567.002"
                ))
            }
        }
        return results
    }

    /// Check a connection against cloud C2 patterns
    public func check(
        hostname: String, processName: String,
        signingId: String?, pid: pid_t
    ) -> NetworkAnomaly? {
        // Skip browsers
        if let sid = signingId, Self.browserIds.contains(sid) { return nil }
        let browserNames = ["Safari", "Google Chrome", "Firefox", "Brave Browser"]
        if browserNames.contains(processName) { return nil }

        // Check cloud APIs
        for (host, svc) in Self.cloudAPIs where hostname.contains(host) {
            return NetworkAnomaly(
                type: .rawIPConnection,
                processName: processName,
                remoteAddress: hostname,
                description: "\(processName) (PID \(pid)) connecting to \(svc) API — possible cloud C2/exfil",
                severity: .high,
                connectionCount: 1,
                averageInterval: 0
            )
        }

        // Check dead drop resolvers
        for (host, svc) in Self.deadDrops where hostname.contains(host) {
            return NetworkAnomaly(
                type: .suspiciousPort,
                processName: processName,
                remoteAddress: hostname,
                description: "\(processName) (PID \(pid)) connecting to \(svc) — possible dead drop resolver",
                severity: .high,
                connectionCount: 1,
                averageInterval: 0
            )
        }

        return nil
    }
}
