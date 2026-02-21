import Foundation
import os.log

/// Compares a process's runtime entitlements against its on-disk entitlements.
///
/// Lie detected: "This process has always had these entitlements"
/// Ground truth: Parse embedded entitlements from Mach-O __TEXT,__entitlements
///               on disk, compare against SecCodeCopySigningInformation() runtime query.
///               If runtime has entitlements not present on disk → injection.
///
/// What this catches:
/// - AMFI bypass: process gained entitlements it was never signed with
/// - task_for_pid abuse: attacker injected entitlements into running process
/// - Code signing spoofing: modified binary still reports old entitlements
///
/// Adversary cost: Would need to hook SecCodeCopySigningInformation AND
/// modify the on-disk Mach-O — or patch AMFI to suppress the check.
public actor EntitlementContradictionProbe {
    public static let shared = EntitlementContradictionProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "EntitlementContradiction")

    /// Critical entitlements that APTs want
    private let dangerousEntitlements: Set<String> = [
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.debugger",
        "com.apple.private.security.no-sandbox",
        "com.apple.private.tcc.allow",
        "com.apple.rootless.install",
        "com.apple.rootless.install.heritable",
        "platform-application",
        "com.apple.system-task-ports",
        "task_for_pid-allow",
    ]

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            let path = snapshot.path(for: pid)
            guard !path.isEmpty else { continue }
            guard !path.hasPrefix("/System/") && !path.hasPrefix("/usr/") && !path.hasPrefix("/sbin/") else {
                continue // skip sealed system volume binaries
            }

            let diskEntitlements = readDiskEntitlements(path: path)
            let runtimeEntitlements = readRuntimeEntitlements(pid: pid)

            guard let disk = diskEntitlements, let runtime = runtimeEntitlements else { continue }

            // Find entitlements present at runtime but NOT on disk
            let injected = runtime.subtracting(disk)

            // Only flag dangerous injected entitlements
            let dangerousInjected = injected.intersection(dangerousEntitlements)
            guard !dangerousInjected.isEmpty else { continue }

            let name = snapshot.name(for: pid) ?? "unknown"
            anomalies.append(.forProcess(
                pid: pid, name: name, path: path,
                technique: "Runtime Entitlement Injection",
                description: "Process '\(name)' has \(dangerousInjected.count) dangerous entitlement(s) at runtime not present in on-disk binary.",
                severity: .critical, mitreID: "T1548",
                scannerId: "entitlement_contradiction",
                enumMethod: "SecCodeCopySigningInformation vs Mach-O __TEXT,__entitlements",
                evidence: ["pid: \(pid)", "path: \(path)"] +
                    dangerousInjected.sorted().map { "injected: \($0)" } +
                    ["disk_entitlements: \(disk.count)", "runtime_entitlements: \(runtime.count)"]
            ))
            logger.critical("ENTITLEMENT INJECTION: \(name) (PID \(pid)) has injected: \(dangerousInjected)")
        }

        return anomalies
    }

    // MARK: - On-Disk Entitlements

    /// Parse entitlements from the Mach-O binary's code signature.
    private func readDiskEntitlements(path: String) -> Set<String>? {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode) == errSecSuccess,
              let code = staticCode else { return nil }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }

        guard let entData = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else {
            return Set() // no entitlements = empty set (valid)
        }

        return Set(entData.keys)
    }

    // MARK: - Runtime Entitlements

    /// Query entitlements of a running process via Security framework.
    private func readRuntimeEntitlements(pid: pid_t) -> Set<String>? {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as NSDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code) == errSecSuccess,
              let guestCode = code else { return nil }

        // Convert dynamic SecCode to SecStaticCode for signing info query
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
              let sc = staticCode else { return nil }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }

        guard let entData = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any] else {
            return Set()
        }

        return Set(entData.keys)
    }
}
