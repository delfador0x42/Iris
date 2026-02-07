import Foundation
import os.log

/// Enumerates all persistence mechanisms on the system (KnockKnock-inspired)
public actor PersistenceScanner {
    public static let shared = PersistenceScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "PersistenceScanner")
    let verifier = SigningVerifier.shared

    /// Scan all persistence locations and return combined results
    public func scanAll() async -> [PersistenceItem] {
        async let daemons = scanLaunchDaemons()
        async let agents = scanLaunchAgents()
        async let logins = scanLoginItems()
        async let crons = scanCronJobs()
        async let kexts = scanKernelExtensions()
        async let sysexts = scanSystemExtensions()
        async let browser = scanBrowserExtensions()
        async let authPlugins = scanAuthorizationPlugins()
        async let hooks = scanLoginHooks()
        async let startup = scanStartupScripts()
        async let shells = scanShellConfigs()
        async let dylibs = scanDylibInserts()
        async let periodic = scanPeriodicScripts()

        let all = await [
            daemons, agents, logins, crons, kexts, sysexts,
            browser, authPlugins, hooks, startup, shells, dylibs, periodic
        ]
        return all.flatMap { $0 }
    }
}
