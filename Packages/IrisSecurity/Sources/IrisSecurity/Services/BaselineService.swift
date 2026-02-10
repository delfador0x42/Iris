import Foundation
import os.log

/// Loads the stock macOS 26.2 baseline from IPSW-extracted data.
/// Provides context tags only — tells you what ships with stock macOS.
/// Does NOT grant passes or reduce suspicion scores.
public final class BaselineService: Sendable {
    public static let shared = BaselineService()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Baseline")

    private let daemonLabels: Set<String>
    private let agentLabels: Set<String>
    private let kextBundleIDs: Set<String>
    private let authPlugins: Set<String>
    private let periodicScripts: Set<String>
    private let shellConfigs: Set<String>

    private init() {
        var daemons = Set<String>()
        var agents = Set<String>()
        var kexts = Set<String>()
        var auth = Set<String>()
        var periodic = Set<String>()
        var shells = Set<String>()

        if let url = Bundle.main.url(forResource: "baseline-25C56", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            daemons = Set((json["launchDaemonLabels"] as? [String]) ?? [])
            agents = Set((json["launchAgentLabels"] as? [String]) ?? [])
            kexts = Set((json["kextBundleIDs"] as? [String]) ?? [])
            auth = Set((json["authPlugins"] as? [String]) ?? [])
            periodic = Set((json["periodicScripts"] as? [String]) ?? [])
            shells = Set((json["shellConfigs"] as? [String]) ?? [])
        }

        self.daemonLabels = daemons
        self.agentLabels = agents
        self.kextBundleIDs = kexts
        self.authPlugins = auth
        self.periodicScripts = periodic
        self.shellConfigs = shells

        let total = daemons.count + agents.count + kexts.count + auth.count
        if total > 0 {
            logger.info("Loaded baseline: \(daemons.count) daemons, \(agents.count) agents, \(kexts.count) kexts, \(auth.count) plugins")
        } else {
            logger.warning("No baseline data loaded — baseline-25C56.json not found in bundle")
        }
    }

    public func isBaselineDaemon(_ label: String) -> Bool { daemonLabels.contains(label) }
    public func isBaselineAgent(_ label: String) -> Bool { agentLabels.contains(label) }
    public func isBaselineKext(_ bundleID: String) -> Bool { kextBundleIDs.contains(bundleID) }
    public func isBaselineAuthPlugin(_ name: String) -> Bool { authPlugins.contains(name) }
    public func isBaselinePeriodicScript(_ name: String) -> Bool { periodicScripts.contains(name) }
    public func isBaselineShellConfig(_ path: String) -> Bool { shellConfigs.contains(path) }

    /// Check if a launch item label (daemon or agent) is in the IPSW baseline
    public func isBaselineLaunchItem(_ label: String) -> Bool {
        daemonLabels.contains(label) || agentLabels.contains(label)
    }
}
