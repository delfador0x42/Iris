import Foundation

/// Registers all contradiction probes with the runner.
/// Called once at app startup.
extension ProbeRunner {
    public func registerDefaultProbes() {
        register([
            // Phase 1: migrated probes
            DyldCacheProbe.shared,
            SIPProbe.shared,
            ProcessCensusProbe2.shared,
            BinaryIntegrityProbe2.shared,
            NetworkGhostProbe2.shared,
            // Phase 2: new contradiction probes
            KextCensusProbe.shared,
            DNSContradictionProbe.shared,
            TimingOracleProbe.shared,
            TrustCacheProbe.shared,
        ])
    }
}
