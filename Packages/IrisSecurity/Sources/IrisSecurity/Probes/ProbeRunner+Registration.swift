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
            // Phase 3: ground truth probes from GROUND_TRUTH_APIS.md
            KernelBootProbe.shared,
            MACPolicyProbe.shared,
            // Phase 4: additional ground truth probes
            CodeSignContradictionProbe.shared,
            IOKitGroundTruthProbe.shared,
            ArchitectureContradictionProbe.shared,
            // Phase 5: compromised-host probes (assume kernel is hostile)
            EntitlementAuditProbe.shared,
            NECPPolicyProbe.shared,
            FileDescriptorAuditProbe.shared,
        ])
    }
}
