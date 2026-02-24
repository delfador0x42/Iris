import Foundation

/// Bridges non-ES data into the Event system.
/// Scanner findings, detection alerts, and probe results.
public enum EventBridge {

    /// Convert scanner findings into Events.
    public static func fromFinding(
        pid: Int32, processPath: String, signingId: String?,
        scannerId: String, technique: String, mitre: String?,
        severity: Severity, evidence: [String], description: String
    ) -> Event {
        Event(
            id: EventIDGen.shared.next(),
            source: .scanner,
            severity: severity,
            process: ProcessRef(pid: pid, path: processPath, sign: signingId ?? ""),
            kind: .finding(
                scanner: scannerId,
                technique: technique,
                mitre: mitre ?? "",
                evidence: evidence
            )
        )
    }

    /// Convert a detection alert into an Event.
    public static func fromAlert(
        ruleId: String, name: String, mitre: String,
        detail: String, processPath: String, pid: Int32,
        signingId: String?, chainIds: [UInt64] = []
    ) -> Event {
        Event(
            id: EventIDGen.shared.next(),
            source: .engine,
            severity: .high,
            process: ProcessRef(pid: pid, path: processPath, sign: signingId ?? ""),
            kind: .alert(
                rule: ruleId, name: name,
                mitre: mitre, detail: detail,
                chain: chainIds
            )
        )
    }

    /// Convert a probe result into an Event.
    public static func fromProbe(
        probeId: String, verdict: Verdict,
        contradictions: [Contradiction]
    ) -> Event {
        Event(
            id: EventIDGen.shared.next(),
            source: .probe,
            severity: verdict == .contradiction ? .critical : .info,
            process: .unknown,
            kind: .probeResult(
                probe: probeId,
                verdict: verdict,
                contradictions: contradictions
            )
        )
    }
}
