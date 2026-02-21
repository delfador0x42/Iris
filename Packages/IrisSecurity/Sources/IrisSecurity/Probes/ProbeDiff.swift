import Foundation

/// Represents a change in probe state between two runs.
public struct ProbeDelta: Sendable, Codable {
    public let probeId: String
    public let probeName: String
    /// Previous verdict (nil if probe is new)
    public let previousVerdict: ProbeVerdict?
    /// Current verdict
    public let currentVerdict: ProbeVerdict
    /// What changed — human-readable summary
    public let change: String
    /// New comparisons that flipped from matching to mismatching
    public let newContradictions: [SourceComparison]
    /// Comparisons that were contradictions but are now resolved
    public let resolvedContradictions: [SourceComparison]
}

/// Compares two probe runs and returns what changed.
/// This is Gap #1 from DESIGN.md — temporal comparison.
public enum ProbeDiff {

    /// Compare current results against previous results.
    /// Returns only probes where something changed.
    public static func diff(
        current: [ProbeResult],
        previous: [ProbeResult]
    ) -> [ProbeDelta] {
        let prevMap = Dictionary(uniqueKeysWithValues: previous.map { ($0.probeId, $0) })
        var deltas: [ProbeDelta] = []

        for cur in current {
            guard let prev = prevMap[cur.probeId] else {
                // New probe — no previous result
                if cur.verdict == .contradiction {
                    deltas.append(ProbeDelta(
                        probeId: cur.probeId,
                        probeName: cur.probeName,
                        previousVerdict: nil,
                        currentVerdict: cur.verdict,
                        change: "NEW CONTRADICTION: \(cur.message)",
                        newContradictions: cur.comparisons.filter { !$0.matches },
                        resolvedContradictions: []))
                }
                continue
            }

            // Verdict changed?
            if cur.verdict != prev.verdict {
                let newMismatches = cur.comparisons.filter { cmp in
                    !cmp.matches && !prev.comparisons.contains { p in
                        p.label == cmp.label && !p.matches
                    }
                }
                let resolved = prev.comparisons.filter { pcmp in
                    !pcmp.matches && !cur.comparisons.contains { c in
                        c.label == pcmp.label && !c.matches
                    }
                }

                deltas.append(ProbeDelta(
                    probeId: cur.probeId,
                    probeName: cur.probeName,
                    previousVerdict: prev.verdict,
                    currentVerdict: cur.verdict,
                    change: "\(prev.verdict.rawValue) → \(cur.verdict.rawValue)",
                    newContradictions: newMismatches,
                    resolvedContradictions: resolved))
            } else if cur.verdict == .contradiction {
                // Same verdict but different comparisons?
                let newMismatches = cur.comparisons.filter { cmp in
                    !cmp.matches && !prev.comparisons.contains { p in
                        p.label == cmp.label && !p.matches
                    }
                }
                if !newMismatches.isEmpty {
                    deltas.append(ProbeDelta(
                        probeId: cur.probeId,
                        probeName: cur.probeName,
                        previousVerdict: prev.verdict,
                        currentVerdict: cur.verdict,
                        change: "New contradictions in existing probe",
                        newContradictions: newMismatches,
                        resolvedContradictions: []))
                }
            }
        }

        return deltas
    }

    /// Write temporal diff to ~/.iris/probes/diff.json
    public static func writeDiff(_ deltas: [ProbeDelta]) {
        guard !deltas.isEmpty else { return }
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".iris/probes", isDirectory: true)
        let url = dir.appendingPathComponent("diff.json")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(deltas) {
            try? data.write(to: url, options: .atomic)
        }
    }
}
