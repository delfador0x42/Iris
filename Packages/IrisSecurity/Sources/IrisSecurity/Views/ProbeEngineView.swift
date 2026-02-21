import SwiftUI

/// Contradiction probe dashboard — shows each probe's verdict with expandable comparison details.
public struct ProbeEngineView: View {
    @State private var runner = ProbeRunner.shared
    @State private var expandedProbe: String?

    public init() {}

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if runner.results.isEmpty && !runner.isRunning {
                    emptyState
                } else {
                    if !runner.deltas.isEmpty {
                        deltasBanner
                    }
                    ForEach(runner.results) { result in
                        probeRow(result)
                    }
                }
            }
            .padding(20)
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Contradiction Probes")
                    .font(.system(size: 18, weight: .bold, design: .monospaced))
                    .foregroundColor(.white)
                Text("Force the system to reveal truth through action, not reporting")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.gray)
            }
            Spacer()
            if runner.isRunning {
                ProgressView().controlSize(.small).tint(.orange)
            }
            Button(action: { Task { await runner.runAll() } }) {
                Label("Run All", systemImage: "play.fill")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
            }
            .buttonStyle(.borderedProminent)
            .tint(.orange)
            .disabled(runner.isRunning)
        }
    }

    // MARK: - Probe Row

    private func probeRow(_ result: ProbeResult) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: {
                withAnimation(.easeInOut(duration: 0.2)) {
                    expandedProbe = expandedProbe == result.probeId ? nil : result.probeId
                }
            }) {
                HStack(spacing: 12) {
                    verdictBadge(result.verdict)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(result.probeName)
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(.white)
                        Text(result.message)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.gray)
                            .lineLimit(1)
                    }
                    Spacer()
                    Text("\(result.durationMs)ms")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.6))
                    Image(systemName: expandedProbe == result.probeId ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10))
                        .foregroundColor(.gray.opacity(0.5))
                }
                .padding(12)
            }
            .buttonStyle(.plain)

            if expandedProbe == result.probeId {
                comparisonDetail(result)
            }
        }
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.white.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(verdictColor(result.verdict).opacity(0.2), lineWidth: 1)))
    }

    // MARK: - Comparison Detail

    private func comparisonDetail(_ result: ProbeResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Divider().background(Color.gray.opacity(0.2))
            ForEach(result.comparisons) { cmp in
                HStack(spacing: 8) {
                    Image(systemName: cmp.matches ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundColor(cmp.matches ? .green : .red)
                        .font(.system(size: 12))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cmp.label)
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(.white.opacity(0.9))
                        HStack(spacing: 4) {
                            Text(cmp.sourceA.source)
                                .foregroundColor(.cyan)
                            Text("=")
                                .foregroundColor(.gray)
                            Text(truncate(cmp.sourceA.value, max: 30))
                                .foregroundColor(.white.opacity(0.7))
                        }
                        .font(.system(size: 10, design: .monospaced))
                        HStack(spacing: 4) {
                            Text(cmp.sourceB.source)
                                .foregroundColor(.orange)
                            Text("=")
                                .foregroundColor(.gray)
                            Text(truncate(cmp.sourceB.value, max: 30))
                                .foregroundColor(.white.opacity(0.7))
                        }
                        .font(.system(size: 10, design: .monospaced))
                    }
                }
                .padding(.horizontal, 12)
            }
        }
        .padding(.bottom, 12)
    }

    // MARK: - Temporal Deltas

    private var deltasBanner: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .foregroundColor(.purple)
                    .font(.system(size: 12))
                Text("State Changes Since Last Run")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.purple)
            }
            ForEach(runner.deltas, id: \.probeId) { delta in
                HStack(spacing: 6) {
                    if let prev = delta.previousVerdict {
                        verdictBadge(prev)
                        Image(systemName: "arrow.right")
                            .font(.system(size: 8))
                            .foregroundColor(.gray)
                    }
                    verdictBadge(delta.currentVerdict)
                    Text(delta.probeName)
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundColor(.white.opacity(0.9))
                    Text(delta.change)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                        .lineLimit(1)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.purple.opacity(0.05))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(Color.purple.opacity(0.3), lineWidth: 1)))
    }

    // MARK: - Helpers

    private func verdictBadge(_ verdict: ProbeVerdict) -> some View {
        let (icon, color) = verdictInfo(verdict)
        return Image(systemName: icon)
            .font(.system(size: 16))
            .foregroundColor(color)
            .frame(width: 24)
    }

    private func verdictInfo(_ verdict: ProbeVerdict) -> (String, Color) {
        switch verdict {
        case .consistent: return ("checkmark.shield.fill", .green)
        case .contradiction: return ("exclamationmark.triangle.fill", .red)
        case .degraded: return ("questionmark.circle.fill", .yellow)
        case .error: return ("xmark.circle.fill", .gray)
        }
    }

    private func verdictColor(_ verdict: ProbeVerdict) -> Color {
        verdictInfo(verdict).1
    }

    private func truncate(_ s: String, max: Int) -> String {
        s.count <= max ? s : String(s.prefix(max)) + "..."
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 32))
                .foregroundColor(.orange.opacity(0.5))
            Text("No probe results yet")
                .font(.system(size: 13, design: .monospaced))
                .foregroundColor(.gray)
            Text("Run all probes to verify system integrity")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.gray.opacity(0.6))
        }
        .frame(maxWidth: .infinity, minHeight: 200)
    }
}
