import SwiftUI

extension WiFiMonitorView {

    // MARK: - Helper Views

    func signalBars(quality: WiFiSignalQuality, size: CGFloat = 24) -> some View {
        HStack(spacing: 2) {
            ForEach(0..<4) { bar in
                RoundedRectangle(cornerRadius: 2)
                    .fill(bar < quality.bars ? colorForSignal(quality) : Color.gray.opacity(0.3))
                    .frame(width: size / 4, height: size * CGFloat(bar + 1) / 4)
            }
        }
        .frame(width: size, height: size, alignment: .bottom)
    }

    func statCell(
        title: String,
        value: String,
        quality: WiFiSignalQuality? = nil,
        isSecure: Bool? = nil
    ) -> some View {
        VStack(spacing: 4) {
            Text(title)
                .font(.caption2)
                .foregroundColor(.gray)

            Text(value)
                .font(.system(.body, design: .monospaced))
                .foregroundColor(
                    quality != nil ? colorForSignal(quality!) :
                    isSecure == false ? .orange :
                    .white
                )
        }
    }

    func colorForSignal(_ quality: WiFiSignalQuality) -> Color {
        switch quality {
        case .excellent: return .green
        case .good: return .cyan
        case .fair: return .yellow
        case .weak: return .orange
        case .poor: return .red
        }
    }

    func snrQuality(_ snr: Int) -> WiFiSignalQuality {
        switch snr {
        case 40...: return .excellent
        case 25..<40: return .good
        case 15..<25: return .fair
        case 10..<15: return .weak
        default: return .poor
        }
    }
}
