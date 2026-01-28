import SwiftUI

/// Statistics panel showing satellite counts
struct StatisticsView: View {
    let statistics: SatelliteStatistics

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Distribution (\(statistics.totalCount) satellites)")
                .font(.headline)
                .foregroundColor(.white)

            ForEach(OrbitalClassification.allCases) { classification in
                // Use pre-calculated values from AppState (avoids computation in view body)
                let count = statistics.byClassification[classification] ?? 0
                let percentage = statistics.percentages[classification] ?? 0

                HStack {
                    Text(classification.rawValue)
                        .font(.system(size: 12))
                        .foregroundColor(.white)
                        .frame(width: 70, alignment: .leading)

                    // Progress bar
                    GeometryReader { geometry in
                        ZStack(alignment: .leading) {
                            Rectangle()
                                .fill(Color.white.opacity(0.1))
                                .frame(height: 8)
                                .cornerRadius(4)

                            Rectangle()
                                .fill(Color(
                                    red: classification.uiColor.red,
                                    green: classification.uiColor.green,
                                    blue: classification.uiColor.blue
                                ))
                                .frame(width: geometry.size.width * CGFloat(percentage) / 100, height: 8)
                                .cornerRadius(4)
                        }
                    }
                    .frame(height: 8)

                    Text(String(format: "%d (%.1f%%)", count, percentage))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                        .frame(width: 80, alignment: .trailing)
                }
            }
        }
        .padding(12)
        .background(.ultraThinMaterial)
        .cornerRadius(10)
    }
}
