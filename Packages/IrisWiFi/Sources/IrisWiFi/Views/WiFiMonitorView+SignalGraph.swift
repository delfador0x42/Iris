import SwiftUI
import Charts

extension WiFiMonitorView {

    // MARK: - Signal Graph

    var signalGraph: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Signal Strength")
                    .font(.headline)
                    .foregroundColor(.white)

                Spacer()

                Button("Clear") {
                    store.clearSignalHistory()
                }
                .font(.caption)
                .foregroundColor(.blue)
            }

            Chart(store.signalHistory) { sample in
                LineMark(
                    x: .value("Time", sample.timestamp),
                    y: .value("RSSI", sample.rssi)
                )
                .foregroundStyle(Color.cyan)
                .interpolationMethod(.catmullRom)

                AreaMark(
                    x: .value("Time", sample.timestamp),
                    y: .value("RSSI", sample.rssi)
                )
                .foregroundStyle(
                    LinearGradient(
                        colors: [Color.cyan.opacity(0.3), Color.cyan.opacity(0.0)],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .interpolationMethod(.catmullRom)
            }
            .chartYScale(domain: -100...(-20))
            .chartYAxis {
                AxisMarks(position: .leading, values: [-90, -70, -50, -30]) { value in
                    AxisGridLine()
                        .foregroundStyle(Color.white.opacity(0.1))
                    AxisValueLabel {
                        Text("\(value.as(Int.self) ?? 0)")
                            .font(.caption2)
                            .foregroundColor(.gray)
                    }
                }
            }
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 5)) { _ in
                    AxisGridLine()
                        .foregroundStyle(Color.white.opacity(0.1))
                }
            }
            .frame(height: 150)
        }
        .padding()
        .background(Color.white.opacity(0.05))
        .cornerRadius(16)
    }
}
