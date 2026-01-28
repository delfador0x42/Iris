import SwiftUI

/// Time and playback controls
struct ControlsView: View {
    @ObservedObject var store: SatelliteStore
    var timeScales: [TimeScale]

    var body: some View {
        HStack(spacing: 16) {
            // Time display
            VStack(alignment: .leading, spacing: 2) {
                Text("Simulation Time")
                    .font(.system(size: 10))
                    .foregroundColor(.gray)

                Text(store.simulationTime, style: .date)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white)

                Text(store.simulationTime, style: .time)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white)
            }

            Divider()
                .frame(height: 40)

            // Playback controls
            HStack(spacing: 8) {
                // Previous (step back)
                Button(action: {
                    store.stepTime(by: -60)
                }) {
                    Image(systemName: "backward.fill")
                        .font(.system(size: 14))
                }
                .buttonStyle(.plain)
                .foregroundColor(.white)

                // Play/Pause
                Button(action: {
                    store.togglePause()
                }) {
                    Image(systemName: store.isPaused ? "play.fill" : "pause.fill")
                        .font(.system(size: 16))
                }
                .buttonStyle(.plain)
                .foregroundColor(.white)

                // Next (step forward)
                Button(action: {
                    store.stepTime(by: 60)
                }) {
                    Image(systemName: "forward.fill")
                        .font(.system(size: 14))
                }
                .buttonStyle(.plain)
                .foregroundColor(.white)

                // Reset to now
                Button(action: {
                    store.resetTime()
                }) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 14))
                }
                .buttonStyle(.plain)
                .foregroundColor(.white)
            }

            Divider()
                .frame(height: 40)

            // Time scale picker
            HStack(spacing: 4) {
                ForEach(timeScales) { scale in
                    Button(action: {
                        store.setTimeScale(scale.value)
                    }) {
                        Text(scale.label)
                            .font(.system(size: 11, weight: store.timeScale == scale.value ? .bold : .regular))
                            .foregroundColor(store.timeScale == scale.value ? .white : .gray)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(
                                store.timeScale == scale.value
                                    ? Color.white.opacity(0.2)
                                    : Color.clear
                            )
                            .cornerRadius(4)
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .padding(12)
        .background(.ultraThinMaterial)
        .cornerRadius(10)
    }
}
