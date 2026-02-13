import SwiftUI

/// Real-time microphone and camera monitoring (OverSight-inspired).
/// Uses CoreAudio property listeners for mic, AVCaptureDevice for camera.
public struct AVMonitorView: View {
    @StateObject private var monitor = AVMonitor.shared

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                if monitor.events.isEmpty {
                    emptyView
                } else {
                    eventList
                }
            }
        }
        .onAppear { monitor.startMonitoring() }
        .onDisappear { monitor.stopMonitoring() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("AV Monitor")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                HStack(spacing: 12) {
                    statusPill("Mics", count: monitor.activeMicrophones.count)
                    statusPill("Cameras", count: monitor.activeCameras.count)
                    Text("\(monitor.events.count) events")
                        .font(.caption).foregroundColor(.gray)
                }
            }
            Spacer()
        }.padding(20)
    }

    private func statusPill(_ label: String, count: Int) -> some View {
        HStack(spacing: 4) {
            Circle()
                .fill(count > 0 ? Color.red : Color.green)
                .frame(width: 6, height: 6)
            Text("\(count) \(label)")
                .font(.system(size: 11)).foregroundColor(.white)
        }
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background((count > 0 ? Color.red : Color.green).opacity(0.15))
        .cornerRadius(4)
    }

    private var eventList: some View {
        ThemedScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(monitor.events) { event in
                    AVEventRow(event: event)
                }
            }.padding(.vertical, 8)
        }
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "waveform.badge.magnifyingglass")
                .font(.system(size: 48)).foregroundColor(.gray)
            Text("Monitoring active").font(.headline).foregroundColor(.white)
            Text("Events appear when mic or camera activates")
                .font(.caption).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var darkBackground: some View {
        LinearGradient(
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }
}

struct AVEventRow: View {
    let event: AVDeviceEvent

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: event.deviceType.icon)
                .foregroundColor(event.isActive ? .red : .green)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(event.deviceName)
                    .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                if let proc = event.processName {
                    Text(proc).font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
            }
            Spacer()
            Text(event.isActive ? "ON" : "OFF")
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(event.isActive ? .red : .green)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background((event.isActive ? Color.red : Color.green).opacity(0.15))
                .cornerRadius(4)
            Text(event.timestamp, style: .time)
                .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
        }
        .padding(.horizontal, 20).padding(.vertical, 8)
        .background(event.isActive ? Color.red.opacity(0.05) : Color.white.opacity(0.02))
    }
}
