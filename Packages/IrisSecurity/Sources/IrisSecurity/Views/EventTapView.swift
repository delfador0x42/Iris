import SwiftUI

/// Displays detected event taps (ReiKey-style keylogger detection)
public struct EventTapView: View {
    @State private var taps: [EventTapInfo] = []
    @State private var isLoading = true

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                if isLoading {
                    loadingView
                } else if taps.isEmpty {
                    emptyView
                } else {
                    tapList
                }
            }
        }
        .task { await loadTaps() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Event Tap Monitor")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                let suspicious = taps.filter(\.isSuspicious).count
                Text("\(taps.count) taps found\(suspicious > 0 ? " (\(suspicious) suspicious)" : "")")
                    .font(.caption).foregroundColor(suspicious > 0 ? .red : .gray)
            }
            Spacer()
            Button(action: { Task { await loadTaps() } }) {
                Image(systemName: "arrow.clockwise").foregroundColor(.blue)
            }.buttonStyle(.plain)
        }.padding(20)
    }

    private var tapList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(taps) { tap in
                    EventTapRow(tap: tap)
                }
            }.padding(.vertical, 8)
        }
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48)).foregroundColor(.green)
            Text("No suspicious event taps detected")
                .font(.headline).foregroundColor(.white)
            Text("No processes are intercepting keyboard events")
                .font(.caption).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
            Text("Scanning event taps...")
                .font(.system(size: 14)).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var darkBackground: some View {
        LinearGradient(
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }

    private func loadTaps() async {
        isLoading = true
        taps = await EventTapScanner.shared.scan()
        isLoading = false
    }
}

struct EventTapRow: View {
    let tap: EventTapInfo

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: tap.isSuspicious ? "exclamationmark.triangle.fill" : "keyboard")
                .foregroundColor(tap.isSuspicious ? .red : .gray)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(tap.tappingProcessName)
                    .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                Text("PID \(tap.tappingPID) -> \(tap.targetDescription)")
                    .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Text(tap.isActiveFilter ? "Active Filter" : "Passive")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(tap.isActiveFilter ? .red : .green)
                if tap.isKeyboardTap {
                    Text("Keyboard")
                        .font(.system(size: 9))
                        .foregroundColor(.orange)
                }
            }

            Text(tap.signingStatus.rawValue)
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(tap.signingStatus == .apple ? .green : .orange)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background((tap.signingStatus == .apple ? Color.green : Color.orange).opacity(0.15))
                .cornerRadius(4)
        }
        .padding(.horizontal, 20).padding(.vertical, 8)
        .background(tap.isSuspicious ? Color.red.opacity(0.05) : Color.white.opacity(0.02))
    }
}
