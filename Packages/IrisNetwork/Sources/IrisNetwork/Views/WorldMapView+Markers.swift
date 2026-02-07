import SwiftUI

// MARK: - Map Markers

struct UserLocationMarker: View {
    @State private var isPulsing = false

    var body: some View {
        ZStack {
            // Outer pulse ring
            Circle()
                .stroke(.blue.opacity(0.4), lineWidth: 2)
                .frame(width: 40, height: 40)
                .scaleEffect(isPulsing ? 1.5 : 1.0)
                .opacity(isPulsing ? 0 : 0.8)

            // Inner glow
            Circle()
                .fill(.blue.opacity(0.3))
                .frame(width: 32, height: 32)

            // Main circle
            Circle()
                .fill(
                    RadialGradient(
                        colors: [.cyan, .blue],
                        center: .center,
                        startRadius: 0,
                        endRadius: 10
                    )
                )
                .frame(width: 18, height: 18)

            // Center dot
            Circle()
                .fill(.white)
                .frame(width: 8, height: 8)
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: false)) {
                isPulsing = true
            }
        }
    }
}

struct EndpointMarker: View {
    let endpoint: ConnectionEndpoint
    @State private var showPopover = false

    var body: some View {
        Button {
            showPopover.toggle()
        } label: {
            ZStack {
                Circle()
                    .fill(markerColor.opacity(0.8))
                    .frame(width: markerSize, height: markerSize)

                Circle()
                    .stroke(.white, lineWidth: 2)
                    .frame(width: markerSize, height: markerSize)

                if endpoint.connectionCount > 1 {
                    Text("\(endpoint.connectionCount)")
                        .font(.system(size: fontSize, weight: .bold))
                        .foregroundColor(.white)
                }
            }
        }
        .buttonStyle(.plain)
        .popover(isPresented: $showPopover) {
            EndpointPopover(endpoint: endpoint)
        }
    }

    private var markerSize: CGFloat {
        // Scale marker based on connection count
        CGFloat(min(48, 20 + endpoint.connectionCount * 4))
    }

    private var fontSize: CGFloat {
        markerSize > 30 ? 12 : 10
    }

    private var markerColor: Color {
        // Color based on traffic volume
        let totalBytes = endpoint.totalBytesUp + endpoint.totalBytesDown
        if totalBytes > 10_000_000 { // > 10MB
            return .red
        } else if totalBytes > 1_000_000 { // > 1MB
            return .orange
        } else {
            return .green
        }
    }
}
