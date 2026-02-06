import SwiftUI
import MapKit
import AppKit

/// World map visualization showing network connection destinations
public struct WorldMapView: View {
    @ObservedObject var store: SecurityStore
    @State private var cameraPosition: MapCameraPosition = .automatic
    @State private var animationPhase: CGFloat = 0

    // Default user location (can be updated with actual location)
    private let userLocation = CLLocationCoordinate2D(latitude: 37.7749, longitude: -122.4194) // San Francisco

    public init(store: SecurityStore) {
        self.store = store
    }

    public var body: some View {
        ZStack {
            mapContent

            // Overlay with stats
            VStack {
                Spacer()
                statsOverlay
            }
        }
        .onAppear {
            // Start animation timer
            withAnimation(.linear(duration: 2).repeatForever(autoreverses: false)) {
                animationPhase = 1
            }
        }
    }

    @ViewBuilder
    private var mapContent: some View {
        if #available(macOS 14.0, *) {
            Map(position: $cameraPosition) {
                // Connection arcs (drawn first, so they appear behind markers)
                ForEach(aggregatedEndpoints) { endpoint in
                    // Draw arc from user to endpoint
                    MapPolyline(coordinates: greatCircleArc(
                        from: userLocation,
                        to: endpoint.coordinate,
                        segments: 50
                    ))
                    .stroke(
                        arcGradient(for: endpoint),
                        style: StrokeStyle(
                            lineWidth: arcLineWidth(for: endpoint),
                            lineCap: .round,
                            lineJoin: .round
                        )
                    )
                }

                // User location marker
                Annotation("You", coordinate: userLocation) {
                    UserLocationMarker()
                }

                // Connection endpoint markers
                ForEach(aggregatedEndpoints) { endpoint in
                    Annotation(endpoint.label, coordinate: endpoint.coordinate) {
                        EndpointMarker(endpoint: endpoint)
                    }
                }
            }
            .mapStyle(.imagery(elevation: .realistic))
            .mapControls {
                MapCompass()
                MapScaleView()
                MapZoomStepper()
            }
        } else {
            // Fallback for older macOS
            Text("Map requires macOS 14.0 or later")
                .foregroundColor(.secondary)
        }
    }

    /// Calculate points along a great circle arc between two coordinates
    private func greatCircleArc(
        from start: CLLocationCoordinate2D,
        to end: CLLocationCoordinate2D,
        segments: Int
    ) -> [CLLocationCoordinate2D] {
        var coordinates: [CLLocationCoordinate2D] = []

        let lat1 = start.latitude * .pi / 180
        let lon1 = start.longitude * .pi / 180
        let lat2 = end.latitude * .pi / 180
        let lon2 = end.longitude * .pi / 180

        // Calculate the angular distance
        let d = 2 * asin(sqrt(
            pow(sin((lat1 - lat2) / 2), 2) +
            cos(lat1) * cos(lat2) * pow(sin((lon1 - lon2) / 2), 2)
        ))

        for i in 0...segments {
            let f = Double(i) / Double(segments)

            let A = sin((1 - f) * d) / sin(d)
            let B = sin(f * d) / sin(d)

            let x = A * cos(lat1) * cos(lon1) + B * cos(lat2) * cos(lon2)
            let y = A * cos(lat1) * sin(lon1) + B * cos(lat2) * sin(lon2)
            let z = A * sin(lat1) + B * sin(lat2)

            let lat = atan2(z, sqrt(x * x + y * y))
            let lon = atan2(y, x)

            coordinates.append(CLLocationCoordinate2D(
                latitude: lat * 180 / .pi,
                longitude: lon * 180 / .pi
            ))
        }

        return coordinates
    }

    /// Get gradient color for arc based on traffic volume
    private func arcGradient(for endpoint: ConnectionEndpoint) -> LinearGradient {
        let totalBytes = endpoint.totalBytesUp + endpoint.totalBytesDown
        let baseColor: Color
        if totalBytes > 10_000_000 {
            baseColor = .red
        } else if totalBytes > 1_000_000 {
            baseColor = .orange
        } else {
            baseColor = .cyan
        }

        return LinearGradient(
            colors: [
                baseColor.opacity(0.3),
                baseColor.opacity(0.8),
                baseColor.opacity(0.3)
            ],
            startPoint: .leading,
            endPoint: .trailing
        )
    }

    /// Get line width based on connection count
    private func arcLineWidth(for endpoint: ConnectionEndpoint) -> CGFloat {
        CGFloat(min(6, 1 + endpoint.connectionCount / 5))
    }

    private var statsOverlay: some View {
        HStack(spacing: 16) {
            StatBadge(
                label: "Locations",
                value: "\(aggregatedEndpoints.count)"
            )
            StatBadge(
                label: "Countries",
                value: "\(store.uniqueCountries.count)"
            )
            StatBadge(
                label: "Geolocated",
                value: "\(store.geolocatedCount)/\(store.connections.count)"
            )
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .padding()
    }

    /// Aggregate connections by location for cleaner map visualization
    private var aggregatedEndpoints: [ConnectionEndpoint] {
        let geoConnections = store.connections.filter { $0.hasGeolocation }

        // Group by approximate location (rounded to reduce clustering)
        let grouped = Dictionary(grouping: geoConnections) { connection -> String in
            let lat = connection.remoteLatitude ?? 0
            let lon = connection.remoteLongitude ?? 0
            // Round to ~11km precision for clustering
            return "\(round(lat * 10) / 10),\(round(lon * 10) / 10)"
        }

        return grouped.compactMap { (_, connections) -> ConnectionEndpoint? in
            guard let first = connections.first,
                  let lat = first.remoteLatitude,
                  let lon = first.remoteLongitude else {
                return nil
            }

            return ConnectionEndpoint(
                id: "\(lat),\(lon)",
                coordinate: CLLocationCoordinate2D(latitude: lat, longitude: lon),
                country: first.remoteCountry ?? "Unknown",
                countryCode: first.remoteCountryCode ?? "",
                city: first.remoteCity ?? "",
                connectionCount: connections.count,
                totalBytesUp: connections.reduce(0) { $0 + $1.bytesUp },
                totalBytesDown: connections.reduce(0) { $0 + $1.bytesDown },
                processes: Set(connections.map { $0.processName }),
                uniqueIPs: Set(connections.map { $0.remoteAddress })
            )
        }
        .sorted { $0.connectionCount > $1.connectionCount }
    }
}

// MARK: - Supporting Types

struct ConnectionEndpoint: Identifiable {
    let id: String
    let coordinate: CLLocationCoordinate2D
    let country: String
    let countryCode: String
    let city: String
    let connectionCount: Int
    let totalBytesUp: UInt64
    let totalBytesDown: UInt64
    let processes: Set<String>
    let uniqueIPs: Set<String>  // Unique IP addresses at this location

    var label: String {
        if city.isEmpty {
            return country
        }
        return "\(city), \(countryCode)"
    }

    var formattedBytes: String {
        let total = totalBytesUp + totalBytesDown
        return NetworkConnection.formatBytes(total)
    }
}

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

struct EndpointPopover: View {
    let endpoint: ConnectionEndpoint

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Location
            HStack {
                Image(systemName: "mappin.circle.fill")
                    .foregroundColor(.red)
                Text(endpoint.label)
                    .font(.headline)
            }

            Divider()

            // Stats
            LabeledContent("Connections", value: "\(endpoint.connectionCount)")
            LabeledContent("Upload", value: NetworkConnection.formatBytes(endpoint.totalBytesUp))
            LabeledContent("Download", value: NetworkConnection.formatBytes(endpoint.totalBytesDown))

            // IP addresses with Shodan links
            if !endpoint.uniqueIPs.isEmpty {
                Divider()
                Text("IP Addresses:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                ForEach(Array(endpoint.uniqueIPs.prefix(5)).sorted(), id: \.self) { ip in
                    IPAddressRow(ip: ip)
                }
                if endpoint.uniqueIPs.count > 5 {
                    Text("... and \(endpoint.uniqueIPs.count - 5) more")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            if !endpoint.processes.isEmpty {
                Divider()
                Text("Processes:")
                    .font(.caption)
                    .foregroundColor(.secondary)
                ForEach(Array(endpoint.processes.prefix(5)), id: \.self) { process in
                    Text("• \(process)")
                        .font(.caption)
                }
                if endpoint.processes.count > 5 {
                    Text("... and \(endpoint.processes.count - 5) more")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
        }
        .padding()
        .frame(minWidth: 220)
    }
}

struct IPAddressRow: View {
    let ip: String
    @State private var isHovering = false

    var body: some View {
        Button {
            openShodan(for: ip)
        } label: {
            Text("• \(ip)")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(isHovering ? .cyan : .primary)
                .underline(isHovering)
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .onHover { hovering in
            isHovering = hovering
        }
        .help("View on Shodan")
    }

    private func openShodan(for ip: String) {
        let urlString = "https://www.shodan.io/host/\(ip)"
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
        }
    }
}

struct StatBadge: View {
    let label: String
    let value: String

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 16, weight: .bold, design: .rounded))
                .foregroundColor(.primary)
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Preview

#Preview {
    WorldMapView(store: SecurityStore())
        .frame(width: 800, height: 600)
}
