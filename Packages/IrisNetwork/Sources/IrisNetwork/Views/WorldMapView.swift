import SwiftUI
import MapKit

/// World map visualization showing network connection destinations
public struct WorldMapView: View {
    @ObservedObject var store: SecurityStore
    @State private var cameraPosition: MapCameraPosition = .automatic

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
    }

    @ViewBuilder
    private var mapContent: some View {
        if #available(macOS 14.0, *) {
            Map(position: $cameraPosition) {
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
                processes: Set(connections.map { $0.processName })
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
    var body: some View {
        ZStack {
            Circle()
                .fill(.blue.opacity(0.3))
                .frame(width: 32, height: 32)

            Circle()
                .fill(.blue)
                .frame(width: 16, height: 16)

            Circle()
                .fill(.white)
                .frame(width: 8, height: 8)
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
        .frame(minWidth: 200)
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
