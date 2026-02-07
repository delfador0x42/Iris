import SwiftUI
import MapKit
import AppKit

/// World map visualization showing network connection destinations
public struct WorldMapView: View {
    @ObservedObject var store: SecurityStore
    @State private var cameraPosition: MapCameraPosition = .automatic
    @State private var animationPhase: CGFloat = 0

    // Default user location (can be updated with actual location)
    let userLocation = CLLocationCoordinate2D(latitude: 37.7749, longitude: -122.4194) // San Francisco

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
    var mapContent: some View {
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

    var statsOverlay: some View {
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
    var aggregatedEndpoints: [ConnectionEndpoint] {
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

// MARK: - Preview

#Preview {
    WorldMapView(store: SecurityStore())
        .frame(width: 800, height: 600)
}
