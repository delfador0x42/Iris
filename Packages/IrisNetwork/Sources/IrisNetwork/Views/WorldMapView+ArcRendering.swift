import SwiftUI
import MapKit

// MARK: - Great Circle Arc & Styling Helpers

extension WorldMapView {

    /// Calculate points along a great circle arc between two coordinates
    func greatCircleArc(
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
    func arcGradient(for endpoint: ConnectionEndpoint) -> LinearGradient {
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
    func arcLineWidth(for endpoint: ConnectionEndpoint) -> CGFloat {
        CGFloat(min(6, 1 + endpoint.connectionCount / 5))
    }
}
