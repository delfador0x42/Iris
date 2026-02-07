import SwiftUI
import MapKit

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
