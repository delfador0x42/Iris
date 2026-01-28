import Foundation

/// Fetches satellite data from CelesTrak API.
/// Conforms to SatelliteDataSourceProtocol for dependency injection.
public actor CelesTrakDataSource: SatelliteDataSourceProtocol {
    private let configuration: APIConfiguration
    private var cache: [SatelliteGroup: (data: [SatelliteData], timestamp: Date)] = [:]
    // Shared decoder instance (avoids allocation per request)
    private static let jsonDecoder = JSONDecoder()

    public enum DataSourceError: Error, LocalizedError, Sendable {
        case invalidURL
        case networkError(Error)
        case decodingError(Error)
        case noData

        public var errorDescription: String? {
            switch self {
            case .invalidURL:
                return "Invalid URL"
            case .networkError(let error):
                return "Network error: \(error.localizedDescription)"
            case .decodingError(let error):
                return "Decoding error: \(error.localizedDescription)"
            case .noData:
                return "No data received"
            }
        }
    }

    public init(configuration: APIConfiguration = .default) {
        self.configuration = configuration
    }

    public func fetchSatellites(group: SatelliteGroup, forceRefresh: Bool = false) async throws -> [SatelliteData] {
        // Check cache
        if !forceRefresh, let cached = cache[group] {
            if Date().timeIntervalSince(cached.timestamp) < configuration.cacheTimeout {
                return cached.data
            }
        }

        var components = URLComponents(url: configuration.baseURL, resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(name: "GROUP", value: group.rawValue),
            URLQueryItem(name: "FORMAT", value: "json")
        ]

        guard let url = components?.url else {
            throw DataSourceError.invalidURL
        }

        let data: Data
        do {
            let (responseData, _) = try await URLSession.shared.data(from: url)
            data = responseData
        } catch {
            throw DataSourceError.networkError(error)
        }

        let satellites: [SatelliteData]
        do {
            satellites = try Self.jsonDecoder.decode([SatelliteData].self, from: data)
        } catch {
            throw DataSourceError.decodingError(error)
        }

        // Update cache
        cache[group] = (satellites, Date())

        return satellites
    }

    public func clearCache() {
        cache.removeAll()
    }
}
