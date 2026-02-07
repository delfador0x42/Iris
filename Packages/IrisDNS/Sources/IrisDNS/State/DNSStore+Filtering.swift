import Foundation
import Combine

// MARK: - Filtering & Search

@MainActor
extension DNSStore {

    // MARK: - Search Debounce

    func setupSearchDebounce() {
        $searchQuery
            .debounce(for: .milliseconds(300), scheduler: RunLoop.main)
            .sink { [weak self] _ in
                self?.objectWillChange.send()
            }
            .store(in: &cancellables)
    }

    // MARK: - Filtered Queries

    /// Queries filtered by current search and filters.
    public var filteredQueries: [DNSQueryRecord] {
        var result = queries

        if !searchQuery.isEmpty {
            let query = searchQuery.lowercased()
            result = result.filter { record in
                record.domain.lowercased().contains(query) ||
                record.answers.contains { $0.lowercased().contains(query) } ||
                (record.processName?.lowercased().contains(query) ?? false)
            }
        }

        if let type = typeFilter {
            result = result.filter { $0.recordType == type }
        }

        if showBlockedOnly {
            result = result.filter { $0.isBlocked }
        }

        return result
    }

    /// Unique record types in captured queries.
    public var availableTypes: [String] {
        Array(Set(queries.map { $0.recordType })).sorted()
    }

    /// Top queried domains.
    public var topDomains: [(domain: String, count: Int)] {
        var counts: [String: Int] = [:]
        for query in queries {
            // Use root domain (e.g., "apple.com" from "api.apple.com")
            let parts = query.domain.split(separator: ".")
            let root = parts.count >= 2 ? parts.suffix(2).joined(separator: ".") : query.domain
            counts[root, default: 0] += 1
        }
        return counts.sorted { $0.value > $1.value }.prefix(10).map { ($0.key, $0.value) }
    }
}
