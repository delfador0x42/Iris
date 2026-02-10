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
                self?.updateFilteredQueries()
            }
            .store(in: &cancellables)
    }

    // MARK: - Derived State

    /// Recalculate filtered queries and top domains.
    /// Called when queries, typeFilter, or showBlockedOnly change.
    func updateFilteredQueries() {
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

        filteredQueries = result
        availableTypes = Array(Set(queries.map { $0.recordType })).sorted()

        // Top domains
        var counts: [String: Int] = [:]
        for query in queries {
            let parts = query.domain.split(separator: ".")
            let root = parts.count >= 2 ? parts.suffix(2).joined(separator: ".") : query.domain
            counts[root, default: 0] += 1
        }
        topDomains = counts.sorted { $0.value > $1.value }.prefix(10).map { ($0.key, $0.value) }
    }
}
