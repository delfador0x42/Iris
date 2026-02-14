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

    /// Pre-computed lowercase search index. Built once when queries change,
    /// not per-keystroke. Keyed by query UUID.
    struct SearchEntry {
        let domain: String
        let answers: [String]
        let process: String?
    }

    /// Rebuild the search index when queries change. Called from queries didSet.
    func rebuildSearchIndex() {
        var index: [UUID: SearchEntry] = [:]
        index.reserveCapacity(queries.count)
        for q in queries {
            index[q.id] = SearchEntry(
                domain: q.domain.lowercased(),
                answers: q.answers.map { $0.lowercased() },
                process: q.processName?.lowercased()
            )
        }
        searchIndex = index
    }

    /// Recalculate filtered queries and top domains.
    /// Called when queries, typeFilter, or showBlockedOnly change.
    func updateFilteredQueries() {
        // Rebuild index if stale (queries changed but index wasn't updated)
        if searchIndex.count != queries.count {
            rebuildSearchIndex()
        }

        var result = queries

        if !searchQuery.isEmpty {
            let query = searchQuery.lowercased()
            result = result.filter { record in
                guard let entry = searchIndex[record.id] else { return false }
                return entry.domain.contains(query) ||
                    entry.answers.contains { $0.contains(query) } ||
                    (entry.process?.contains(query) ?? false)
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
