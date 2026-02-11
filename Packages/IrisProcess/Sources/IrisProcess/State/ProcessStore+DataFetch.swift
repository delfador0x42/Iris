import Foundation
import os.log

// MARK: - Data Fetching

@MainActor
extension ProcessStore {

    /// Standard refresh method - reloads all process data
    public func refresh() async {
        await refreshProcesses()
    }

    /// Fetch processes - uses data source if available, otherwise XPC/local fallback
    public func refreshProcesses() async {
        isLoading = processes.isEmpty

        // Use injected data source if available (for testing)
        if let dataSource = dataSource {
            await fetchProcessesViaDataSource(dataSource)
        } else if let connection = xpcConnection {
            logger.debug("[FETCH] Using XPC connection for process data")
            await fetchProcessesViaXPC(connection)
        } else {
            logger.debug("[FETCH] No XPC connection — using local sysctl enumeration")
            await fetchProcessesLocally()
        }

        // PERF: Work on a local copy to avoid triggering @Published didSet 1240+ times.
        // Each processes[i].resources = x fires didSet → updateDisplayedProcesses() (filter+sort+publish).
        // Batching into one assignment reduces from ~1240 updates to 1.
        var snapshot = processes

        // Enrich with resource metrics (CPU, memory, threads, FDs)
        let collector = ProcessResourceCollector.shared
        let pids = snapshot.map { $0.pid }
        let resources = await collector.collectBatch(pids: pids)
        for i in snapshot.indices {
            if let info = resources[snapshot[i].pid] {
                snapshot[i].resources = info
            }
        }

        // Compute suspicion reasons once (not per-render)
        for i in snapshot.indices { snapshot[i].refreshSuspicion() }

        // Single assignment → one didSet → one updateDisplayedProcesses()
        processes = snapshot

        // Check man pages in background (don't block refresh)
        Task {
            await checkManPagesForProcesses()
        }

        lastUpdate = Date()
        isLoading = false
    }

    /// Check if processes have man pages
    func checkManPagesForProcesses() async {
        let manPageStore = ManPageStore.shared
        let commandNames = Set(processes.map { $0.name })
        await manPageStore.preCacheManPages(for: Array(commandNames))

        // Batch-update man page status on local copy, assign once
        var snapshot = processes
        var changed = false
        for i in snapshot.indices {
            let hasManPage = manPageStore.hasManPage(for: snapshot[i].name)
            if snapshot[i].hasManPage != hasManPage {
                snapshot[i].hasManPage = hasManPage
                snapshot[i].refreshSuspicion()
                changed = true
            }
        }
        if changed { processes = snapshot }
    }

    func fetchProcessesViaDataSource(_ dataSource: any ProcessDataSourceProtocol) async {
        do {
            let dataArray = try await dataSource.fetchProcesses()
            processProcessData(dataArray)
        } catch {
            logger.error("Data source error: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }
    }

    func fetchProcessesViaXPC(_ connection: NSXPCConnection) async {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self] error in
            Task { @MainActor in
                self?.logger.error("[FETCH] XPC proxy error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        }) as? EndpointXPCProtocol else {
            logger.warning("[FETCH] Failed to get XPC proxy — falling back to local")
            await fetchProcessesLocally()
            return
        }

        // Timeout prevents infinite hang if extension isn't responding
        let gotResponse = await withTaskGroup(of: Bool.self) { group in
            group.addTask { @MainActor in
                await withCheckedContinuation { continuation in
                    proxy.getProcesses { [weak self] dataArray in
                        Task { @MainActor in
                            self?.logger.info("[FETCH] XPC getProcesses() returned \(dataArray.count) data items")
                            self?.processProcessData(dataArray)
                            continuation.resume()
                        }
                    }
                }
                return true
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            return result
        }

        if gotResponse {
            isUsingEndpointSecurity = true
            let count = processes.count
            logger.info("[FETCH] XPC fetch succeeded — \(count) processes decoded")
        } else {
            logger.warning("[FETCH] XPC getProcesses() TIMED OUT after 3s — falling back to local")
            isUsingEndpointSecurity = false
            await fetchProcessesLocally()
        }
    }

    func processProcessData(_ dataArray: [Data]) {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var decoded = 0
        var failed = 0
        processes = dataArray.compactMap { data -> ProcessInfo? in
            if let p = try? decoder.decode(ProcessInfo.self, from: data) {
                decoded += 1
                return p
            } else {
                failed += 1
                if failed <= 3 {
                    // Log first few failures for debugging decode issues
                    let preview = String(data: data.prefix(200), encoding: .utf8) ?? "<binary>"
                    logger.error("[DECODE] Failed to decode ProcessInfo: \(preview)")
                }
                return nil
            }
        }
        if failed > 0 {
            logger.warning("[DECODE] \(decoded) decoded OK, \(failed) FAILED out of \(dataArray.count) total")
        }
    }

}
