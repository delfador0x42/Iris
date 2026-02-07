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
            // Try XPC first
            await fetchProcessesViaXPC(connection)
        } else {
            // Fallback to local enumeration
            await fetchProcessesLocally()
        }

        // Enrich with resource metrics (CPU, memory, threads, FDs)
        await enrichWithResources()

        // Check man pages for processes (in background, don't block refresh)
        Task {
            await checkManPagesForProcesses()
        }

        lastUpdate = Date()
        isLoading = false
    }

    /// Check if processes have man pages
    func checkManPagesForProcesses() async {
        let manPageStore = ManPageStore.shared

        // Get unique command names to check
        let commandNames = Set(processes.map { $0.name })

        // Pre-cache man page existence for all commands
        await manPageStore.preCacheManPages(for: Array(commandNames))

        // Update processes with man page status
        for i in processes.indices {
            let hasManPage = manPageStore.hasManPage(for: processes[i].name)
            if processes[i].hasManPage != hasManPage {
                processes[i].hasManPage = hasManPage
            }
        }
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
                self?.logger.error("XPC error: \(error.localizedDescription)")
                self?.errorMessage = error.localizedDescription
            }
        }) as? EndpointXPCProtocol else {
            await fetchProcessesLocally()
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getProcesses { [weak self] dataArray in
                Task { @MainActor in
                    self?.processProcessData(dataArray)
                    continuation.resume()
                }
            }
        }
    }

    func processProcessData(_ dataArray: [Data]) {
        let decoder = JSONDecoder()
        processes = dataArray.compactMap { data -> ProcessInfo? in
            try? decoder.decode(ProcessInfo.self, from: data)
        }
    }

    /// Enumerate processes locally using BSD APIs
    func fetchProcessesLocally() async {
        var newProcesses: [ProcessInfo] = []

        // Get number of processes
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0

        // First call to get size
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else {
            logger.error("Failed to get process list size")
            return
        }

        // Allocate buffer
        let count = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: count)

        // Second call to get data
        guard sysctl(&mib, 4, &procList, &size, nil, 0) == 0 else {
            logger.error("Failed to get process list")
            return
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride

        for i in 0..<actualCount {
            let proc = procList[i]
            let pid = proc.kp_proc.p_pid

            guard pid > 0 else { continue }

            if let processInfo = getProcessInfo(pid: pid, kinfo: proc) {
                newProcesses.append(processInfo)
            }
        }

        processes = newProcesses
    }

    func getProcessInfo(pid: pid_t, kinfo: kinfo_proc) -> ProcessInfo? {
        // Get process path
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard pathLength > 0 else { return nil }

        let path = String(cString: pathBuffer)
        let name = (path as NSString).lastPathComponent

        // Get ppid, uid from kinfo
        let ppid = kinfo.kp_eproc.e_ppid
        let uid = kinfo.kp_eproc.e_ucred.cr_uid
        // Use uid for gid as fallback (cr_gid not available in this struct)
        let gid = kinfo.kp_eproc.e_pcred.p_rgid

        // Get code signing info
        let codeSigningInfo = getCodeSigningInfo(forPath: path)

        let arguments = Self.getProcessArguments(pid: pid)

        return ProcessInfo(
            pid: pid,
            ppid: ppid,
            path: path,
            name: name,
            arguments: arguments,
            userId: uid,
            groupId: gid,
            codeSigningInfo: codeSigningInfo,
            timestamp: Date()
        )
    }

    // MARK: - Resource Enrichment

    /// Enrich all processes with CPU, memory, thread, and FD metrics
    func enrichWithResources() async {
        let collector = ProcessResourceCollector.shared
        let activePids = Set(processes.map { $0.pid })
        await collector.pruneStale(activePids: activePids)

        for i in processes.indices {
            let pid = processes[i].pid
            if let info = await collector.collect(pid: pid) {
                processes[i].resources = info
            }
        }
    }

    // MARK: - Process Arguments

    /// Parse command-line arguments from KERN_PROCARGS2 sysctl data.
    /// Format: [4-byte argc][exec path \0][padding \0s][arg0 \0][arg1 \0]...
    static func getProcessArguments(pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0

        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }
        guard size > MemoryLayout<Int32>.size else { return [] }

        // Read argc from first 4 bytes
        let argc: Int32 = buffer.withUnsafeBufferPointer {
            $0.baseAddress!.withMemoryRebound(to: Int32.self, capacity: 1) { $0.pointee }
        }
        guard argc > 0, argc < 256 else { return [] }

        var offset = MemoryLayout<Int32>.size

        // Skip executable path (null-terminated)
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null padding after exec path
        while offset < size && buffer[offset] == 0 { offset += 1 }

        // Parse null-terminated argument strings
        var args: [String] = []
        while args.count < Int(argc) && offset < size {
            let start = offset
            while offset < size && buffer[offset] != 0 { offset += 1 }
            if offset > start,
               let arg = String(bytes: buffer[start..<offset], encoding: .utf8) {
                args.append(arg)
            }
            offset += 1
        }

        return args
    }

    // MARK: - Code Signing

    func getCodeSigningInfo(forPath path: String) -> ProcessInfo.CodeSigningInfo? {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL

        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return nil
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return nil
        }

        let teamId = signingInfo["teamid"] as? String
        let signingId = signingInfo["identifier"] as? String
        let flags = (signingInfo["flags"] as? UInt32) ?? 0

        // Check for Apple signature
        let isAppleSigned = teamId == nil && signingId?.hasPrefix("com.apple.") == true

        // Check if platform binary
        let isPlatformBinary = isAppleSigned && (flags & 0x0001) != 0  // CS_VALID

        return ProcessInfo.CodeSigningInfo(
            teamId: teamId,
            signingId: signingId,
            flags: flags,
            isAppleSigned: isAppleSigned,
            isPlatformBinary: isPlatformBinary
        )
    }
}
