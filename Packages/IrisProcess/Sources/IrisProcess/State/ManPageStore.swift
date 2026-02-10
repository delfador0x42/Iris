import Foundation
import Combine
import os.log

/// Manages caching and retrieval of man pages
@MainActor
public final class ManPageStore: ObservableObject {

    // MARK: - Singleton

    public static let shared = ManPageStore()

    // MARK: - Published State

    @Published public private(set) var isLoading = false

    // MARK: - Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "ManPageStore")
    private let cacheDirectory: URL
    private var manPageExistsCache: [String: Bool] = [:]
    private var manPageContentCache: [String: String] = [:]

    // MARK: - Initialization

    private init() {
        // Create cache directory in Application Support
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        cacheDirectory = appSupport.appendingPathComponent("Iris/ManPages", isDirectory: true)

        // Create directory if needed
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)

        // Load cached man page existence data
        loadExistenceCache()
    }

    // MARK: - Public API

    /// Check if a command has a man page
    /// - Parameter command: The command name (e.g., "ls", "grep")
    /// - Returns: true if man page exists, false otherwise
    public func hasManPage(for command: String) -> Bool {
        let normalizedCommand = normalizeCommand(command)

        // Check memory cache first
        if let cached = manPageExistsCache[normalizedCommand] {
            return cached
        }

        // Check on disk (save deferred to batch caller)
        let exists = checkManPageExists(for: normalizedCommand)
        manPageExistsCache[normalizedCommand] = exists

        return exists
    }

    /// Check if a command has a man page (async version that doesn't block)
    /// - Parameter command: The command name
    /// - Returns: true if man page exists
    public func hasManPageAsync(for command: String) async -> Bool {
        let normalizedCommand = normalizeCommand(command)

        // Check memory cache first
        if let cached = manPageExistsCache[normalizedCommand] {
            return cached
        }

        // Run check in background using static helper
        let exists = await Task.detached {
            Self.checkManPageExistsStatic(for: normalizedCommand)
        }.value

        manPageExistsCache[normalizedCommand] = exists

        return exists
    }

    /// Get the man page content for a command
    /// - Parameter command: The command name
    /// - Returns: The man page content as plain text, or nil if not found
    public func getManPage(for command: String) async -> String? {
        let normalizedCommand = normalizeCommand(command)

        // Check memory cache
        if let cached = manPageContentCache[normalizedCommand] {
            return cached
        }

        // Check disk cache
        let cacheFile = cacheDirectory.appendingPathComponent("\(normalizedCommand).txt")
        if let cached = try? String(contentsOf: cacheFile, encoding: .utf8) {
            manPageContentCache[normalizedCommand] = cached
            return cached
        }

        // Fetch from system
        await MainActor.run { isLoading = true }
        defer { Task { @MainActor in isLoading = false } }

        guard let content = await fetchManPage(for: normalizedCommand) else {
            return nil
        }

        // Cache to memory and disk
        manPageContentCache[normalizedCommand] = content
        try? content.write(to: cacheFile, atomically: true, encoding: .utf8)

        return content
    }

    /// Pre-cache man pages for a list of commands.
    /// Only checks names not already in cache. Max 10 concurrent subprocess checks.
    public func preCacheManPages(for commands: [String]) async {
        let uncached = commands.filter { manPageExistsCache[normalizeCommand($0)] == nil }
        guard !uncached.isEmpty else { return }

        let maxConcurrency = 10
        await withTaskGroup(of: Void.self) { group in
            var running = 0
            for command in uncached {
                if running >= maxConcurrency {
                    await group.next()
                    running -= 1
                }
                group.addTask {
                    _ = await self.hasManPageAsync(for: command)
                }
                running += 1
            }
        }

        // Save once after batch completes (not per-lookup)
        saveExistenceCache()
    }

    /// Clear all cached man pages
    public func clearCache() {
        manPageExistsCache.removeAll()
        manPageContentCache.removeAll()

        // Remove cached files
        try? FileManager.default.removeItem(at: cacheDirectory)
        try? FileManager.default.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
    }

    // MARK: - Private Methods

    private func normalizeCommand(_ command: String) -> String {
        // Extract just the command name from a path
        let name = (command as NSString).lastPathComponent
        // Remove any version numbers or extensions
        return name.components(separatedBy: CharacterSet.alphanumerics.inverted).first ?? name
    }

    private func checkManPageExists(for command: String) -> Bool {
        Self.checkManPageExistsStatic(for: command)
    }

    /// Static version that can be called from detached tasks
    nonisolated private static func checkManPageExistsStatic(for command: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/man")
        process.arguments = ["-w", command]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }

    private func fetchManPage(for command: String) async -> String? {
        await Task.detached {
            let process = Process()
            let pipe = Pipe()

            process.executableURL = URL(fileURLWithPath: "/usr/bin/man")
            process.arguments = [command]
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice

            // Set MANPAGER to cat to get plain text output
            var env = Foundation.ProcessInfo.processInfo.environment
            env["MANPAGER"] = "cat"
            env["COLUMNS"] = "100"
            process.environment = env

            do {
                try process.run()
                process.waitUntilExit()

                guard process.terminationStatus == 0 else {
                    return nil
                }

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                var content = String(data: data, encoding: .utf8)

                // Clean up the content - remove backspace sequences used for bold/underline
                content = content?.replacingOccurrences(of: ".\u{08}", with: "", options: .regularExpression)
                content = content?.replacingOccurrences(of: "_\u{08}", with: "", options: .regularExpression)
                content = content?.replacingOccurrences(of: "\u{08}.", with: "", options: .regularExpression)

                return content
            } catch {
                return nil
            }
        }.value
    }

    // MARK: - Persistence

    private var existenceCacheFile: URL {
        cacheDirectory.appendingPathComponent("existence_cache.json")
    }

    private func loadExistenceCache() {
        guard let data = try? Data(contentsOf: existenceCacheFile),
              let cache = try? JSONDecoder().decode([String: Bool].self, from: data) else {
            return
        }
        manPageExistsCache = cache
    }

    private func saveExistenceCache() {
        guard let data = try? JSONEncoder().encode(manPageExistsCache) else { return }
        try? data.write(to: existenceCacheFile)
    }
}
