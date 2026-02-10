import Foundation

/// Thread-safe boolean flag for cross-closure synchronization.
/// Replaces `NSLock + var Bool` pattern that Swift 6 flags as a data race
/// when captured in @Sendable closures.
final class AtomicFlag: @unchecked Sendable {
    private var value = false
    private let lock = NSLock()

    /// Sets the flag. Returns true only on the first call.
    func trySet() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !value else { return false }
        value = true
        return true
    }

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
