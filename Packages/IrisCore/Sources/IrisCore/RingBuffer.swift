/// Generic ring buffer. O(1) insert, O(1) eviction, bounded memory.
/// Not thread-safe — caller must synchronize (actor or lock).
public struct RingBuffer<T> {
    private var storage: [T?]
    private var head: Int = 0
    private var count_: Int = 0
    public let capacity: Int

    public var count: Int { count_ }
    public var isEmpty: Bool { count_ == 0 }

    public init(capacity: Int) {
        self.capacity = capacity
        self.storage = [T?](repeating: nil, count: capacity)
    }

    /// Append element. O(1). Evicts oldest if full.
    @discardableResult
    public mutating func append(_ element: T) -> T? {
        let writeIdx = (head + count_) % capacity
        let evicted = storage[writeIdx]
        storage[writeIdx] = element
        if count_ < capacity {
            count_ += 1
        } else {
            head = (head + 1) % capacity
        }
        return evicted
    }

    /// Read newest-first. Returns up to `limit` elements.
    public func newest(_ limit: Int = .max) -> [T] {
        let n = min(limit, count_)
        var result: [T] = []
        result.reserveCapacity(n)
        for i in stride(from: count_ - 1, through: count_ - n, by: -1) {
            let idx = (head + i) % capacity
            if let elem = storage[idx] { result.append(elem) }
        }
        return result
    }

    /// Read oldest-first. Returns up to `limit` elements.
    public func oldest(_ limit: Int = .max) -> [T] {
        let n = min(limit, count_)
        var result: [T] = []
        result.reserveCapacity(n)
        for i in 0..<n {
            let idx = (head + i) % capacity
            if let elem = storage[idx] { result.append(elem) }
        }
        return result
    }

    /// Read all elements since a given sequence point.
    /// `since` is the index of the last seen element (0-based from start of ring).
    /// Returns elements newer than `since`.
    public func since(_ seq: Int) -> [T] {
        guard seq < count_ else { return [] }
        let start = max(0, seq)
        var result: [T] = []
        result.reserveCapacity(count_ - start)
        for i in start..<count_ {
            let idx = (head + i) % capacity
            if let elem = storage[idx] { result.append(elem) }
        }
        return result
    }

    /// Clear all elements.
    public mutating func clear() {
        storage = [T?](repeating: nil, count: capacity)
        head = 0
        count_ = 0
    }

    /// Access by absolute index (0 = oldest still in buffer)
    public subscript(index: Int) -> T? {
        guard index >= 0, index < count_ else { return nil }
        return storage[(head + index) % capacity]
    }
}
