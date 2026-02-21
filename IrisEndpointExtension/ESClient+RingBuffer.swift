import Foundation
import os.log

// MARK: - Ring Buffer Operations

extension ESClient {

  // MARK: - Process Event History

  /// Record a process event into the ring buffer — O(1) insert, no allocations.
  func recordEvent(_ type: ESProcessEvent.EventType, process: ESProcessInfo) {
    let event = ESProcessEvent(eventType: type, process: process, timestamp: Date())
    eventHistoryLock.lock()
    defer { eventHistoryLock.unlock() }
    let writeIndex = (eventRingHead + eventRingCount) % maxEventHistory
    eventRing[writeIndex] = event
    if eventRingCount < maxEventHistory {
      eventRingCount += 1
    } else {
      eventRingHead = (eventRingHead + 1) % maxEventHistory
    }
  }

  /// Get the most recent N events from the ring buffer — O(n) read only.
  func getRecentEvents(limit: Int) -> [ESProcessEvent] {
    eventHistoryLock.lock()
    defer { eventHistoryLock.unlock() }
    let count = min(limit, eventRingCount)
    var events: [ESProcessEvent] = []
    events.reserveCapacity(count)
    let start = (eventRingHead + eventRingCount - count) % maxEventHistory
    for i in 0..<count {
      let idx = (start + i) % maxEventHistory
      if let event = eventRing[idx] {
        events.append(event)
      }
    }
    return events
  }

  // MARK: - Security Event History

  /// Record a security event into the dedicated ring buffer — O(1) insert.
  func recordSecurityEvent(
    _ type: SecurityEventType,
    process: ESProcessInfo,
    targetPath: String? = nil,
    targetProcess: ESProcessInfo? = nil,
    detail: String? = nil
  ) {
    // Resolve parent path NOW while the parent is likely still alive.
    // Check processTable first (O(1) lookup, no syscall), fall back to proc_pidpath.
    var resolvedParentPath: String? = nil
    var resolvedParentName: String? = nil
    if process.ppid > 1 {
      processLock.lock()
      let cached = processTable[process.ppid]
      processLock.unlock()
      if let cached {
        resolvedParentPath = cached.path
        resolvedParentName = cached.name
      } else {
        let len = proc_pidpath(process.ppid, parentPathBuf, UInt32(MAXPATHLEN))
        if len > 0 {
          let path = String(cString: parentPathBuf)
          resolvedParentPath = path
          resolvedParentName = (path as NSString).lastPathComponent
        }
      }
    }

    securityRingLock.lock()
    securitySequence += 1
    var event = ESSecurityEvent(
      eventType: type, process: process, timestamp: Date(),
      targetPath: targetPath, targetProcess: targetProcess, detail: detail,
      parentPath: resolvedParentPath, parentName: resolvedParentName
    )
    event.sequenceNumber = securitySequence

    let writeIndex = (securityRingHead + securityRingCount) % maxSecurityHistory
    securityRing[writeIndex] = event
    if securityRingCount < maxSecurityHistory {
      securityRingCount += 1
    } else {
      securityRingHead = (securityRingHead + 1) % maxSecurityHistory
    }
    securityRingLock.unlock()

    logger.info("[ES] SECURITY: \(type.rawValue) by \(process.name) target=\(targetPath ?? "none")")
  }

  /// Delta fetch: returns security events with sequenceNumber > sinceSeq.
  /// Returns (maxSeqReturned, events) — caller uses maxSeqReturned as next sinceSeq.
  func getSecurityEventsSince(_ sinceSeq: UInt64, limit: Int) -> (UInt64, [ESSecurityEvent]) {
    securityRingLock.lock()
    defer { securityRingLock.unlock() }

    // Detect gap: if caller is behind by more than ring capacity, events were lost.
    // The oldest event in the ring has sequence ~(securitySequence - ringCount + 1).
    if securityRingCount == maxSecurityHistory && sinceSeq > 0 {
      let oldestSeq = securitySequence - UInt64(securityRingCount)
      if sinceSeq < oldestSeq {
        let dropped = oldestSeq - sinceSeq
        logger.warning("[ES] Security event gap: \(dropped) events lost (ring overflow)")
      }
    }

    var events: [ESSecurityEvent] = []
    events.reserveCapacity(min(limit, securityRingCount))

    for i in 0..<securityRingCount {
      let idx = (securityRingHead + i) % maxSecurityHistory
      if let event = securityRing[idx], event.sequenceNumber > sinceSeq {
        events.append(event)
        if events.count >= limit { break }
      }
    }
    // Return the actual max sequence of returned events, not the global max.
    // Returning securitySequence when limit caused early break would make the
    // caller skip all events between the break point and securitySequence.
    let maxSeqReturned = events.last?.sequenceNumber ?? sinceSeq
    return (maxSeqReturned, events)
  }
}
