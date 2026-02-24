import Foundation
import os.log

extension ESClient {

  // MARK: - Process Event History

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

  func getRecentEvents(limit: Int) -> [ESProcessEvent] {
    eventHistoryLock.lock()
    defer { eventHistoryLock.unlock() }
    let count = min(limit, eventRingCount)
    var events: [ESProcessEvent] = []
    events.reserveCapacity(count)
    let start = (eventRingHead + eventRingCount - count) % maxEventHistory
    for i in 0..<count {
      let idx = (start + i) % maxEventHistory
      if let event = eventRing[idx] { events.append(event) }
    }
    return events
  }

  // MARK: - Security Event History

  func recordSecurityEvent(
    _ type: SecurityEventType,
    process: ESProcessInfo,
    machTime: UInt64? = nil,
    targetPath: String? = nil,
    targetProcess: ESProcessInfo? = nil,
    detail: String? = nil
  ) {
    // Resolve parent path now while parent is likely alive
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
      machTime: machTime,
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
  }

  func getSecurityEventsSince(_ sinceSeq: UInt64, limit: Int) -> (UInt64, [ESSecurityEvent]) {
    securityRingLock.lock()
    defer { securityRingLock.unlock() }

    if securityRingCount == maxSecurityHistory && sinceSeq > 0 {
      let oldestSeq = securitySequence - UInt64(securityRingCount)
      if sinceSeq < oldestSeq {
        logger.warning("[ES] Security event gap: \(oldestSeq - sinceSeq) events lost")
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
    let maxSeqReturned = events.last?.sequenceNumber ?? sinceSeq
    return (maxSeqReturned, events)
  }
}
