import Foundation
import NetworkExtension
import Security
import os.log

// MARK: - Private Helpers

extension FilterDataProvider {

    func getSigningIdentifier(pid: Int32) -> String? {
        // Check cache first — same PID always has the same signing identity
        if let cached = signingIdCache[pid] {
            return cached
        }

        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as NSDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code) == errSecSuccess,
              let guestCode = code else {
            signingIdCache[pid] = .some(nil)
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
              let sc = staticCode else {
            signingIdCache[pid] = .some(nil)
            return nil
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sc, SecCSFlags(), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let identifier = dict[kSecCodeInfoIdentifier as String] as? String else {
            signingIdCache[pid] = .some(nil)
            return nil
        }
        signingIdCache[pid] = identifier
        return identifier
    }

    func getProcessPath(pid: Int32) -> String {
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
        if result > 0 {
            return String(cString: pathBuffer)
        }
        return "/unknown"
    }

    func updateBytes(flow: NEFilterFlow, bytesUp: UInt64 = 0, bytesDown: UInt64 = 0) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }

        guard let connectionId = flowToConnection[ObjectIdentifier(flow)],
              var tracker = connections[connectionId] else {
            return
        }

        tracker.bytesUp += bytesUp
        tracker.bytesDown += bytesDown
        tracker.lastActivity = Date()

        // Update local endpoint if it wasn't available initially
        if tracker.localAddress == "0.0.0.0" || tracker.localPort == 0 {
            if let socketFlow = flow as? NEFilterSocketFlow,
               let localEndpoint = socketFlow.localEndpoint as? NWHostEndpoint {
                if !localEndpoint.hostname.isEmpty && localEndpoint.hostname != "0.0.0.0" {
                    tracker.localAddress = localEndpoint.hostname
                }
                if let port = UInt16(localEndpoint.port), port != 0 {
                    tracker.localPort = port
                }
            }
        }

        connections[connectionId] = tracker
    }
}

// MARK: - Helper for audit token

func audit_token_to_pid(_ token: Data) -> Int32 {
    // audit_token_t is 8 x UInt32 = 32 bytes; PID is at index 5 (byte offset 20)
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { ptr in
        let tokenPtr = ptr.bindMemory(to: UInt32.self)
        return Int32(bitPattern: tokenPtr[5])
    }
}
