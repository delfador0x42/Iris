//
//  ProcessInfo.swift
//  IrisProxyExtension
//
//  Process identification helpers for network flow attribution.
//  Absorbed from IrisNetworkExtension/FilterDataProvider+ProcessInfo.swift.
//

import Foundation
import Security

/// Gets the code signing identifier for a process.
/// Uses the shared cache in ProxyXPCService.
func getSigningIdentifier(pid: Int32, cache: NSLock, signingIdCache: inout [pid_t: String?]) -> String? {
    cache.lock()
    if let cached = signingIdCache[pid] {
        cache.unlock()
        return cached
    }
    cache.unlock()

    var code: SecCode?
    let attrs = [kSecGuestAttributePid: pid] as NSDictionary
    guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code) == errSecSuccess,
          let guestCode = code else {
        cache.lock()
        signingIdCache[pid] = .some(nil)
        cache.unlock()
        return nil
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(guestCode, SecCSFlags(), &staticCode) == errSecSuccess,
          let sc = staticCode else {
        cache.lock()
        signingIdCache[pid] = .some(nil)
        cache.unlock()
        return nil
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(sc, SecCSFlags(), &info) == errSecSuccess,
          let dict = info as? [String: Any],
          let identifier = dict[kSecCodeInfoIdentifier as String] as? String else {
        cache.lock()
        signingIdCache[pid] = .some(nil)
        cache.unlock()
        return nil
    }
    cache.lock()
    signingIdCache[pid] = identifier
    cache.unlock()
    return identifier
}

/// Gets the file path for a process by PID.
func getProcessPath(pid: Int32) -> String {
    var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let result = proc_pidpath(pid, &pathBuffer, UInt32(MAXPATHLEN))
    if result > 0 {
        return String(cString: pathBuffer)
    }
    return "/unknown"
}

/// Extracts PID from an audit_token_t Data blob.
/// audit_token_t is 8 x UInt32 = 32 bytes; PID is at index 5 (byte offset 20).
func audit_token_to_pid(_ token: Data) -> Int32 {
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { ptr in
        let tokenPtr = ptr.bindMemory(to: UInt32.self)
        return Int32(bitPattern: tokenPtr[5])
    }
}
