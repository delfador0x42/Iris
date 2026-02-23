import Foundation
import Security
import CommonCrypto

/// Binary parsing and cdhash computation for TrustCacheProbe.
extension TrustCacheProbe {

    // MARK: - Trust Cache Parsing

    func parseIMG4TrustCache(_ data: Data) -> Set<String> {
        var hashes = Set<String>()
        guard data.count > 48 else { return hashes }

        guard let offset = findTrustCachePayload(data) else { return hashes }
        let remaining = data.count - offset
        guard remaining > 28 else { return hashes }

        let version = data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            $0.load(as: UInt32.self).littleEndian
        }

        let entryStart: Int
        let entrySize: Int

        if version == 1 {
            let entryCount = data.subdata(in: (offset + 4)..<(offset + 8)).withUnsafeBytes {
                $0.load(as: UInt32.self).littleEndian
            }
            guard entryCount < 50000, remaining >= 8 + Int(entryCount) * 22 else { return hashes }
            entryStart = offset + 8
            entrySize = 22 // 20-byte cdhash + 1-byte hash_type + 1-byte flags
        } else if version == 2 {
            guard remaining > 24 else { return hashes }
            let entryCount = data.subdata(in: (offset + 24)..<(offset + 28)).withUnsafeBytes {
                $0.load(as: UInt32.self).littleEndian
            }
            guard entryCount < 50000, remaining >= 28 + Int(entryCount) * 24 else { return hashes }
            entryStart = offset + 28
            entrySize = 24 // 20-byte cdhash + 2-byte hash_type + 2-byte constraint_category
        } else {
            return hashes
        }

        var pos = entryStart
        while pos + entrySize <= data.count {
            let cdhash = data.subdata(in: pos..<(pos + 20))
            let hex = cdhash.map { String(format: "%02x", $0) }.joined()
            if hex != String(repeating: "0", count: 40) {
                hashes.insert(hex)
            }
            pos += entrySize
        }

        return hashes
    }

    private func findTrustCachePayload(_ data: Data) -> Int? {
        let bytes = [UInt8](data)
        for i in stride(from: 0, to: min(bytes.count - 28, 2048), by: 1) {
            if bytes[i] == 2 && bytes[i+1] == 0 && bytes[i+2] == 0 && bytes[i+3] == 0 {
                if i + 28 <= bytes.count {
                    let entryCount = UInt32(bytes[i+24]) | UInt32(bytes[i+25]) << 8
                        | UInt32(bytes[i+26]) << 16 | UInt32(bytes[i+27]) << 24
                    if entryCount > 100 && entryCount < 50000 {
                        return i
                    }
                }
            }
            if bytes[i] == 1 && bytes[i+1] == 0 && bytes[i+2] == 0 && bytes[i+3] == 0 {
                if i + 8 <= bytes.count {
                    let entryCount = UInt32(bytes[i+4]) | UInt32(bytes[i+5]) << 8
                        | UInt32(bytes[i+6]) << 16 | UInt32(bytes[i+7]) << 24
                    if entryCount > 100 && entryCount < 50000 {
                        return i
                    }
                }
            }
        }
        return nil
    }

    // MARK: - Runtime CDHash

    func computeRuntimeCDHash(path: String) -> String? {
        let url = URL(fileURLWithPath: path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let staticCode = code else { return nil }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return nil }

        if let hashData = dict[kSecCodeInfoUnique as String] as? Data {
            return hashData.prefix(20).map { String(format: "%02x", $0) }.joined()
        }
        return nil
    }

    // MARK: - Disk CDHash

    func computeDiskCDHash(path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        guard data.count > 32 else { return nil }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }

        let headerSize: Int
        switch magic {
        case 0xFEEDFACF: headerSize = 32        // 64-bit
        case 0xFEEDFACE: headerSize = 28        // 32-bit
        case 0xBEBAFECA: return computeFatCDHash(data: data)
        default: return nil
        }

        let ncmds = data.subdata(in: 16..<20).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        var offset = headerSize
        for _ in 0..<ncmds {
            guard offset + 8 <= data.count else { break }
            let cmd = data.subdata(in: offset..<(offset+4)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            let cmdsize = data.subdata(in: (offset+4)..<(offset+8)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            if cmd == 0x1D { // LC_CODE_SIGNATURE
                guard offset + 16 <= data.count else { break }
                let dataoff = data.subdata(in: (offset+8)..<(offset+12)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                let datasize = data.subdata(in: (offset+12)..<(offset+16)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                return extractCDHashFromSignature(data: data, sigOffset: Int(dataoff), sigSize: Int(datasize))
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    private func computeFatCDHash(data: Data) -> String? {
        guard data.count > 8 else { return nil }
        let nfat = data.subdata(in: 4..<8).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        var off = 8
        for _ in 0..<nfat {
            guard off + 20 <= data.count else { break }
            let cpuType = data.subdata(in: off..<(off+4)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let sliceOff = data.subdata(in: (off+8)..<(off+12)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let sliceSize = data.subdata(in: (off+12)..<(off+16)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

            if cpuType == 0x0100000C { // CPU_TYPE_ARM64
                let end = Int(sliceOff + sliceSize)
                guard end <= data.count else { break }
                let slice = data.subdata(in: Int(sliceOff)..<end)
                return computeDiskCDHashFromSlice(slice)
            }
            off += 20
        }
        return nil
    }

    private func computeDiskCDHashFromSlice(_ data: Data) -> String? {
        guard data.count > 32 else { return nil }
        let ncmds = data.subdata(in: 16..<20).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
        var offset = 32
        for _ in 0..<ncmds {
            guard offset + 8 <= data.count else { break }
            let cmd = data.subdata(in: offset..<(offset+4)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            let cmdsize = data.subdata(in: (offset+4)..<(offset+8)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
            if cmd == 0x1D {
                guard offset + 16 <= data.count else { break }
                let dataoff = data.subdata(in: (offset+8)..<(offset+12)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                let datasize = data.subdata(in: (offset+12)..<(offset+16)).withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }
                return extractCDHashFromSignature(data: data, sigOffset: Int(dataoff), sigSize: Int(datasize))
            }
            offset += Int(cmdsize)
        }
        return nil
    }

    func extractCDHashFromSignature(data: Data, sigOffset: Int, sigSize: Int) -> String? {
        guard sigOffset + sigSize <= data.count, sigSize > 12 else { return nil }

        let sigData = data.subdata(in: sigOffset..<(sigOffset + sigSize))
        guard sigData.count > 12 else { return nil }

        let magic = sigData.subdata(in: 0..<4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard magic == 0xFADE0CC0 else { return nil } // CSMAGIC_EMBEDDED_SIGNATURE

        let count = sigData.subdata(in: 8..<12).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

        for i in 0..<count {
            let idxOff = 12 + Int(i) * 8
            guard idxOff + 8 <= sigData.count else { break }
            let blobType = sigData.subdata(in: idxOff..<(idxOff+4)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let blobOffset = sigData.subdata(in: (idxOff+4)..<(idxOff+8)).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }

            if blobType == 0 { // CSSLOT_CODEDIRECTORY
                guard Int(blobOffset) + 8 <= sigData.count else { break }
                let cdMagic = sigData.subdata(in: Int(blobOffset)..<Int(blobOffset)+4).withUnsafeBytes {
                    $0.load(as: UInt32.self).bigEndian
                }
                let cdLength = sigData.subdata(in: Int(blobOffset)+4..<Int(blobOffset)+8).withUnsafeBytes {
                    $0.load(as: UInt32.self).bigEndian
                }
                guard cdMagic == 0xFADE0C02,
                      Int(blobOffset) + Int(cdLength) <= sigData.count else { break }

                let cdBlob = sigData.subdata(in: Int(blobOffset)..<Int(blobOffset) + Int(cdLength))
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                cdBlob.withUnsafeBytes { ptr in
                    CC_SHA256(ptr.baseAddress, CC_LONG(cdBlob.count), &hash)
                }
                return hash.prefix(20).map { String(format: "%02x", $0) }.joined()
            }
        }
        return nil
    }

    // MARK: - Platform Binary Check

    func checkPlatformBinary(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let staticCode = code else { return false }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any] else { return false }

        if let flags = dict[kSecCodeInfoFlags as String] as? UInt32 {
            return (flags & 0x04000000) != 0 // CS_PLATFORM_BINARY
        }
        return false
    }

    func shortPath(_ path: String) -> String {
        (path as NSString).lastPathComponent
    }
}
