//
//  HTTPParser+ChunkedEncoding.swift
//  Shared
//
//  Chunked Transfer-Encoding helpers (RFC 7230 4.1).
//

import Foundation

extension HTTPParser {

    /// Maximum buffer size before we stop accumulating (16MB)
    static let maxBufferSize = 16 * 1024 * 1024

    /// Checks if chunked body ends with the final 0-length chunk.
    /// RFC 7230 4.1: last-chunk = 1*("0") [chunk-ext] CRLF trailer-part CRLF
    /// Walks chunk structure from start to find the zero-length terminator.
    static func isChunkedBodyComplete(_ data: Data) -> Bool {
        guard data.count >= 5 else { return false }
        let count = data.count
        guard data[count - 4] == 0x0D && data[count - 3] == 0x0A &&
              data[count - 2] == 0x0D && data[count - 1] == 0x0A else {
            return false
        }
        var offset = 0
        while offset < data.count - 1 {
            guard let crlfPos = findCRLF(in: data, from: offset) else { return false }
            let sizeSlice = data[offset..<crlfPos]
            guard let sizeStr = String(data: sizeSlice, encoding: .ascii) else { return false }
            let hexStr = sizeStr.split(separator: ";").first.map(String.init) ?? sizeStr
            guard let chunkSize = UInt(hexStr.trimmingCharacters(in: .whitespaces), radix: 16) else { return false }
            if chunkSize == 0 { return true }
            guard chunkSize <= 16_777_216 else { return false }
            let chunkStart = crlfPos + 2
            let chunkEnd = chunkStart + Int(chunkSize) + 2
            guard chunkEnd <= data.count else { return false }
            offset = chunkEnd
        }
        return false
    }

    /// Decodes chunked transfer encoding into contiguous body data.
    static func decodeChunkedBody(_ data: Data) -> Data? {
        var result = Data()
        var offset = 0

        while offset < data.count {
            guard let crlfPos = findCRLF(in: data, from: offset) else { break }
            let sizeSlice = data[offset..<crlfPos]
            guard let sizeStr = String(data: sizeSlice, encoding: .ascii) else { break }
            let hexStr = sizeStr.split(separator: ";").first.map(String.init) ?? sizeStr
            guard let chunkSize = UInt(hexStr.trimmingCharacters(in: .whitespaces), radix: 16) else { break }
            if chunkSize == 0 { break }
            guard chunkSize <= 16_777_216 else { break }
            let chunkStart = crlfPos + 2
            let chunkEnd = chunkStart + Int(chunkSize)
            guard chunkEnd <= data.count else { break }
            result.append(data[chunkStart..<chunkEnd])
            offset = chunkEnd + 2
        }

        return result
    }

    static func findCRLF(in data: Data, from offset: Int) -> Int? {
        for i in offset..<(data.count - 1) {
            if data[i] == 0x0D && data[i + 1] == 0x0A {
                return i
            }
        }
        return nil
    }
}
