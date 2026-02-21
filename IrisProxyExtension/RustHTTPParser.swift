import Foundation

/// Wrapper around Rust httparse FFI. Returns the same
/// HTTPParser.ParsedRequest / ParsedResponse types so
/// call sites can switch with zero changes.
enum RustHTTPParser {

    static func parseRequest(from data: Data) -> HTTPParser.ParsedRequest? {
        var req = IrisHttpRequest()
        let rc = data.withUnsafeBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return -1 }
            return iris_http_parse_request(
                base.assumingMemoryBound(to: UInt8.self),
                buf.count,
                &req
            )
        }
        guard rc == 0 else { return nil }
        defer { iris_http_free_request(&req) }

        let method = sliceToString(req.method)
        let path = sliceToString(req.path)
        let version = req.version_minor == 0 ? "HTTP/1.0" : "HTTP/1.1"

        var headers: [(name: String, value: String)] = []
        for i in 0..<req.headers_count {
            let h = req.headers.advanced(by: i).pointee
            headers.append((sliceToString(h.name), sliceToString(h.value)))
        }

        return HTTPParser.ParsedRequest(
            method: method,
            path: path,
            httpVersion: version,
            headers: headers,
            headerEndIndex: req.header_end_index,
            contentLength: req.content_length >= 0 ? Int(req.content_length) : nil,
            isChunked: req.is_chunked
        )
    }

    static func parseResponse(from data: Data) -> HTTPParser.ParsedResponse? {
        var resp = IrisHttpResponse()
        let rc = data.withUnsafeBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return -1 }
            return iris_http_parse_response(
                base.assumingMemoryBound(to: UInt8.self),
                buf.count,
                &resp
            )
        }
        guard rc == 0 else { return nil }
        defer { iris_http_free_response(&resp) }

        let reason = sliceToString(resp.reason)
        let version = resp.version_minor == 0 ? "HTTP/1.0" : "HTTP/1.1"

        var headers: [(name: String, value: String)] = []
        for i in 0..<resp.headers_count {
            let h = resp.headers.advanced(by: i).pointee
            headers.append((sliceToString(h.name), sliceToString(h.value)))
        }

        return HTTPParser.ParsedResponse(
            statusCode: Int(resp.status_code),
            reason: reason,
            httpVersion: version,
            headers: headers,
            headerEndIndex: resp.header_end_index,
            contentLength: resp.content_length >= 0 ? Int(resp.content_length) : nil,
            isChunked: resp.is_chunked
        )
    }

    private static func sliceToString(_ s: IrisSlice) -> String {
        guard s.len > 0, s.ptr != nil else { return "" }
        let buf = UnsafeBufferPointer(start: s.ptr, count: s.len)
        return String(bytes: buf, encoding: .utf8) ?? ""
    }
}
