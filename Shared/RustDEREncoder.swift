import Foundation

/// Rust-backed ASN.1 DER encoder. Drop-in replacement for DEREncoder.
/// Fixes bug P8 (negative integer encoding).
enum RustDEREncoder {

    static func buildInteger(_ value: Int) -> [UInt8] {
        derCall { out, len in iris_der_build_integer_i64(Int64(value), out, len) }
    }

    static func buildInteger(_ data: Data) -> [UInt8] {
        data.withUnsafeBytes { buf in
            derCall { out, len in
                iris_der_build_integer_bytes(
                    buf.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    buf.count, out, len)
            }
        }
    }

    static func buildSequence(_ content: Data) -> [UInt8] {
        content.withUnsafeBytes { buf in
            derCall { out, len in
                iris_der_build_sequence(
                    buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    buf.count, out, len)
            }
        }
    }

    static func buildSequence(_ content: [UInt8]) -> [UInt8] {
        buildSequence(Data(content))
    }

    static func buildBitString(_ data: Data) -> [UInt8] {
        data.withUnsafeBytes { buf in
            derCall { out, len in
                iris_der_build_bit_string(
                    buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    buf.count, out, len)
            }
        }
    }

    static func buildOctetString(_ data: Data) -> [UInt8] {
        data.withUnsafeBytes { buf in
            derCall { out, len in
                iris_der_build_octet_string(
                    buf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    buf.count, out, len)
            }
        }
    }

    static func buildOID(_ oid: [UInt]) -> [UInt8] {
        let components = oid.map { UInt32($0) }
        return components.withUnsafeBufferPointer { buf in
            derCall { out, len in
                iris_der_build_oid(buf.baseAddress, buf.count, out, len)
            }
        }
    }

    static func buildUTF8String(_ string: String) -> [UInt8] {
        string.withCString { cstr in
            derCall { out, len in iris_der_build_utf8_string(cstr, out, len) }
        }
    }

    static func buildPrintableString(_ string: String) -> [UInt8] {
        string.withCString { cstr in
            derCall { out, len in iris_der_build_printable_string(cstr, out, len) }
        }
    }

    static func buildUTCTime(_ date: Date) -> [UInt8] {
        derCall { out, len in
            iris_der_build_utc_time(Int64(date.timeIntervalSince1970), out, len)
        }
    }

    static func buildGeneralizedTime(_ date: Date) -> [UInt8] {
        derCall { out, len in
            iris_der_build_generalized_time(Int64(date.timeIntervalSince1970), out, len)
        }
    }

    static func buildExplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        content.withUnsafeBufferPointer { buf in
            derCall { out, len in
                iris_der_build_explicit_tag(
                    UInt8(tag), buf.baseAddress, buf.count, out, len)
            }
        }
    }

    static func buildImplicitTag(_ tag: Int, content: [UInt8]) -> [UInt8] {
        content.withUnsafeBufferPointer { buf in
            derCall { out, len in
                iris_der_build_implicit_tag(
                    UInt8(tag), buf.baseAddress, buf.count, out, len)
            }
        }
    }

    static func buildSet(_ content: [UInt8]) -> [UInt8] {
        content.withUnsafeBufferPointer { buf in
            derCall { out, len in
                iris_der_build_set(buf.baseAddress, buf.count, out, len)
            }
        }
    }

    static func buildBoolean(_ value: Bool) -> [UInt8] {
        derCall { out, len in iris_der_build_boolean(value, out, len) }
    }

    // MARK: - Private

    private static func derCall(
        _ body: (UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
                 UnsafeMutablePointer<Int>) -> Int32
    ) -> [UInt8] {
        var outPtr: UnsafeMutablePointer<UInt8>?
        var outLen: Int = 0
        let rc = body(&outPtr, &outLen)
        guard rc == 0, let ptr = outPtr, outLen > 0 else { return [] }
        defer { iris_free_bytes(ptr, outLen) }
        return Array(UnsafeBufferPointer(start: ptr, count: outLen))
    }
}
