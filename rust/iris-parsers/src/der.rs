//! ASN.1 DER encoding primitives. Fixes bug P8 (negative integer encoding).

use crate::ffi::alloc_bytes;
use std::ffi::{CStr, c_char};

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 { vec![len as u8] }
    else if len < 256 { vec![0x81, len as u8] }
    else { vec![0x82, (len >> 8) as u8, len as u8] }
}

fn build_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + content.len());
    out.push(tag);
    out.extend(encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

fn write_result(data: &[u8], out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let (ptr, len) = alloc_bytes(data);
    if ptr.is_null() && !data.is_empty() { return -2; }
    unsafe { *out = ptr; *out_len = len; }
    0
}

// --- Integer encoding (fixes P8: proper two's complement) ---

/// Encode a 64-bit signed integer as ASN.1 INTEGER.
#[no_mangle]
pub extern "C" fn iris_der_build_integer_i64(
    value: i64, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let bytes = value.to_be_bytes();
    let mut start = 0;
    if value >= 0 {
        while start < 7 && bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0 { start += 1; }
    } else {
        while start < 7 && bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0 { start += 1; }
    }
    write_result(&build_tlv(0x02, &bytes[start..]), out, out_len)
}

/// Encode raw bytes as ASN.1 INTEGER (adds leading 0x00 if high bit set).
#[no_mangle]
pub extern "C" fn iris_der_build_integer_bytes(
    data: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if data.is_null() || out.is_null() || out_len.is_null() || len == 0 { return -2; }
    let buf = unsafe { std::slice::from_raw_parts(data, len) };
    let content = if buf[0] & 0x80 != 0 {
        let mut v = vec![0x00];
        v.extend_from_slice(buf);
        v
    } else { buf.to_vec() };
    write_result(&build_tlv(0x02, &content), out, out_len)
}

// --- Container types ---

#[no_mangle]
pub extern "C" fn iris_der_build_sequence(
    content: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let buf = if content.is_null() || len == 0 { &[] as &[u8] }
              else { unsafe { std::slice::from_raw_parts(content, len) } };
    write_result(&build_tlv(0x30, buf), out, out_len)
}

#[no_mangle]
pub extern "C" fn iris_der_build_set(
    content: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let buf = if content.is_null() || len == 0 { &[] as &[u8] }
              else { unsafe { std::slice::from_raw_parts(content, len) } };
    write_result(&build_tlv(0x31, buf), out, out_len)
}

// --- String types ---

#[no_mangle]
pub extern "C" fn iris_der_build_bit_string(
    data: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let buf = if data.is_null() || len == 0 { &[] as &[u8] }
              else { unsafe { std::slice::from_raw_parts(data, len) } };
    let mut content = Vec::with_capacity(1 + buf.len());
    content.push(0x00); // unused bits = 0
    content.extend_from_slice(buf);
    write_result(&build_tlv(0x03, &content), out, out_len)
}

#[no_mangle]
pub extern "C" fn iris_der_build_octet_string(
    data: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let buf = if data.is_null() || len == 0 { &[] as &[u8] }
              else { unsafe { std::slice::from_raw_parts(data, len) } };
    write_result(&build_tlv(0x04, buf), out, out_len)
}

#[no_mangle]
pub extern "C" fn iris_der_build_boolean(
    value: bool, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    write_result(&[0x01, 0x01, if value { 0xFF } else { 0x00 }], out, out_len)
}

// --- OID encoding ---

fn encode_oid_component(value: u32, out: &mut Vec<u8>) {
    if value < 128 { out.push(value as u8); return; }
    let mut tmp = Vec::new();
    let mut v = value;
    while v > 0 { tmp.push((v & 0x7F) as u8); v >>= 7; }
    tmp.reverse();
    for (i, b) in tmp.iter().enumerate() {
        out.push(if i < tmp.len() - 1 { b | 0x80 } else { *b });
    }
}

#[no_mangle]
pub extern "C" fn iris_der_build_oid(
    components: *const u32, count: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if components.is_null() || count < 2 || out.is_null() || out_len.is_null() { return -2; }
    let c = unsafe { std::slice::from_raw_parts(components, count) };
    let mut content = vec![(c[0] * 40 + c[1]) as u8];
    for &v in &c[2..] { encode_oid_component(v, &mut content); }
    write_result(&build_tlv(0x06, &content), out, out_len)
}

// --- Text strings ---

#[no_mangle]
pub extern "C" fn iris_der_build_utf8_string(
    s: *const c_char, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if s.is_null() || out.is_null() || out_len.is_null() { return -2; }
    write_result(&build_tlv(0x0C, unsafe { CStr::from_ptr(s) }.to_bytes()), out, out_len)
}

#[no_mangle]
pub extern "C" fn iris_der_build_printable_string(
    s: *const c_char, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if s.is_null() || out.is_null() || out_len.is_null() { return -2; }
    write_result(&build_tlv(0x13, unsafe { CStr::from_ptr(s) }.to_bytes()), out, out_len)
}

// --- Tagged types ---

#[no_mangle]
pub extern "C" fn iris_der_build_explicit_tag(
    tag: u8, content: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let buf = if content.is_null() || len == 0 { &[] as &[u8] }
              else { unsafe { std::slice::from_raw_parts(content, len) } };
    write_result(&build_tlv(0xA0 | tag, buf), out, out_len)
}

#[no_mangle]
pub extern "C" fn iris_der_build_implicit_tag(
    tag: u8, content: *const u8, len: usize, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let buf = if content.is_null() || len == 0 { &[] as &[u8] }
              else { unsafe { std::slice::from_raw_parts(content, len) } };
    write_result(&build_tlv(0x80 | tag, buf), out, out_len)
}

// --- Time encoding (Howard Hinnant civil_from_days, no dependencies) ---

fn unix_to_components(ts: i64) -> (i32, u8, u8, u8, u8, u8) {
    let spd: i64 = 86400;
    let days = ts.div_euclid(spd);
    let tod = ts.rem_euclid(spd);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = if m <= 2 { y + 1 } else { y } as i32;
    (y, m, d, (tod / 3600) as u8, ((tod % 3600) / 60) as u8, (tod % 60) as u8)
}

#[no_mangle]
pub extern "C" fn iris_der_build_utc_time(
    unix_timestamp: i64, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let (y, mo, d, h, mi, s) = unix_to_components(unix_timestamp);
    let ts = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, mo, d, h, mi, s);
    write_result(&build_tlv(0x17, ts.as_bytes()), out, out_len)
}

#[no_mangle]
pub extern "C" fn iris_der_build_generalized_time(
    unix_timestamp: i64, out: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() { return -2; }
    let (y, mo, d, h, mi, s) = unix_to_components(unix_timestamp);
    let ts = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, mo, d, h, mi, s);
    write_result(&build_tlv(0x18, ts.as_bytes()), out, out_len)
}
