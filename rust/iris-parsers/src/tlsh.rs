//! TLSH locality-sensitive hashing for binary similarity detection.
//! Similar binaries produce similar hashes. Distance function quantifies similarity.
//! 128-bucket compact mode: 70 hex char hash. Zero dependencies.

use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::io::Read;

const BUCKETS: usize = 128;
const BODY_LEN: usize = 32; // 128 * 2 bits / 8
const HASH_HEX_LEN: usize = 70; // (3 header + 32 body) * 2
const MIN_DATA: usize = 50;
const READ_CAP: usize = 4 * 1024 * 1024; // 4 MB max read

/// Pearson hash permutation table (TLSH standard).
const V: [u8; 256] = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
];

#[inline(always)]
fn p3(a: u8, b: u8, c: u8) -> u8 {
    V[V[a as usize ^ b as usize] as usize ^ c as usize]
}

fn compute(data: &[u8]) -> Option<String> {
    if data.len() < MIN_DATA { return None; }

    let mut bkt = [0u32; BUCKETS];
    let mut cksum: u8 = 0;

    for w in data.windows(5) {
        let (a, b, c, d, e) = (w[0], w[1], w[2], w[3], w[4]);
        bkt[(p3(a, b, c) & 0x7F) as usize] += 1;
        bkt[(p3(a, b, d) & 0x7F) as usize] += 1;
        bkt[(p3(a, c, d) & 0x7F) as usize] += 1;
        bkt[(p3(a, b, e) & 0x7F) as usize] += 1;
        bkt[(p3(a, c, e) & 0x7F) as usize] += 1;
        bkt[(p3(a, d, e) & 0x7F) as usize] += 1;
        cksum = V[cksum as usize ^ a as usize];
    }

    // Quartiles from sorted bucket counts
    let mut sorted = bkt;
    sorted.sort_unstable();
    let q1 = sorted[BUCKETS / 4];
    let q2 = sorted[BUCKETS / 2];
    let q3 = sorted[3 * BUCKETS / 4];
    if q3 == 0 { return None; } // degenerate input

    // Header byte 0: checksum
    // Header byte 1: log-encoded length
    let l_val = {
        let f = (data.len() as f64).ln();
        ((f * 8.0) as u32 % 256) as u8
    };

    // Header byte 2: quartile ratios (4 bits each)
    let q1r = if q2 == 0 { 0u8 } else { ((q1 as u64 * 100 / q2 as u64) % 16) as u8 };
    let q2r = if q3 == 0 { 0u8 } else { ((q2 as u64 * 100 / q3 as u64) % 16) as u8 };
    let q_byte = (q1r << 4) | q2r;

    // Body: 2 bits per bucket → 32 bytes
    let mut body = [0u8; BODY_LEN];
    for (i, &count) in bkt.iter().enumerate() {
        let code: u8 = if count <= q1 { 0 }
            else if count <= q2 { 1 }
            else if count <= q3 { 2 }
            else { 3 };
        body[i / 4] |= code << ((i % 4) * 2);
    }

    let mut hex = String::with_capacity(HASH_HEX_LEN);
    for &b in &[cksum, l_val, q_byte] {
        hex.push_str(&format!("{:02x}", b));
    }
    for &b in &body {
        hex.push_str(&format!("{:02x}", b));
    }
    Some(hex)
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != HASH_HEX_LEN { return None; }
    let mut out = Vec::with_capacity(35);
    let bytes = hex.as_bytes();
    for i in (0..HASH_HEX_LEN).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn distance(h1: &str, h2: &str) -> i32 {
    let b1 = match hex_to_bytes(h1) { Some(v) => v, None => return -1 };
    let b2 = match hex_to_bytes(h2) { Some(v) => v, None => return -1 };

    let mut dist = 0i32;

    // Checksum
    if b1[0] != b2[0] { dist += 1; }

    // Length difference (scaled penalty)
    let ldiff = (b1[1] as i32 - b2[1] as i32).unsigned_abs();
    dist += match ldiff { 0 => 0, 1..=2 => 2, 3..=6 => 6, _ => 12 } as i32;

    // Q-ratio difference
    let (q1a, q2a) = (b1[2] >> 4, b1[2] & 0xF);
    let (q1b, q2b) = (b2[2] >> 4, b2[2] & 0xF);
    dist += ((q1a as i32 - q1b as i32).abs() + (q2a as i32 - q2b as i32).abs()) * 2;

    // Body: 2-bit quartile code pairs
    for i in 3..35 {
        for shift in (0..8).step_by(2) {
            let c1 = (b1[i] >> shift) & 3;
            let c2 = (b2[i] >> shift) & 3;
            let d = (c1 as i32 - c2 as i32).unsigned_abs();
            dist += match d { 0 => 0, 1 => 1, _ => 6 } as i32;
        }
    }
    dist
}

// ---- FFI exports ----

/// Compute TLSH hash of a file. Returns heap-allocated hex string (caller frees with iris_free_string).
/// Returns null if file unreadable or too small (<50 bytes).
#[no_mangle]
pub extern "C" fn iris_tlsh_file(path: *const c_char) -> *mut c_char {
    if path.is_null() { return std::ptr::null_mut(); }
    let p = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s, Err(_) => return std::ptr::null_mut(),
    };
    let mut file = match fs::File::open(p) {
        Ok(f) => f, Err(_) => return std::ptr::null_mut(),
    };
    let mut buf = vec![0u8; READ_CAP];
    let n = match file.read(&mut buf) {
        Ok(n) => n, Err(_) => return std::ptr::null_mut(),
    };
    match compute(&buf[..n]) {
        Some(hex) => CString::new(hex).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Compute TLSH hash of raw bytes. Returns heap-allocated hex string.
#[no_mangle]
pub extern "C" fn iris_tlsh_bytes(data: *const u8, len: usize) -> *mut c_char {
    if data.is_null() || len < MIN_DATA { return std::ptr::null_mut(); }
    let slice = unsafe { std::slice::from_raw_parts(data, len) };
    match compute(slice) {
        Some(hex) => CString::new(hex).unwrap().into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Compute distance between two TLSH hashes (70 hex chars each).
/// Returns distance (0 = identical, <30 = very similar, <100 = similar).
/// Returns -1 on invalid input.
#[no_mangle]
pub extern "C" fn iris_tlsh_distance(
    hash1: *const c_char, hash2: *const c_char,
) -> i32 {
    if hash1.is_null() || hash2.is_null() { return -1; }
    let h1 = match unsafe { CStr::from_ptr(hash1) }.to_str() {
        Ok(s) => s, Err(_) => return -1,
    };
    let h2 = match unsafe { CStr::from_ptr(hash2) }.to_str() {
        Ok(s) => s, Err(_) => return -1,
    };
    distance(h1, h2)
}
