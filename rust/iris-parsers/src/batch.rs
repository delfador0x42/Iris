//! Batch operations: SHA256 hashing and Shannon entropy.
//! These are CPU-heavy ops that benefit from Rust's zero-cost abstractions.

use crate::ffi::{IrisCStringArray, vec_to_c_string_array, free_c_string_array};
use std::ffi::{CStr, CString, c_char};
use std::fs;

/// SHA256 hash a file, returning lowercase hex digest.
fn sha256_file(path: &str) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let digest = sha256_digest(&bytes);
    Some(digest.iter().map(|b| format!("{:02x}", b)).collect())
}

/// Pure-Rust SHA-256 (FIPS 180-4). No dependencies.
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process 512-bit blocks
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[4*i..4*i+4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

/// Shannon entropy of a byte stream (0.0 = uniform, 8.0 = max randomness).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count == 0 { continue; }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Chi-square test for uniform byte distribution.
fn chi_square_test(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let expected = data.len() as f64 / 256.0;
    let mut chi = 0.0f64;
    for &count in &counts {
        let diff = count as f64 - expected;
        chi += (diff * diff) / expected;
    }
    chi
}

/// Monte Carlo pi estimation — truly random data estimates pi accurately.
/// Returns percent error from true pi.
fn monte_carlo_pi(data: &[u8]) -> f64 {
    if data.len() < 12 { return 100.0; }
    let mut inside = 0u64;
    let mut total = 0u64;
    let max_val = 0xFFFFFF as f64;
    let mut i = 0;
    while i + 5 < data.len() {
        let x = ((data[i] as u32) << 16 | (data[i+1] as u32) << 8 | data[i+2] as u32) as f64;
        let y = ((data[i+3] as u32) << 16 | (data[i+4] as u32) << 8 | data[i+5] as u32) as f64;
        let nx = x / max_val;
        let ny = y / max_val;
        if nx * nx + ny * ny <= 1.0 { inside += 1; }
        total += 1;
        i += 6;
    }
    if total == 0 { return 100.0; }
    let estimated_pi = 4.0 * inside as f64 / total as f64;
    100.0 * (std::f64::consts::PI - estimated_pi).abs() / std::f64::consts::PI
}

/// Known file format magic bytes (skip entropy analysis for these).
fn is_known_format(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    let h = &data[..4];
    // PNG, JPEG, GIF, TIFF
    if h == [0x89, 0x50, 0x4E, 0x47] { return true; }
    if h[..2] == [0xFF, 0xD8] { return true; } // JPEG variants
    if h == [0x47, 0x49, 0x46, 0x38] { return true; }
    if h == [0x49, 0x49, 0x2A, 0x00] || h == [0x4D, 0x4D, 0x00, 0x2A] { return true; }
    // gzip
    if data.len() >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08 { return true; }
    // ZIP, PDF
    if h == [0x50, 0x4B, 0x03, 0x04] || h == [0x25, 0x50, 0x44, 0x46] { return true; }
    false
}

const ENTROPY_THRESHOLD: f64 = 7.95;
const MONTE_CARLO_THRESHOLD: f64 = 1.5;
const CHI_SQUARE_THRESHOLD: f64 = 400.0;
const MIN_FILE_SIZE: usize = 1024;
const READ_CHUNK: usize = 3 * 1024 * 1024; // 3 MB

/// Full entropy analysis result.
#[repr(C)]
pub struct IrisEntropyResult {
    pub entropy: f64,
    pub chi_square: f64,
    pub monte_carlo_pi_error: f64,
    pub is_encrypted: bool,
    pub is_known_format: bool,
}

// ---- FFI exports ----

/// Hash a single file. Returns hex string via out_hex (caller must free).
/// Returns 0=ok, -1=file error.
#[no_mangle]
pub extern "C" fn iris_sha256_file(path: *const c_char, out_hex: *mut *mut c_char) -> i32 {
    if path.is_null() || out_hex.is_null() { return -2; }
    let p = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s, Err(_) => return -2,
    };
    match sha256_file(p) {
        Some(hex) => {
            let cstr = CString::new(hex).unwrap();
            unsafe { *out_hex = cstr.into_raw(); }
            0
        }
        None => -1,
    }
}

/// Free a string returned by iris_sha256_file.
#[no_mangle]
pub extern "C" fn iris_free_string(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe { drop(CString::from_raw(ptr)); }
}

/// Compute Shannon entropy of a file (0.0–8.0). Returns 0=ok, -1=error.
#[no_mangle]
pub extern "C" fn iris_file_entropy(path: *const c_char, out: *mut f64) -> i32 {
    if path.is_null() || out.is_null() { return -2; }
    let p = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s, Err(_) => return -2,
    };
    match fs::read(p) {
        Ok(data) => {
            unsafe { *out = shannon_entropy(&data); }
            0
        }
        Err(_) => -1,
    }
}

/// Batch SHA256: hash multiple files. Returns array of hex strings (empty string on error).
#[no_mangle]
pub extern "C" fn iris_batch_sha256(
    paths: *const *const c_char, count: usize, out: *mut IrisCStringArray,
) -> i32 {
    if paths.is_null() || out.is_null() || count == 0 { return -2; }
    let mut results = Vec::with_capacity(count);
    for i in 0..count {
        let cpath = unsafe { *paths.add(i) };
        if cpath.is_null() {
            results.push(String::new());
            continue;
        }
        let p = match unsafe { CStr::from_ptr(cpath) }.to_str() {
            Ok(s) => s, Err(_) => { results.push(String::new()); continue; }
        };
        results.push(sha256_file(p).unwrap_or_default());
    }
    unsafe { *out = vec_to_c_string_array(results); }
    0
}

/// Free batch results.
#[no_mangle]
pub extern "C" fn iris_batch_sha256_free(arr: *mut IrisCStringArray) {
    if arr.is_null() { return; }
    unsafe { free_c_string_array(&*arr); }
}

/// Full entropy analysis: Shannon entropy, chi-square, Monte Carlo pi, encrypted determination.
/// Reads up to 3MB of the file. Skips known formats (images, archives, PDF).
/// Returns 0=ok, -1=file error/too small, -2=arg error, -3=known format (skipped).
#[no_mangle]
pub extern "C" fn iris_file_entropy_full(path: *const c_char, out: *mut IrisEntropyResult) -> i32 {
    if path.is_null() || out.is_null() { return -2; }
    let p = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s, Err(_) => return -2,
    };
    let meta = match fs::metadata(p) {
        Ok(m) => m, Err(_) => return -1,
    };
    if (meta.len() as usize) < MIN_FILE_SIZE { return -1; }

    let mut file = match fs::File::open(p) {
        Ok(f) => f, Err(_) => return -1,
    };
    use std::io::Read;
    let mut buf = vec![0u8; READ_CHUNK];
    let n = match file.read(&mut buf) {
        Ok(n) => n, Err(_) => return -1,
    };
    if n < MIN_FILE_SIZE { return -1; }
    let data = &buf[..n];

    if is_known_format(data) {
        unsafe {
            (*out).is_known_format = true;
            (*out).entropy = 0.0;
            (*out).chi_square = 0.0;
            (*out).monte_carlo_pi_error = 100.0;
            (*out).is_encrypted = false;
        }
        return -3;
    }

    let entropy = shannon_entropy(data);
    let chi = chi_square_test(data);
    let pi_err = monte_carlo_pi(data);
    let encrypted = entropy >= ENTROPY_THRESHOLD
        && pi_err <= MONTE_CARLO_THRESHOLD
        && !(pi_err > 0.5 && chi > CHI_SQUARE_THRESHOLD);

    unsafe {
        (*out).entropy = entropy;
        (*out).chi_square = chi;
        (*out).monte_carlo_pi_error = pi_err;
        (*out).is_encrypted = encrypted;
        (*out).is_known_format = false;
    }
    0
}
