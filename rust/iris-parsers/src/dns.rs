//! DNS wire format parser (RFC 1035) and query builder.

use crate::ffi::alloc_bytes;
use std::ffi::{CString, CStr, c_char};

// --- C FFI types ---

#[repr(C)]
pub struct IrisDnsQuestion {
    pub name: *mut c_char,
    pub record_type: u16,
    pub qclass: u16,
}

#[repr(C)]
pub struct IrisDnsRecord {
    pub name: *mut c_char,
    pub record_type: u16,
    pub rrclass: u16,
    pub ttl: u32,
    pub rdata: *mut u8,
    pub rdata_len: usize,
    pub display_value: *mut c_char,
}

#[repr(C)]
pub struct IrisDnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub is_authoritative: bool,
    pub is_truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: u8,
    pub questions: *mut IrisDnsQuestion,
    pub questions_count: usize,
    pub answers: *mut IrisDnsRecord,
    pub answers_count: usize,
    pub authority: *mut IrisDnsRecord,
    pub authority_count: usize,
    pub additional: *mut IrisDnsRecord,
    pub additional_count: usize,
}

// --- Internal types ---

struct DnsQ { name: String, qtype: u16, qclass: u16 }
struct DnsRR { name: String, rtype: u16, rclass: u16, ttl: u32, rdata: Vec<u8>, display: String }

// --- Parsing ---

fn parse_dns(data: &[u8]) -> Option<(u16, bool, u8, bool, bool, bool, bool, u8,
    Vec<DnsQ>, Vec<DnsRR>, Vec<DnsRR>, Vec<DnsRR>)>
{
    if data.len() < 12 { return None; }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let counts: Vec<usize> = (0..4).map(|i| {
        u16::from_be_bytes([data[4 + i * 2], data[5 + i * 2]]) as usize
    }).collect();
    if counts.iter().any(|&c| c > 256) { return None; }

    let mut off = 12usize;
    let mut questions = Vec::with_capacity(counts[0]);
    for _ in 0..counts[0] {
        let (name, new_off) = parse_name(data, off)?;
        off = new_off;
        if off + 4 > data.len() { return None; }
        let qt = u16::from_be_bytes([data[off], data[off + 1]]);
        let qc = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
        questions.push(DnsQ { name, qtype: qt, qclass: qc });
    }

    let mut answers = Vec::with_capacity(counts[1]);
    for _ in 0..counts[1] {
        let (rr, new_off) = parse_rr(data, off)?;
        off = new_off;
        answers.push(rr);
    }
    let authority = parse_rr_section(data, &mut off, counts[2]);
    let additional = parse_rr_section(data, &mut off, counts[3]);

    Some((id, flags & 0x8000 != 0, ((flags >> 11) & 0xF) as u8,
          flags & 0x0400 != 0, flags & 0x0200 != 0,
          flags & 0x0100 != 0, flags & 0x0080 != 0, (flags & 0xF) as u8,
          questions, answers, authority, additional))
}

fn parse_rr_section(data: &[u8], off: &mut usize, count: usize) -> Vec<DnsRR> {
    let mut rrs = Vec::new();
    for _ in 0..count {
        if let Some((rr, new_off)) = parse_rr(data, *off) {
            *off = new_off;
            rrs.push(rr);
        } else { break; }
    }
    rrs
}

fn parse_name(data: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end_pos = 0usize;
    let mut jumped = false;
    let mut jumps = 0u8;
    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped { end_pos = pos + 1; }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() { return None; }
            if !jumped { end_pos = pos + 2; }
            pos = ((len & 0x3F) << 8) | data[pos + 1] as usize;
            jumped = true;
            jumps += 1;
            if jumps > 10 { return None; }
            continue;
        }
        if len > 63 { return None; }
        pos += 1;
        if pos + len > data.len() { return None; }
        labels.push(std::str::from_utf8(&data[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
    let name = if labels.is_empty() { ".".into() } else { labels.join(".") };
    Some((name, if jumped { end_pos } else { end_pos }))
}

fn parse_rr(data: &[u8], offset: usize) -> Option<(DnsRR, usize)> {
    let (name, mut pos) = parse_name(data, offset)?;
    if pos + 10 > data.len() { return None; }
    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    pos += 10;
    if pos + rdlen > data.len() { return None; }
    let rdata = data[pos..pos + rdlen].to_vec();
    let display = format_rdata(rtype, &rdata, data, pos);
    pos += rdlen;
    Some((DnsRR { name, rtype, rclass, ttl, rdata, display }, pos))
}

// --- RDATA formatting ---

fn format_rdata(rtype: u16, rd: &[u8], msg: &[u8], start: usize) -> String {
    match rtype {
        1 if rd.len() == 4 => format!("{}.{}.{}.{}", rd[0], rd[1], rd[2], rd[3]),
        28 if rd.len() == 16 => (0..8)
            .map(|i| format!("{:x}", u16::from_be_bytes([rd[i * 2], rd[i * 2 + 1]])))
            .collect::<Vec<_>>().join(":"),
        2 | 5 | 12 => parse_name(msg, start).map(|(n, _)| n).unwrap_or_else(|| hex(rd)),
        15 if rd.len() >= 3 => {
            let pri = u16::from_be_bytes([rd[0], rd[1]]);
            let n = parse_name(msg, start + 2).map(|(n, _)| n).unwrap_or_default();
            format!("{} {}", pri, n)
        }
        16 => { // TXT
            let mut parts = Vec::new();
            let mut p = 0;
            while p < rd.len() {
                let len = rd[p] as usize;
                p += 1;
                if p + len > rd.len() { break; }
                if let Ok(s) = std::str::from_utf8(&rd[p..p + len]) { parts.push(s.to_string()); }
                p += len;
            }
            parts.join("")
        }
        33 if rd.len() >= 7 => { // SRV
            let pri = u16::from_be_bytes([rd[0], rd[1]]);
            let wt = u16::from_be_bytes([rd[2], rd[3]]);
            let port = u16::from_be_bytes([rd[4], rd[5]]);
            let tgt = parse_name(msg, start + 6).map(|(n, _)| n).unwrap_or_default();
            format!("{} {} {} {}", pri, wt, port, tgt)
        }
        64 | 65 if rd.len() >= 3 => { // SVCB / HTTPS
            let pri = u16::from_be_bytes([rd[0], rd[1]]);
            let tgt = parse_name(msg, start + 2).map(|(n, _)| n).unwrap_or_default();
            if pri == 0 { format!("AliasMode {}", tgt) } else { format!("{} {}", pri, tgt) }
        }
        _ => hex(rd),
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// --- Serialization ---

fn serialize_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let len = label.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&label.as_bytes()[..len]);
    }
    out.push(0);
    out
}

fn build_query_bytes(domain: &str, rtype: u16, id: u16, rd: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&(if rd { 0x0100u16 } else { 0u16 }).to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&[0; 6]); // AN/NS/AR = 0
    buf.extend(serialize_name(domain));
    buf.extend_from_slice(&rtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    buf
}

// --- FFI helpers ---

fn to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap()).into_raw()
}

fn alloc_questions(qs: Vec<DnsQ>) -> (*mut IrisDnsQuestion, usize) {
    let count = qs.len();
    if count == 0 { return (std::ptr::null_mut(), 0); }
    let layout = std::alloc::Layout::array::<IrisDnsQuestion>(count).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut IrisDnsQuestion };
    if ptr.is_null() { return (std::ptr::null_mut(), 0); }
    for (i, q) in qs.into_iter().enumerate() {
        unsafe {
            ptr.add(i).write(IrisDnsQuestion {
                name: to_cstr(&q.name), record_type: q.qtype, qclass: q.qclass,
            });
        }
    }
    (ptr, count)
}

fn alloc_records(rrs: Vec<DnsRR>) -> (*mut IrisDnsRecord, usize) {
    let count = rrs.len();
    if count == 0 { return (std::ptr::null_mut(), 0); }
    let layout = std::alloc::Layout::array::<IrisDnsRecord>(count).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut IrisDnsRecord };
    if ptr.is_null() { return (std::ptr::null_mut(), 0); }
    for (i, rr) in rrs.into_iter().enumerate() {
        let (rdata_ptr, rdata_len) = alloc_bytes(&rr.rdata);
        unsafe {
            ptr.add(i).write(IrisDnsRecord {
                name: to_cstr(&rr.name), record_type: rr.rtype, rrclass: rr.rclass,
                ttl: rr.ttl, rdata: rdata_ptr, rdata_len,
                display_value: to_cstr(&rr.display),
            });
        }
    }
    (ptr, count)
}

// --- FFI entry points ---

/// Parse DNS wire format. Returns 0=ok, -2=error.
#[no_mangle]
pub extern "C" fn iris_dns_parse(data: *const u8, len: usize, out: *mut IrisDnsMessage) -> i32 {
    if data.is_null() || out.is_null() || len == 0 { return -2; }
    let buf = unsafe { std::slice::from_raw_parts(data, len) };
    match parse_dns(buf) {
        Some((id, is_resp, opcode, aa, tc, rd, ra, rcode, qs, ans, auth, add)) => {
            let (qp, qc) = alloc_questions(qs);
            let (ap, ac) = alloc_records(ans);
            let (np, nc) = alloc_records(auth);
            let (dp, dc) = alloc_records(add);
            unsafe {
                out.write(IrisDnsMessage {
                    id, is_response: is_resp, opcode, is_authoritative: aa,
                    is_truncated: tc, recursion_desired: rd, recursion_available: ra,
                    response_code: rcode,
                    questions: qp, questions_count: qc,
                    answers: ap, answers_count: ac,
                    authority: np, authority_count: nc,
                    additional: dp, additional_count: dc,
                });
            }
            0
        }
        None => -2,
    }
}

/// Build a DNS query. Returns serialized bytes via out_data/out_len. Free with iris_free_bytes.
#[no_mangle]
pub extern "C" fn iris_dns_build_query(
    domain: *const c_char, record_type: u16, id: u16, recursion_desired: bool,
    out_data: *mut *mut u8, out_len: *mut usize,
) -> i32 {
    if domain.is_null() || out_data.is_null() || out_len.is_null() { return -2; }
    let domain_str = match unsafe { CStr::from_ptr(domain) }.to_str() {
        Ok(s) => s, Err(_) => return -2,
    };
    let bytes = build_query_bytes(domain_str, record_type, id, recursion_desired);
    let (ptr, len) = alloc_bytes(&bytes);
    unsafe { *out_data = ptr; *out_len = len; }
    0
}

fn free_questions(ptr: *mut IrisDnsQuestion, count: usize) {
    if ptr.is_null() || count == 0 { return; }
    for i in 0..count {
        unsafe {
            let q = &*ptr.add(i);
            if !q.name.is_null() { drop(CString::from_raw(q.name)); }
        }
    }
    let layout = std::alloc::Layout::array::<IrisDnsQuestion>(count).unwrap();
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout); }
}

fn free_records(ptr: *mut IrisDnsRecord, count: usize) {
    if ptr.is_null() || count == 0 { return; }
    for i in 0..count {
        unsafe {
            let r = &*ptr.add(i);
            if !r.name.is_null() { drop(CString::from_raw(r.name)); }
            if !r.display_value.is_null() { drop(CString::from_raw(r.display_value)); }
            if !r.rdata.is_null() && r.rdata_len > 0 {
                let layout = std::alloc::Layout::array::<u8>(r.rdata_len).unwrap();
                std::alloc::dealloc(r.rdata, layout);
            }
        }
    }
    let layout = std::alloc::Layout::array::<IrisDnsRecord>(count).unwrap();
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout); }
}

/// Free all allocations in a parsed DNS message.
#[no_mangle]
pub extern "C" fn iris_dns_free_message(msg: *mut IrisDnsMessage) {
    if msg.is_null() { return; }
    unsafe {
        let m = &*msg;
        free_questions(m.questions, m.questions_count);
        free_records(m.answers, m.answers_count);
        free_records(m.authority, m.authority_count);
        free_records(m.additional, m.additional_count);
    }
}
