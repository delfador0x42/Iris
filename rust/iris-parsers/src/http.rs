use std::slice;

const MAX_HEADERS: usize = 64;

/// A borrowed slice (pointer + length) into the caller's buffer.
/// Valid only while the original data buffer is alive.
#[repr(C)]
pub struct IrisSlice {
    pub ptr: *const u8,
    pub len: usize,
}

impl IrisSlice {
    fn from_bytes(b: &[u8]) -> Self {
        IrisSlice { ptr: b.as_ptr(), len: b.len() }
    }
}

#[repr(C)]
pub struct IrisHttpHeader {
    pub name: IrisSlice,
    pub value: IrisSlice,
}

#[repr(C)]
pub struct IrisHttpRequest {
    pub method: IrisSlice,
    pub path: IrisSlice,
    pub version_minor: u8, // 0 = HTTP/1.0, 1 = HTTP/1.1
    pub header_end_index: usize,
    pub content_length: i64, // -1 = absent
    pub is_chunked: bool,
    pub headers: *mut IrisHttpHeader,
    pub headers_count: usize,
}

#[repr(C)]
pub struct IrisHttpResponse {
    pub status_code: u16,
    pub reason: IrisSlice,
    pub version_minor: u8,
    pub header_end_index: usize,
    pub content_length: i64,
    pub is_chunked: bool,
    pub has_body: bool,
    pub has_framing: bool,
    pub should_close: bool,
    pub headers: *mut IrisHttpHeader,
    pub headers_count: usize,
}

/// Check Content-Length validity: reject multiple differing values,
/// reject > 100MB. Returns Ok(Some(len)), Ok(None), or Err on conflict.
fn parse_content_length(headers: &[httparse::Header]) -> Result<Option<i64>, ()> {
    let mut values: Vec<i64> = Vec::new();
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            if let Ok(s) = std::str::from_utf8(h.value) {
                if let Ok(v) = s.trim().parse::<i64>() {
                    if v > 104_857_600 { return Err(()); }
                    if !values.contains(&v) { values.push(v); }
                }
            }
        }
    }
    if values.len() > 1 { return Err(()); } // CL-CL desync
    Ok(values.first().copied())
}

fn is_chunked(headers: &[httparse::Header]) -> bool {
    headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && h.value.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked"))
    })
}

fn alloc_headers(headers: &[httparse::Header]) -> (*mut IrisHttpHeader, usize) {
    let count = headers.len();
    if count == 0 {
        return (std::ptr::null_mut(), 0);
    }
    let layout = std::alloc::Layout::array::<IrisHttpHeader>(count).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut IrisHttpHeader };
    if ptr.is_null() {
        return (std::ptr::null_mut(), 0);
    }
    for (i, h) in headers.iter().enumerate() {
        unsafe {
            ptr.add(i).write(IrisHttpHeader {
                name: IrisSlice::from_bytes(h.name.as_bytes()),
                value: IrisSlice::from_bytes(h.value),
            });
        }
    }
    (ptr, count)
}

/// Parse an HTTP request from raw bytes.
/// Returns: 0 = success, -1 = incomplete, -2 = error.
/// On success, `out` is populated. Caller must call `iris_http_free_request`.
/// Slices in `out` point into the original `data` buffer — keep it alive.
#[no_mangle]
pub extern "C" fn iris_http_parse_request(
    data: *const u8,
    len: usize,
    out: *mut IrisHttpRequest,
) -> i32 {
    if data.is_null() || out.is_null() || len == 0 {
        return -2;
    }
    let buf = unsafe { slice::from_raw_parts(data, len) };
    let mut hdr_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut hdr_buf);

    match req.parse(buf) {
        Ok(httparse::Status::Complete(offset)) => {
            let chunked = is_chunked(req.headers);
            let cl = if chunked {
                -1
            } else {
                match parse_content_length(req.headers) {
                    Ok(Some(v)) => v,
                    Ok(None) => -1,
                    Err(()) => return -2, // CL-CL conflict
                }
            };
            let version_minor = req.version.unwrap_or(1) as u8;
            let method = req.method.unwrap_or("");
            let path = req.path.unwrap_or("");
            let (h_ptr, h_count) = alloc_headers(req.headers);

            unsafe {
                out.write(IrisHttpRequest {
                    method: IrisSlice::from_bytes(method.as_bytes()),
                    path: IrisSlice::from_bytes(path.as_bytes()),
                    version_minor,
                    header_end_index: offset,
                    content_length: cl,
                    is_chunked: chunked,
                    headers: h_ptr,
                    headers_count: h_count,
                });
            }
            0
        }
        Ok(httparse::Status::Partial) => -1,
        Err(_) => -2,
    }
}

/// Parse an HTTP response from raw bytes.
/// Returns: 0 = success, -1 = incomplete, -2 = error.
#[no_mangle]
pub extern "C" fn iris_http_parse_response(
    data: *const u8,
    len: usize,
    out: *mut IrisHttpResponse,
) -> i32 {
    if data.is_null() || out.is_null() || len == 0 {
        return -2;
    }
    let buf = unsafe { slice::from_raw_parts(data, len) };
    let mut hdr_buf = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut hdr_buf);

    match resp.parse(buf) {
        Ok(httparse::Status::Complete(offset)) => {
            let status = resp.code.unwrap_or(0);
            let reason = resp.reason.unwrap_or("");
            let version_minor = resp.version.unwrap_or(1) as u8;
            let chunked = is_chunked(resp.headers);
            let cl = if chunked {
                -1
            } else {
                match parse_content_length(resp.headers) {
                    Ok(Some(v)) => v,
                    Ok(None) => -1,
                    Err(()) => return -2,
                }
            };

            // RFC 7230 §3.3: 1xx, 204, 304 have no body
            let has_body = status >= 200 && status != 204 && status != 304;
            let has_framing = cl >= 0 || chunked;

            // Connection: close or HTTP/1.0 without keep-alive
            let conn_header = resp.headers.iter()
                .find(|h| h.name.eq_ignore_ascii_case("connection"))
                .and_then(|h| std::str::from_utf8(h.value).ok());
            let should_close = match conn_header {
                Some(v) if v.eq_ignore_ascii_case("close") => true,
                Some(v) if v.eq_ignore_ascii_case("keep-alive") => false,
                _ => version_minor == 0, // HTTP/1.0 defaults to close
            };

            let (h_ptr, h_count) = alloc_headers(resp.headers);

            unsafe {
                out.write(IrisHttpResponse {
                    status_code: status,
                    reason: IrisSlice::from_bytes(reason.as_bytes()),
                    version_minor,
                    header_end_index: offset,
                    content_length: cl,
                    is_chunked: chunked,
                    has_body,
                    has_framing,
                    should_close,
                    headers: h_ptr,
                    headers_count: h_count,
                });
            }
            0
        }
        Ok(httparse::Status::Partial) => -1,
        Err(_) => -2,
    }
}

/// Free the headers array allocated by parse_request.
#[no_mangle]
pub extern "C" fn iris_http_free_request(req: *mut IrisHttpRequest) {
    if req.is_null() { return; }
    unsafe {
        let r = &*req;
        free_headers(r.headers, r.headers_count);
    }
}

/// Free the headers array allocated by parse_response.
#[no_mangle]
pub extern "C" fn iris_http_free_response(resp: *mut IrisHttpResponse) {
    if resp.is_null() { return; }
    unsafe {
        let r = &*resp;
        free_headers(r.headers, r.headers_count);
    }
}

fn free_headers(ptr: *mut IrisHttpHeader, count: usize) {
    if ptr.is_null() || count == 0 { return; }
    let layout = std::alloc::Layout::array::<IrisHttpHeader>(count).unwrap();
    unsafe { std::alloc::dealloc(ptr as *mut u8, layout); }
}

// --- Helper for tests: read a slice back to &str ---
#[cfg(test)]
fn slice_str(s: &IrisSlice) -> &str {
    if s.ptr.is_null() || s.len == 0 { return ""; }
    unsafe { std::str::from_utf8_unchecked(slice::from_raw_parts(s.ptr, s.len)) }
}

#[cfg(test)]
fn header_name(req_headers: *mut IrisHttpHeader, i: usize) -> &'static str {
    unsafe { slice_str(&(*req_headers.add(i)).name) }
}

#[cfg(test)]
fn header_value(req_headers: *mut IrisHttpHeader, i: usize) -> &'static str {
    unsafe { slice_str(&(*req_headers.add(i)).value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_get() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        assert_eq!(slice_str(&req.method), "GET");
        assert_eq!(slice_str(&req.path), "/path");
        assert_eq!(req.version_minor, 1);
        assert_eq!(req.headers_count, 1);
        assert_eq!(header_name(req.headers, 0), "Host");
        assert_eq!(header_value(req.headers, 0), "example.com");
        assert_eq!(req.content_length, -1);
        assert!(!req.is_chunked);
        assert_eq!(req.header_end_index, data.len());
        free_headers(req.headers, req.headers_count);
    }

    #[test]
    fn parse_post_with_content_length() {
        let data = b"POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 23\r\n\r\n{\"name\": \"test user\"}";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        assert_eq!(slice_str(&req.method), "POST");
        assert_eq!(slice_str(&req.path), "/api/users");
        assert_eq!(req.content_length, 23);
        assert!(!req.is_chunked);
        assert_eq!(req.headers_count, 3);
        free_headers(req.headers, req.headers_count);
    }

    #[test]
    fn parse_chunked_request() {
        let data = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        assert!(req.is_chunked);
        assert_eq!(req.content_length, -1);
        free_headers(req.headers, req.headers_count);
    }

    #[test]
    fn parse_connect_request() {
        let data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        assert_eq!(slice_str(&req.method), "CONNECT");
        assert_eq!(slice_str(&req.path), "example.com:443");
        free_headers(req.headers, req.headers_count);
    }

    #[test]
    fn incomplete_request_returns_minus_one() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, -1);
    }

    #[test]
    fn parse_request_with_query_params() {
        let data = b"GET /search?q=test&page=1&limit=10 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        assert_eq!(slice_str(&req.path), "/search?q=test&page=1&limit=10");
        free_headers(req.headers, req.headers_count);
    }

    #[test]
    fn parse_multiple_headers() {
        let data = b"GET /api HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Test/1.0\r\nAccept: application/json\r\nAuthorization: Bearer tok\r\nCache-Control: no-cache\r\n\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        assert_eq!(req.headers_count, 5);
        assert_eq!(header_name(req.headers, 0), "Host");
        assert_eq!(header_name(req.headers, 1), "User-Agent");
        assert_eq!(header_name(req.headers, 2), "Accept");
        assert_eq!(header_name(req.headers, 3), "Authorization");
        assert_eq!(header_name(req.headers, 4), "Cache-Control");
        free_headers(req.headers, req.headers_count);
    }

    // --- Response tests ---

    #[test]
    fn parse_200_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.status_code, 200);
        assert_eq!(slice_str(&resp.reason), "OK");
        assert_eq!(resp.version_minor, 1);
        assert_eq!(resp.content_length, 13);
        assert!(resp.has_body);
        assert!(resp.has_framing);
        assert!(!resp.should_close);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn parse_404_response() {
        let data = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.status_code, 404);
        assert_eq!(slice_str(&resp.reason), "Not Found");
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn parse_204_no_body() {
        let data = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.status_code, 204);
        assert!(!resp.has_body);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn parse_304_no_body() {
        let data = b"HTTP/1.1 304 Not Modified\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert!(!resp.has_body);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn parse_chunked_response() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert!(resp.is_chunked);
        assert_eq!(resp.content_length, -1);
        assert!(resp.has_framing);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn parse_response_no_reason() {
        let data = b"HTTP/1.1 204\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.status_code, 204);
        assert_eq!(slice_str(&resp.reason), "");
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn incomplete_response_returns_minus_one() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, -1);
    }

    #[test]
    fn connection_close_detected() {
        let data = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert!(resp.should_close);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn http10_defaults_to_close() {
        let data = b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.version_minor, 0);
        assert!(resp.should_close);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn http10_keepalive_not_close() {
        let data = b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert!(!resp.should_close);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn duplicate_content_length_rejected() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, -2); // CL-CL desync rejected
    }

    #[test]
    fn oversized_content_length_rejected() {
        let data = b"POST /big HTTP/1.1\r\nHost: x\r\nContent-Length: 999999999\r\n\r\n";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, -2);
    }

    #[test]
    fn null_data_returns_error() {
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(std::ptr::null(), 0, req.as_mut_ptr());
        assert_eq!(rc, -2);
    }

    #[test]
    fn multiple_set_cookie_headers() {
        let data = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Path=/\r\nSet-Cookie: user=john; HttpOnly\r\nContent-Type: text/html\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.headers_count, 3);
        let mut cookie_count = 0;
        for i in 0..resp.headers_count {
            if header_name(resp.headers, i) == "Set-Cookie" {
                cookie_count += 1;
            }
        }
        assert_eq!(cookie_count, 2);
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn parse_301_redirect() {
        let data = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://new.example.com/\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert_eq!(resp.status_code, 301);
        assert_eq!(header_value(resp.headers, 0), "https://new.example.com/");
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn chunked_overrides_content_length() {
        // RFC 7230 §3.3.3: Transfer-Encoding overrides Content-Length
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut resp = std::mem::MaybeUninit::<IrisHttpResponse>::uninit();
        let rc = iris_http_parse_response(data.as_ptr(), data.len(), resp.as_mut_ptr());
        assert_eq!(rc, 0);
        let resp = unsafe { resp.assume_init() };
        assert!(resp.is_chunked);
        assert_eq!(resp.content_length, -1); // CL ignored when chunked
        free_headers(resp.headers, resp.headers_count);
    }

    #[test]
    fn header_end_index_correct() {
        let data = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY";
        let mut req = std::mem::MaybeUninit::<IrisHttpRequest>::uninit();
        let rc = iris_http_parse_request(data.as_ptr(), data.len(), req.as_mut_ptr());
        assert_eq!(rc, 0);
        let req = unsafe { req.assume_init() };
        // header_end_index should point right after \r\n\r\n, at 'B'
        assert_eq!(&data[req.header_end_index..], b"BODY");
        free_headers(req.headers, req.headers_count);
    }
}
