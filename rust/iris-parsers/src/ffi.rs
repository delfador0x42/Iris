//! Common FFI helpers shared across parser modules.

use std::ffi::{CString, c_char};

/// Array of owned null-terminated C strings, passed across FFI.
#[repr(C)]
pub struct IrisCStringArray {
    pub items: *mut *mut c_char,
    pub count: usize,
}

pub fn vec_to_c_string_array(strings: Vec<String>) -> IrisCStringArray {
    let count = strings.len();
    if count == 0 {
        return IrisCStringArray { items: std::ptr::null_mut(), count: 0 };
    }
    let layout = std::alloc::Layout::array::<*mut c_char>(count).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) as *mut *mut c_char };
    if ptr.is_null() {
        return IrisCStringArray { items: std::ptr::null_mut(), count: 0 };
    }
    for (i, s) in strings.into_iter().enumerate() {
        let cstr = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
        unsafe { ptr.add(i).write(cstr.into_raw()); }
    }
    IrisCStringArray { items: ptr, count }
}

pub fn free_c_string_array(arr: &IrisCStringArray) {
    if arr.items.is_null() || arr.count == 0 { return; }
    for i in 0..arr.count {
        unsafe {
            let s = *arr.items.add(i);
            if !s.is_null() { drop(CString::from_raw(s)); }
        }
    }
    let layout = std::alloc::Layout::array::<*mut c_char>(arr.count).unwrap();
    unsafe { std::alloc::dealloc(arr.items as *mut u8, layout); }
}

/// Allocate a copy of `data` on the heap. Caller frees with iris_free_bytes.
pub fn alloc_bytes(data: &[u8]) -> (*mut u8, usize) {
    if data.is_empty() {
        return (std::ptr::null_mut(), 0);
    }
    let layout = std::alloc::Layout::array::<u8>(data.len()).unwrap();
    let ptr = unsafe { std::alloc::alloc(layout) };
    if ptr.is_null() { return (std::ptr::null_mut(), 0); }
    unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()); }
    (ptr, data.len())
}

/// Free a byte buffer allocated by any iris_* function.
#[no_mangle]
pub extern "C" fn iris_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 { return; }
    let layout = std::alloc::Layout::array::<u8>(len).unwrap();
    unsafe { std::alloc::dealloc(ptr, layout); }
}
