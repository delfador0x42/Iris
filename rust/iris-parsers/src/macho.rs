//! Mach-O binary parser using goblin. Extracts load commands for dylib hijack detection.

use crate::ffi::{IrisCStringArray, vec_to_c_string_array, free_c_string_array};
use goblin::mach::{MachO, MultiArch};
use goblin::mach::load_command::CommandVariant;
use std::ffi::{CStr, c_char};

#[repr(C)]
pub struct IrisMachOInfo {
    pub load_dylibs: IrisCStringArray,
    pub weak_dylibs: IrisCStringArray,
    pub rpaths: IrisCStringArray,
    pub reexport_dylibs: IrisCStringArray,
    pub file_type: u32,
}

struct ParseResult {
    load_dylibs: Vec<String>,
    weak_dylibs: Vec<String>,
    rpaths: Vec<String>,
    reexport_dylibs: Vec<String>,
    file_type: u32,
}

/// Read a null-terminated C string from bytes at the given offset.
fn cstr_at(bytes: &[u8], offset: usize) -> Option<&str> {
    if offset >= bytes.len() { return None; }
    let end = bytes[offset..].iter().position(|&b| b == 0)?;
    std::str::from_utf8(&bytes[offset..offset + end]).ok()
}

fn extract_info(macho: &MachO, bytes: &[u8]) -> ParseResult {
    let mut r = ParseResult {
        load_dylibs: Vec::new(), weak_dylibs: Vec::new(),
        rpaths: Vec::new(), reexport_dylibs: Vec::new(),
        file_type: macho.header.filetype,
    };
    for lc in &macho.load_commands {
        let (list, cmd_ref) = match lc.command {
            CommandVariant::LoadDylib(ref c)
            | CommandVariant::LazyLoadDylib(ref c)
            | CommandVariant::LoadUpwardDylib(ref c) => (&mut r.load_dylibs, c),
            CommandVariant::LoadWeakDylib(ref c) => (&mut r.weak_dylibs, c),
            CommandVariant::ReexportDylib(ref c) => (&mut r.reexport_dylibs, c),
            CommandVariant::Rpath(ref c) => {
                if let Some(name) = cstr_at(bytes, lc.offset + c.path as usize) {
                    r.rpaths.push(name.to_string());
                }
                continue;
            }
            _ => continue,
        };
        if let Some(name) = cstr_at(bytes, lc.offset + cmd_ref.dylib.name as usize) {
            list.push(name.to_string());
        }
    }
    r
}

fn parse_file(path: &str) -> Result<ParseResult, i32> {
    let bytes = std::fs::read(path).map_err(|_| -1)?;
    if bytes.len() < 4 { return Err(-2); }

    // Check for fat binary magic (big-endian 0xcafebabe or byte-swapped)
    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic == 0xcafe_babe || magic == 0xbeba_feca {
        let arches = {
            let multi = MultiArch::new(&bytes).map_err(|_| -2)?;
            multi.arches().map_err(|_| -2)?
        };
        if arches.is_empty() { return Err(-2); }
        let off = arches[0].offset as usize;
        let sz = arches[0].size as usize;
        if off.checked_add(sz).map_or(true, |end| end > bytes.len()) { return Err(-2); }
        let slice = &bytes[off..off + sz];
        let macho = MachO::parse_lossy(slice, 0).map_err(|_| -2)?;
        return Ok(extract_info(&macho, slice));
    }

    let macho = MachO::parse_lossy(&bytes, 0).map_err(|_| -2)?;
    Ok(extract_info(&macho, &bytes))
}

/// Parse a Mach-O binary at `path`. Returns 0=ok, -1=file error, -2=parse error.
#[no_mangle]
pub extern "C" fn iris_macho_parse(path: *const c_char, out: *mut IrisMachOInfo) -> i32 {
    if path.is_null() || out.is_null() { return -2; }
    let path_str = match unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };
    match parse_file(path_str) {
        Ok(r) => {
            unsafe {
                out.write(IrisMachOInfo {
                    load_dylibs: vec_to_c_string_array(r.load_dylibs),
                    weak_dylibs: vec_to_c_string_array(r.weak_dylibs),
                    rpaths: vec_to_c_string_array(r.rpaths),
                    reexport_dylibs: vec_to_c_string_array(r.reexport_dylibs),
                    file_type: r.file_type,
                });
            }
            0
        }
        Err(code) => code,
    }
}

/// Free all strings in an IrisMachOInfo.
#[no_mangle]
pub extern "C" fn iris_macho_free(info: *mut IrisMachOInfo) {
    if info.is_null() { return; }
    unsafe {
        let i = &*info;
        free_c_string_array(&i.load_dylibs);
        free_c_string_array(&i.weak_dylibs);
        free_c_string_array(&i.rpaths);
        free_c_string_array(&i.reexport_dylibs);
    }
}
