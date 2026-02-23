import Foundation

/// Single source of truth for undocumented C syscall/dyld bindings.
/// These are stable ABI but not in public headers.
/// One declaration per symbol avoids @_silgen_name type-mismatch conflicts.

// MARK: - Code Signing

@_silgen_name("csops")
func iris_csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer?, _ usersize: Int) -> Int32

// MARK: - SIP / CSR

@_silgen_name("csr_get_active_config")
func iris_csr_get_active_config(_ config: UnsafeMutablePointer<UInt32>) -> Int32

@_silgen_name("csr_check")
func iris_csr_check(_ mask: UInt32) -> Int32

// MARK: - dyld shared cache (from <mach-o/dyld_priv.h>)

@_silgen_name("_dyld_get_shared_cache_uuid")
func iris_dyld_get_shared_cache_uuid(_ uuid: UnsafeMutablePointer<uuid_t>) -> Bool

@_silgen_name("_dyld_get_shared_cache_range")
func iris_dyld_get_shared_cache_range(_ length: UnsafeMutablePointer<Int>) -> UnsafeRawPointer?
