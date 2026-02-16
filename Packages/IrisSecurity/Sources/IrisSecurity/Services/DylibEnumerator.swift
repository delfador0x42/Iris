import Foundation
import MachO
import os.log

/// Enumerates loaded dylibs for a process.
/// Primary: task_info(TASK_DYLD_INFO) — reads dyld's image list (requires root).
/// Fallback: PROC_PIDREGIONPATHINFO — walks VM regions (no root, misses shared cache).
enum DylibEnumerator {

    /// Enumeration method used — callers should note when coverage is incomplete.
    enum Method: String { case dyld, vmRegion }
    struct Result { let images: [String]; let method: Method }

    private static let logger = Logger(subsystem: "com.wudan.iris", category: "DylibEnumerator")

    /// Returns loaded images with method metadata.
    static func loadedImagesWithMethod(for pid: pid_t) -> Result {
        if let images = loadedImagesDyld(pid: pid), !images.isEmpty {
            return Result(images: images, method: .dyld)
        }
        logger.info("PID \(pid): TASK_DYLD_INFO failed, falling back to VM region scan (incomplete)")
        return Result(images: loadedImagesRegions(pid: pid), method: .vmRegion)
    }

    /// Legacy convenience — returns just the image list.
    static func loadedImages(for pid: pid_t) -> [String] {
        loadedImagesWithMethod(for: pid).images
    }

    // MARK: - TASK_DYLD_INFO (complete coverage, needs root)

    private static func loadedImagesDyld(pid: pid_t) -> [String]? {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }

        // Get dyld_all_image_infos address in target process
        var dyldInfo = task_dyld_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_dyld_info_data_t>.size / MemoryLayout<natural_t>.size
        )
        let kr = withUnsafeMutablePointer(to: &dyldInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(task, task_flavor_t(TASK_DYLD_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS, dyldInfo.all_image_info_addr != 0 else { return nil }

        // Read dyld_all_image_infos from target
        var allInfo = dyld_all_image_infos()
        guard readMem(task, dyldInfo.all_image_info_addr,
                      &allInfo, MemoryLayout<dyld_all_image_infos>.size) else { return nil }

        let imageCount = Int(allInfo.infoArrayCount)
        guard imageCount > 0 else { return nil }

        // infoArray pointer is in target's address space
        let arrayAddr = unsafeBitCast(allInfo.infoArray, to: UInt.self)
        guard arrayAddr != 0 else { return nil } // NULL = dyld updating

        // Read the dyld_image_info array
        let stride = MemoryLayout<dyld_image_info>.stride
        let buf = UnsafeMutableRawPointer.allocate(byteCount: stride * imageCount, alignment: 8)
        defer { buf.deallocate() }
        guard readMemRaw(task, mach_vm_address_t(arrayAddr),
                         buf, stride * imageCount) else { return nil }

        // Read each image path
        let infoArray = buf.bindMemory(to: dyld_image_info.self, capacity: imageCount)
        var images = Set<String>()
        var pathBuf = [CChar](repeating: 0, count: 1024)

        for i in 0..<imageCount {
            let pathPtr = unsafeBitCast(infoArray[i].imageFilePath, to: UInt.self)
            guard pathPtr != 0 else { continue }
            pathBuf[0] = 0
            pathBuf.withUnsafeMutableBufferPointer { bp in
                _ = readMemRaw(task, mach_vm_address_t(pathPtr),
                               bp.baseAddress!, 1023)
            }
            pathBuf[1023] = 0
            let path = String(cString: pathBuf)
            if !path.isEmpty { images.insert(path) }
        }

        return Array(images)
    }

    // MARK: - PROC_PIDREGIONPATHINFO fallback (partial, no root)

    private static func loadedImagesRegions(pid: pid_t) -> [String] {
        var images = Set<String>()
        var address: UInt64 = 0

        for _ in 0..<50_000 {
            var rwpi = proc_regionwithpathinfo()
            let size = proc_pidinfo(
                pid, PROC_PIDREGIONPATHINFO, address,
                &rwpi, Int32(MemoryLayout<proc_regionwithpathinfo>.size)
            )
            guard size > 0 else { break }

            let path = withUnsafePointer(to: rwpi.prp_vip.vip_path) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }
            if !path.isEmpty && (path.hasSuffix(".dylib") || path.contains(".framework/")) {
                images.insert(path)
            }

            let regionEnd = rwpi.prp_prinfo.pri_address + rwpi.prp_prinfo.pri_size
            guard regionEnd > address else { break }
            address = regionEnd
        }
        return Array(images)
    }

    // MARK: - Mach VM helpers

    private static func readMem<T>(_ task: mach_port_t, _ addr: mach_vm_address_t,
                                   _ out: inout T, _ size: Int) -> Bool {
        var outSize: mach_vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &out) { ptr in
            mach_vm_read_overwrite(
                task, addr, mach_vm_size_t(size),
                mach_vm_address_t(UInt(bitPattern: ptr)), &outSize
            )
        }
        return kr == KERN_SUCCESS
    }

    private static func readMemRaw(_ task: mach_port_t, _ addr: mach_vm_address_t,
                                   _ buf: UnsafeMutableRawPointer, _ size: Int) -> Bool {
        var outSize: mach_vm_size_t = 0
        let kr = mach_vm_read_overwrite(
            task, addr, mach_vm_size_t(size),
            mach_vm_address_t(UInt(bitPattern: buf)), &outSize
        )
        return kr == KERN_SUCCESS
    }
}
