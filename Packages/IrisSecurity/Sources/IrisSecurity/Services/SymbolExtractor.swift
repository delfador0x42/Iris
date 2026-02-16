import Foundation
import MachO

/// Extract symbol table entries from Mach-O binaries via LC_SYMTAB + nlist_64.
/// No shell-out to /usr/bin/nm — reads raw bytes directly.
public enum SymbolExtractor {

  public struct Result: Sendable {
    public let importCount: Int
    public let exportCount: Int
    public let suspiciousImports: [String]
  }

  /// Extract symbol info from a Mach-O binary at path.
  public static func extract(path: String) -> Result? {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
          data.count >= MemoryLayout<mach_header_64>.size else { return nil }

    let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
    let offset: Int
    if magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64 {
      guard let o = firstArchOffset(data) else { return nil }
      offset = o
    } else {
      offset = 0
    }

    return parseSymtab(data, offset: offset)
  }

  private static func firstArchOffset(_ data: Data) -> Int? {
    guard data.count >= MemoryLayout<fat_header>.size + MemoryLayout<fat_arch>.size else { return nil }
    let archData = data.subdata(
      in: MemoryLayout<fat_header>.size..<(MemoryLayout<fat_header>.size + MemoryLayout<fat_arch>.size))
    let arch = archData.withUnsafeBytes { $0.load(as: fat_arch.self) }
    return Int(UInt32(bigEndian: arch.offset))
  }

  private static func parseSymtab(_ data: Data, offset: Int) -> Result? {
    guard offset + MemoryLayout<mach_header_64>.size <= data.count else { return nil }
    let slice = data.subdata(in: offset..<data.count)
    let magic = slice.withUnsafeBytes { $0.load(as: UInt32.self) }

    let headerSize: Int
    let ncmds: UInt32
    switch magic {
    case MH_MAGIC_64, MH_CIGAM_64:
      let h = slice.withUnsafeBytes { $0.load(as: mach_header_64.self) }
      headerSize = MemoryLayout<mach_header_64>.size
      ncmds = h.ncmds
    case MH_MAGIC, MH_CIGAM:
      let h = slice.withUnsafeBytes { $0.load(as: mach_header.self) }
      headerSize = MemoryLayout<mach_header>.size
      ncmds = h.ncmds
    default: return nil
    }

    // Find LC_SYMTAB
    var cmdOff = headerSize
    for _ in 0..<ncmds {
      guard cmdOff + MemoryLayout<load_command>.size <= slice.count else { break }
      let lc = slice.withUnsafeBytes { buf in
        buf.loadUnaligned(fromByteOffset: cmdOff, as: load_command.self)
      }
      if lc.cmd == UInt32(LC_SYMTAB) {
        guard cmdOff + MemoryLayout<symtab_command>.size <= slice.count else { break }
        let sym = slice.withUnsafeBytes { buf in
          buf.loadUnaligned(fromByteOffset: cmdOff, as: symtab_command.self)
        }
        return readSymbols(slice, sym: sym, is64: magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
      }
      cmdOff += Int(lc.cmdsize)
    }
    return nil
  }

  private static func readSymbols(_ data: Data, sym: symtab_command, is64: Bool) -> Result {
    let strOff = Int(sym.stroff)
    let strSize = Int(sym.strsize)
    let symOff = Int(sym.symoff)
    let nsyms = Int(sym.nsyms)
    let entrySize = is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size

    var imports = 0
    var exports = 0
    var suspicious: [String] = []
    var seen = Set<String>()

    for i in 0..<nsyms {
      let off = symOff + i * entrySize
      guard off + entrySize <= data.count else { break }

      let nType: UInt8
      let nStrx: UInt32
      if is64 {
        let entry = data.withUnsafeBytes { buf in
          buf.loadUnaligned(fromByteOffset: off, as: nlist_64.self)
        }
        nType = entry.n_type
        nStrx = entry.n_un.n_strx
      } else {
        let entry = data.withUnsafeBytes { buf in
          buf.loadUnaligned(fromByteOffset: off, as: nlist.self)
        }
        nType = entry.n_type
        nStrx = entry.n_un.n_strx
      }

      let isExternal = nType & 0x01 != 0 // N_EXT
      let isUndef = (nType & 0x0E) == 0   // N_UNDF — import
      if isExternal && isUndef { imports += 1 }
      else if isExternal { exports += 1 }

      // Read symbol name
      let nameOff = strOff + Int(nStrx)
      guard nameOff < strOff + strSize, nameOff < data.count else { continue }
      let maxLen = min(strOff + strSize - nameOff, 256)
      guard maxLen > 0, nameOff + maxLen <= data.count else { continue }
      let nameData = data.subdata(in: nameOff..<(nameOff + maxLen))
      guard let name = String(bytes: nameData, encoding: .utf8)?
              .components(separatedBy: "\0").first, !name.isEmpty else { continue }
      let clean = name.hasPrefix("_") ? String(name.dropFirst()) : name
      if !seen.contains(clean) && suspiciousNames.contains(clean) {
        seen.insert(clean)
        suspicious.append(clean)
      }
    }

    return Result(importCount: imports, exportCount: exports, suspiciousImports: suspicious)
  }

  private static let suspiciousNames: Set<String> = [
    "dlopen", "dlsym", "ptrace", "task_for_pid", "task_info",
    "csops", "IOServiceGetMatchingService", "IOServiceOpen",
    "SecItemCopyMatching", "SecItemAdd", "SecItemUpdate",
    "method_exchangeImplementations", "class_replaceMethod",
    "NSCreateObjectFileImageFromMemory", "NSLinkModule",
    "mach_vm_write", "mach_vm_protect", "mach_vm_allocate",
    "thread_create_running", "task_threads",
    "kqueue", "kevent64",
  ]
}
