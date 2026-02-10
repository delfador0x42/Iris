import Foundation
import MachO
import os.log

/// Parses Mach-O binaries to extract load commands for dylib hijack detection
public struct MachOParser {
    private static let logger = Logger(subsystem: "com.wudan.iris", category: "MachOParser")

    /// Parsed load command data from a Mach-O binary
    public struct LoadInfo: Sendable {
        public let path: String
        public let loadDylibs: [String]
        public let weakDylibs: [String]
        public let rpaths: [String]
        public let reexportDylibs: [String]
        public let fileType: UInt32
    }

    /// Parse a Mach-O binary and extract all load commands
    public static func parse(_ path: String) -> LoadInfo? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return nil
        }
        guard data.count >= 4 else { return nil }

        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }

        // Handle fat (universal) binaries
        if magic == FAT_MAGIC || magic == FAT_CIGAM ||
           magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64 {
            return parseFat(data, path: path)
        }

        return parseSingleArch(data, offset: 0, path: path)
    }

    private static func parseFat(_ data: Data, path: String) -> LoadInfo? {
        guard data.count >= MemoryLayout<fat_header>.size else { return nil }
        let header = data.withUnsafeBytes { $0.load(as: fat_header.self) }
        let archCount = Int(UInt32(bigEndian: header.nfat_arch))

        // Parse first architecture (usually sufficient for hijack detection)
        guard archCount > 0,
              data.count >= MemoryLayout<fat_header>.size + MemoryLayout<fat_arch>.size else {
            return nil
        }

        let archData = data.subdata(
            in: MemoryLayout<fat_header>.size..<(MemoryLayout<fat_header>.size + MemoryLayout<fat_arch>.size)
        )
        let arch = archData.withUnsafeBytes { $0.load(as: fat_arch.self) }
        let offset = Int(UInt32(bigEndian: arch.offset))

        return parseSingleArch(data, offset: offset, path: path)
    }

    private static func parseSingleArch(_ data: Data, offset: Int, path: String) -> LoadInfo? {
        guard offset + MemoryLayout<mach_header_64>.size <= data.count else { return nil }

        let slice = data.subdata(in: offset..<data.count)
        let magic = slice.withUnsafeBytes { $0.load(as: UInt32.self) }

        let headerSize: Int
        let ncmds: UInt32
        let fileType: UInt32

        switch magic {
        case MH_MAGIC_64, MH_CIGAM_64:
            let h = slice.withUnsafeBytes { $0.load(as: mach_header_64.self) }
            headerSize = MemoryLayout<mach_header_64>.size
            ncmds = h.ncmds
            fileType = h.filetype
        case MH_MAGIC, MH_CIGAM:
            let h = slice.withUnsafeBytes { $0.load(as: mach_header.self) }
            headerSize = MemoryLayout<mach_header>.size
            ncmds = h.ncmds
            fileType = h.filetype
        default:
            return nil
        }

        var loadDylibs: [String] = []
        var weakDylibs: [String] = []
        var rpaths: [String] = []
        var reexports: [String] = []
        var cmdOffset = headerSize

        for _ in 0..<ncmds {
            guard cmdOffset + MemoryLayout<load_command>.size <= slice.count else { break }
            let cmdSlice = slice.subdata(in: cmdOffset..<slice.count)
            let cmd = cmdSlice.withUnsafeBytes { $0.load(as: load_command.self) }

            if let name = extractDylibName(cmdSlice, cmdSize: Int(cmd.cmdsize)) {
                switch cmd.cmd {
                case UInt32(LC_LOAD_DYLIB):
                    loadDylibs.append(name)
                case UInt32(LC_LOAD_WEAK_DYLIB):
                    weakDylibs.append(name)
                case UInt32(LC_RPATH):
                    rpaths.append(name)
                case UInt32(LC_REEXPORT_DYLIB):
                    reexports.append(name)
                default:
                    break
                }
            }

            cmdOffset += Int(cmd.cmdsize)
        }

        return LoadInfo(
            path: path,
            loadDylibs: loadDylibs,
            weakDylibs: weakDylibs,
            rpaths: rpaths,
            reexportDylibs: reexports,
            fileType: fileType
        )
    }

    /// Extract the dylib name string from a load command
    private static func extractDylibName(_ data: Data, cmdSize: Int) -> String? {
        // For dylib_command: name offset is at byte 12 (after cmd + cmdsize + offset)
        // For rpath_command: path offset is at byte 8
        let cmd = data.withUnsafeBytes { $0.load(as: load_command.self) }
        let nameOffset: Int

        switch cmd.cmd {
        case UInt32(LC_RPATH):
            guard data.count >= MemoryLayout<rpath_command>.size else { return nil }
            let rpath = data.withUnsafeBytes { $0.load(as: rpath_command.self) }
            nameOffset = Int(rpath.path.offset)
        case UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB), UInt32(LC_REEXPORT_DYLIB):
            guard data.count >= MemoryLayout<dylib_command>.size else { return nil }
            let dylib = data.withUnsafeBytes { $0.load(as: dylib_command.self) }
            nameOffset = Int(dylib.dylib.name.offset)
        default:
            return nil
        }

        guard nameOffset >= 0, nameOffset < cmdSize, nameOffset < data.count else { return nil }
        let maxLen = min(cmdSize - nameOffset, data.count - nameOffset)
        guard maxLen > 0, nameOffset <= data.count - maxLen else { return nil }
        let nameData = data.subdata(in: nameOffset..<(nameOffset + maxLen))

        guard let str = String(bytes: nameData, encoding: .utf8) else { return nil }
        // Trim at null terminator
        if let nullIdx = str.firstIndex(of: "\0") {
            return String(str[str.startIndex..<nullIdx])
        }
        return str
    }
}
