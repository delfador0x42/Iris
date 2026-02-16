import Foundation

/// Rust-backed Mach-O parser using goblin. Drop-in replacement for MachOParser.
enum RustMachOParser {

    /// Parse a Mach-O binary and extract load commands.
    /// Returns the same LoadInfo type as MachOParser for API compatibility.
    static func parse(_ path: String) -> MachOParser.LoadInfo? {
        var info = IrisMachOInfo()
        let rc = path.withCString { cpath in
            iris_macho_parse(cpath, &info)
        }
        guard rc == 0 else { return nil }
        defer { iris_macho_free(&info) }

        return MachOParser.LoadInfo(
            path: path,
            loadDylibs: stringArray(info.load_dylibs),
            weakDylibs: stringArray(info.weak_dylibs),
            rpaths: stringArray(info.rpaths),
            reexportDylibs: stringArray(info.reexport_dylibs),
            fileType: info.file_type
        )
    }

    private static func stringArray(_ arr: IrisCStringArray) -> [String] {
        guard arr.count > 0, let items = arr.items else { return [] }
        return (0..<arr.count).compactMap { i in
            guard let cstr = items.advanced(by: i).pointee else { return nil }
            return String(cString: cstr)
        }
    }
}
