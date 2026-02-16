import Foundation
import IOKit
import IOKit.usb

/// Native IOKit access — replaces shell-outs to /usr/sbin/ioreg.
/// Direct IOKit calls are faster and avoid Process() overhead.
public enum IOKitHelper {

  /// Walk an IOKit plane recursively and return all entry properties.
  public static func registryEntries(plane: String) -> [[String: Any]] {
    let root = IORegistryGetRootEntry(kIOMainPortDefault)
    var iterator: io_iterator_t = 0
    guard IORegistryEntryCreateIterator(
      root, plane,
      IOOptionBits(kIORegistryIterateRecursively),
      &iterator
    ) == KERN_SUCCESS else { return [] }
    defer { IOObjectRelease(iterator) }
    return collectEntries(iterator)
  }

  /// Get properties for all services matching a dictionary.
  public static func matchingServices(
    _ matching: CFDictionary
  ) -> [[String: Any]] {
    var iterator: io_iterator_t = 0
    guard IOServiceGetMatchingServices(
      kIOMainPortDefault, matching, &iterator
    ) == KERN_SUCCESS else { return [] }
    defer { IOObjectRelease(iterator) }
    return collectEntries(iterator)
  }

  /// Get services matching a class name.
  public static func servicesMatching(
    className: String
  ) -> [[String: Any]] {
    guard let matching = IOServiceMatching(className) else { return [] }
    return matchingServices(matching)
  }

  /// Check if a named entry exists in a plane.
  public static func entryExists(plane: String, path: String) -> Bool {
    let entry = IORegistryEntryFromPath(
      kIOMainPortDefault, "\(plane):/\(path)")
    guard entry != 0 else { return false }
    IOObjectRelease(entry)
    return true
  }

  /// Read all NVRAM variables via IOKit (replaces /usr/sbin/nvram -p).
  public static func nvramVariables() -> [String: Any] {
    let entry = IORegistryEntryFromPath(
      kIOMainPortDefault, "IODeviceTree:/options")
    guard entry != 0 else { return [:] }
    defer { IOObjectRelease(entry) }
    var props: Unmanaged<CFMutableDictionary>?
    guard IORegistryEntryCreateCFProperties(
      entry, &props, kCFAllocatorDefault, 0
    ) == KERN_SUCCESS else { return [:] }
    return (props?.takeRetainedValue() as? [String: Any]) ?? [:]
  }

  /// Get USB devices from IOUSB plane.
  public static func usbDevices() -> [[String: Any]] {
    registryEntries(plane: kIOUSBPlane)
  }

  // MARK: - Private

  private static func collectEntries(
    _ iterator: io_iterator_t
  ) -> [[String: Any]] {
    var results: [[String: Any]] = []
    while case let entry = IOIteratorNext(iterator), entry != 0 {
      defer { IOObjectRelease(entry) }
      var props: Unmanaged<CFMutableDictionary>?
      if IORegistryEntryCreateCFProperties(
        entry, &props, kCFAllocatorDefault, 0
      ) == KERN_SUCCESS,
        let dict = props?.takeRetainedValue() as? [String: Any]
      {
        results.append(dict)
      }
    }
    return results
  }
}
